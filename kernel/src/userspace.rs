//! User-space address regions, program loading, and the drop into Ring 3.
//!
//! ## Isolation
//!
//! Two boundaries, not one. Kernel pages are mapped without `USER_ACCESSIBLE`,
//! so Ring 3 faults trying to touch them; and each process has its own page
//! tables, so one process cannot name another's memory at all.
//!
//! Threads still take a slot from a fixed table. With separate address spaces
//! that no longer partitions the address range -- every ELF program links at the
//! same base -- but it still bounds how many user processes can exist at once,
//! and kernel threads that map graphics buffers share one space and so do need
//! distinct regions.

use core::arch::{asm, global_asm};

use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

use crate::arch::x86_64::gdt;
use crate::memory::paging::{self, MapError};
use crate::sched::ThreadId;
use crate::sync::{without_interrupts, Mutex};

/// Base of everything Ring 3 can reach. Well clear of the kernel, the heap at
/// 0x4444_4444_0000, and the APIC window at 0x7777_0000_0000.
pub const USER_BASE: u64 = 0x0000_2000_0000_0000;

/// Address space handed to each user thread.
///
/// 64 MiB, sized by the graphics case rather than the code case: a single
/// 1280x720 32-bit buffer is 3.6 MiB, and a compositor maps several at once.
pub const SLOT_SIZE: u64 = 0x400_0000;

/// How many slots exist, and therefore the end of the user region.
pub const MAX_SLOTS: u64 = 16;

/// One past the last address Ring 3 may ever name.
pub const USER_REGION_END: u64 = USER_BASE + MAX_SLOTS * SLOT_SIZE;

const PAGE_SIZE: u64 = 4096;

/// Offsets within a slot.
const CODE_OFFSET: u64 = 0;
const DATA_OFFSET: u64 = 0x1000;
const STACK_BOTTOM_OFFSET: u64 = 0x1_0000;
const STACK_PAGES: u64 = 4;

/// Where shared graphics buffers start being mapped, well clear of the stack.
pub const BUFFER_AREA_OFFSET: u64 = 0x10_0000;

/// Base address of a slot, by index.
pub fn slot_base_of(slot: u64) -> u64 {
    slot_base(slot)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// Every user slot is occupied.
    NoFreeSlot,
    /// The program does not fit in one page.
    TooLarge,
    Mapping(MapError),
    Elf(crate::elf::ElfError),
}

/// Which thread occupies each slot.
///
/// Slots are allocated from this table rather than derived from the thread id.
/// Thread ids only ever increase -- reaped slots in the scheduler are never
/// reused -- so using one as an index meant the seventeenth user program ran off
/// the end of the region and panicked the kernel.
static SLOTS: Mutex<[Option<ThreadId>; MAX_SLOTS as usize]> = Mutex::new([None; MAX_SLOTS as usize]);

fn claim_slot(owner: ThreadId) -> Option<u64> {
    without_interrupts(|| {
        let mut slots = SLOTS.lock();
        // Already has one: a thread loading a second program reuses its space
        // rather than leaking the first.
        if let Some(index) = slots.iter().position(|slot| *slot == Some(owner)) {
            return Some(index as u64);
        }
        let index = slots.iter().position(Option::is_none)?;
        slots[index] = Some(owner);
        Some(index as u64)
    })
}

/// The slot a thread occupies, claiming one if it has none.
///
/// A thread does not have to be running a user program to need user-accessible
/// address space -- mapping a shared graphics buffer is reason enough.
pub fn ensure_slot(owner: ThreadId) -> Option<u64> {
    claim_slot(owner)
}

/// The slot a thread occupies, if any.
pub fn slot_of(owner: ThreadId) -> Option<u64> {
    without_interrupts(|| {
        SLOTS
            .lock()
            .iter()
            .position(|slot| *slot == Some(owner))
            .map(|index| index as u64)
    })
}

/// Slots currently in use. Diagnostic, and used by tests.
pub fn slots_in_use() -> usize {
    without_interrupts(|| SLOTS.lock().iter().filter(|slot| slot.is_some()).count())
}

/// Tear down a thread's user address space and return its slot to the pool.
///
/// Called when the thread exits. Without this, every user program permanently
/// consumed both physical frames and one of the sixteen slots, so the system
/// could run at most sixteen user programs in its entire uptime before refusing
/// to start another.
pub fn release_slot(owner: ThreadId) {
    let Some(slot) = slot_of(owner) else {
        return;
    };
    let space = crate::sched::address_space_of(owner);

    // No page-by-page unmapping. Releasing the space walks its user subtree and
    // frees every table and data page in it, which is both simpler and correct
    // for ELF images -- their segments land wherever the program headers say,
    // not at a layout this function could predict.
    if let Some(space) = space {
        // SAFETY: the thread is exiting and its space is not loaded -- the
        // scheduler switched to the kernel's on the way here, and no other CPU
        // exists yet to have it active.
        unsafe { space.release() };
    }

    without_interrupts(|| {
        let mut slots = SLOTS.lock();
        if let Some(entry) = slots.get_mut(slot as usize) {
            *entry = None;
        }
    });
}

/// Where a loaded program's pieces ended up.
#[derive(Debug, Clone, Copy)]
pub struct UserImage {
    pub entry: VirtAddr,
    pub stack_top: VirtAddr,
    /// A writable scratch page, for message buffers and the like.
    pub data: VirtAddr,
}

fn slot_base(slot: u64) -> u64 {
    USER_BASE + slot * SLOT_SIZE
}

// The userland binaries, built by `cargo xtask` before the kernel and embedded
// here. `include_bytes!` makes them a compile-time dependency, so editing a
// user program rebuilds the kernel that carries it.
//
// A bare `cargo build` in kernel/ fails until userland has been built once;
// `cargo xtask build` and `cargo xtask test` always do it first.
pub const SHELL_ELF: &[u8] =
    include_bytes!("../../userland/target/x86_64-unknown-none/release/shell");
pub const COMPOSITOR_ELF: &[u8] =
    include_bytes!("../../userland/target/x86_64-unknown-none/release/compositor");
pub const INPUT_ELF: &[u8] =
    include_bytes!("../../userland/target/x86_64-unknown-none/release/input");
pub const CLIENT_ELF: &[u8] =
    include_bytes!("../../userland/target/x86_64-unknown-none/release/client");
/// Test programs, selected by the `mode` word of their parameter page.
pub const PROBE_ELF: &[u8] =
    include_bytes!("../../userland/target/x86_64-unknown-none/release/probe");

/// Probe modes. Must match `userland/src/bin/probe.rs`.
pub mod probe {
    pub const DEMO: u64 = 0;
    pub const TRESPASS: u64 = 1;
    pub const IPC: u64 = 2;
    pub const PEEK: u64 = 3;
    pub const FILES: u64 = 4;
}

/// Load the probe program in `mode`, with an optional address or endpoint.
///
/// Returns the image; the caller enters Ring 3 with `image.data` as the
/// argument.
pub fn load_probe(owner: ThreadId, mode: u64, argument: u64) -> Result<UserImage, LoadError> {
    let image = load_elf(owner, PROBE_ELF)?;
    // SAFETY: `image.data` is the writable parameter page just mapped for this
    // program, which is not running yet.
    unsafe { write_parameters(image.data, &[mode, argument, argument]) };
    Ok(image)
}

/// Load an ELF program and give the thread a stack for it.
///
/// Unlike `load_program`, the image may span many pages and carries its own
/// section permissions, so text ends up read-only and executable while data and
/// stack are writable and not.
pub fn load_elf(owner: ThreadId, image: &[u8]) -> Result<UserImage, LoadError> {
    let slot = claim_slot(owner).ok_or(LoadError::NoFreeSlot)?;
    let _ = slot;

    let space = paging::AddressSpace::new_user().ok_or(LoadError::NoFreeSlot)?;
    crate::sched::set_address_space(owner, space);
    // SAFETY: cloned from the kernel space, so the code running here and the
    // stack under it are mapped identically. Activated before the loader copies
    // segments in through these very mappings.
    unsafe { space.activate() };

    let loaded = crate::elf::load(&space, image, USER_BASE, USER_BASE + SLOT_SIZE)
        .map_err(LoadError::Elf)?;

    // Stack goes above the image, page aligned, with a gap so an overrun lands
    // in unmapped space rather than in the program's own data.
    let stack_bottom = loaded.end.as_u64() + PAGE_SIZE;
    let user_data = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    for index in 0..STACK_PAGES {
        paging::map_in(&space, page_at(stack_bottom + index * PAGE_SIZE), user_data)
            .map_err(LoadError::Mapping)?;
    }

    // One writable page above the stack for start-up parameters.
    let data = stack_bottom + STACK_PAGES * PAGE_SIZE;
    paging::map_in(&space, page_at(data), user_data).map_err(LoadError::Mapping)?;

    Ok(UserImage {
        entry: loaded.entry,
        stack_top: VirtAddr::new(stack_bottom + STACK_PAGES * PAGE_SIZE),
        data: VirtAddr::new(data),
    })
}

/// Map a slot and copy `code` into its first page.
///
/// The code page is left read-only afterwards. Nothing forces that -- `EFER.NXE`
/// is off, so every present page is executable -- but a program that cannot
/// rewrite its own instructions is one fewer thing to reason about.
pub fn load_program(owner: ThreadId, code: &[u8]) -> Result<UserImage, LoadError> {
    if code.len() as u64 > PAGE_SIZE {
        return Err(LoadError::TooLarge);
    }

    // An error, not an assertion. Running out of address space is a condition
    // the caller can report; panicking takes the whole system down because one
    // process asked for too much.
    let slot = claim_slot(owner).ok_or(LoadError::NoFreeSlot)?;
    let base = slot_base(slot);

    // Its own page tables, cloned from the kernel's so every kernel mapping is
    // still reachable while the user region starts empty. This is what makes one
    // process unable to name another's memory at all -- before it, they shared a
    // single address space and only page permissions kept them out of the
    // kernel, not out of each other.
    let space = paging::AddressSpace::new_user().ok_or(LoadError::NoFreeSlot)?;
    crate::sched::set_address_space(owner, space);

    // Activate now: the code is copied in below through these very mappings, and
    // the thread will not be rescheduled before it reaches Ring 3.
    //
    // SAFETY: cloned from the kernel space, so the code executing here and the
    // stack under it are mapped identically.
    unsafe { space.activate() };

    // Writable while the code is copied in; narrowed below.
    let user_rw = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE;

    // W^X for everything that is not code. An executable stack is the oldest
    // exploit primitive there is: any bug that lets a process write to its own
    // stack and jump there becomes arbitrary code execution.
    let user_data = user_rw | PageTableFlags::NO_EXECUTE;

    let code_page = page_at(base + CODE_OFFSET);
    let data_page = page_at(base + DATA_OFFSET);

    paging::map_in(&space, code_page, user_rw).map_err(LoadError::Mapping)?;
    paging::map_in(&space, data_page, user_data).map_err(LoadError::Mapping)?;

    for index in 0..STACK_PAGES {
        paging::map_in(
            &space,
            page_at(base + STACK_BOTTOM_OFFSET + index * PAGE_SIZE),
            user_data,
        )
        .map_err(LoadError::Mapping)?;
    }

    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: the code page was just mapped present and writable, it is
        // `code.len()` bytes or more, nothing else references it yet -- the
        // thread that will run this program has not been started -- and the
        // guard lets Ring 0 write a user-accessible page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                (base + CODE_OFFSET) as *mut u8,
                code.len(),
            );
        }
    });

    // Drop WRITABLE now the contents are in place. The space is active, so the
    // global helper edits the right tables.
    let user_ro = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    let _ = paging::set_flags(code_page, user_ro);

    Ok(UserImage {
        entry: VirtAddr::new(base + CODE_OFFSET),
        // Stacks grow down, so the top is one past the last stack page.
        stack_top: VirtAddr::new(base + STACK_BOTTOM_OFFSET + STACK_PAGES * PAGE_SIZE),
        data: VirtAddr::new(base + DATA_OFFSET),
    })
}

fn page_at(address: u64) -> Page<Size4KiB> {
    Page::containing_address(VirtAddr::new(address))
}

/// Check that a user-supplied buffer is one the kernel may safely touch.
///
/// A pointer arriving from Ring 3 is an attacker-controlled integer. Two things
/// have to hold before the kernel dereferences it: the whole range lies inside
/// the user region, and every page it spans is actually mapped with the
/// permissions the access needs. Checking only the first is the classic
/// confused-deputy hole -- the kernel would happily fault, or worse, on a
/// half-mapped range.
pub fn validate_user_buffer(pointer: u64, length: u64, need_write: bool) -> bool {
    if length == 0 {
        return true;
    }

    let Some(end) = pointer.checked_add(length) else {
        // Wrapping past the top of the address space.
        return false;
    };

    if pointer < USER_BASE || end > USER_REGION_END {
        return false;
    }

    let mut address = pointer & !(PAGE_SIZE - 1);
    while address < end {
        let Some(flags) = paging::flags(VirtAddr::new(address)) else {
            return false;
        };
        if !flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE) {
            return false;
        }
        if need_write && !flags.contains(PageTableFlags::WRITABLE) {
            return false;
        }
        address += PAGE_SIZE;
    }

    true
}

/// Drop to Ring 3 and start executing at `entry`.
///
/// `argument` arrives in R15. `iretq` does not clear registers, which gives a
/// program its one piece of start-up state -- an endpoint id, typically -- with
/// no need for an auxiliary vector or a parameter page.
///
/// Does not return: the only ways back into the kernel are a syscall, an
/// interrupt, or a fault.
///
/// # Safety
///
/// `entry` and `stack_top` must be mapped user-accessible and the stack must be
/// writable.
pub unsafe fn enter_ring3(entry: VirtAddr, stack_top: VirtAddr, argument: u64) -> ! {
    let selectors = gdt::selectors();
    let code_selector = selectors.user_code.0 as u64;
    let data_selector = selectors.user_data.0 as u64;

    // Publish this thread's Ring 0 stack. The scheduler does this on every
    // switch, but a thread that has not been switched since it was created
    // would otherwise take its first trap onto whatever was there before.
    let kernel_stack = crate::sched::current_kernel_stack_top();
    if kernel_stack != 0 {
        gdt::set_kernel_stack(VirtAddr::new(kernel_stack));
    }

    // SAFETY: the frame pushed below is exactly what `iretq` consumes -- SS,
    // RSP, RFLAGS, CS, RIP from the top down. Both selectors are Ring 3
    // descriptors from the live GDT, and RFLAGS has IF set so the new thread is
    // preemptible the moment it starts. The caller guarantees the mappings.
    unsafe {
        asm!(
            // DS and ES are ignored for addressing in long mode, but leaving
            // Ring 0 selectors loaded is untidy and confuses debuggers.
            "mov ds, {selector:x}",
            "mov es, {selector:x}",
            "push {selector}",   // SS
            "push {stack}",      // RSP
            "push {flags}",      // RFLAGS: IF set, bit 1 reserved-one
            "push {code}",       // CS
            "push {entry}",      // RIP
            "iretq",
            selector = in(reg) data_selector,
            stack = in(reg) stack_top.as_u64(),
            flags = in(reg) 0x202u64,
            code = in(reg) code_selector,
            entry = in(reg) entry.as_u64(),
            // Survives the transition untouched and is the program's only
            // start-up argument.
            in("r15") argument,
            options(noreturn),
        )
    }
}

// A tiny position-independent Ring 3 program, assembled into the kernel image
// and copied into a user page at load time.
//
// The input daemon. Reads raw bytes from the console and forwards the ones it
// approves of to a single endpoint, handed to it in R15.
//
// The compositor. Maps the scanout buffer, then blits client buffers into it as
// their handles arrive over IPC.
//
// A graphics client. Allocates a buffer, fills it with one colour, shares it
// with the compositor and asks for it to be shown.
//
// Writes an instruction onto its own stack and jumps to it.
//
// With W^X enforced this faults immediately and the thread is killed. Without
// it, the two bytes are `jmp -2` -- an infinite loop -- so the thread stays alive
// forever and the test fails by timing out rather than passing by accident. A
// `ret` would have been ambiguous: it faults either way.
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_NXTEST_START",
    "USER_NXTEST_START:",
    "  subq $32, %rsp",
    "  movw $0xFEEB, (%rsp)", // EB FE = jmp -2
    "  jmp *%rsp",
    "1:",
    "  jmp 1b",
    ".global USER_NXTEST_END",
    "USER_NXTEST_END:",
    ".section .text",
    options(att_syntax),
);

extern "C" {
    static USER_NXTEST_START: u8;
    static USER_NXTEST_END: u8;
}

/// # Safety
///
/// `start` and `end` must bound a contiguous, immutable range in the kernel
/// image, with `end` at or after `start`.
unsafe fn blob(start: *const u8, end: *const u8) -> &'static [u8] {
    let length = end as usize - start as usize;
    // SAFETY: forwarded from this function's contract.
    unsafe { core::slice::from_raw_parts(start, length) }
}

/// Tries to execute its own stack. Should be killed by the page-fault handler.
///
/// The last program still written in assembly, and the only one that has to be:
/// it plants two bytes of machine code on its own stack and jumps to them,
/// which is not something Rust will express.
pub fn stack_execution_program() -> &'static [u8] {
    // SAFETY: the symbols bound a range emitted by one `global_asm!` block, in
    // this order, immutable for the life of the kernel.
    unsafe { blob(&raw const USER_NXTEST_START, &raw const USER_NXTEST_END) }
}

/// Write a program's start-up parameters into its data page.
///
/// # Safety
///
/// `data` must be the data page returned by `load_program`, mapped writable, and
/// the program must not be running yet.
pub unsafe fn write_parameters(data: VirtAddr, values: &[u64]) {
    assert!(values.len() * 8 <= PAGE_SIZE as usize);
    crate::arch::x86_64::with_user_access(|| {
        for (index, value) in values.iter().enumerate() {
            // SAFETY: forwarded from this function's contract; the assertion
            // above keeps every write inside the page, and the guard lets Ring 0
            // write a user-accessible one.
            unsafe { core::ptr::write_volatile((data.as_u64() as *mut u64).add(index), *value) };
        }
    });
}

