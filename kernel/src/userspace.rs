//! User-space address regions, program loading, and the drop into Ring 3.
//!
//! ## The isolation this does and does not provide
//!
//! Every thread shares one address space; there is no per-process CR3 yet.
//! Protection is by page permission: kernel pages are mapped without
//! `USER_ACCESSIBLE`, so Ring 3 cannot read or write them, and the attempt
//! faults. That is a genuine privilege boundary and it is what Milestone 3 asks
//! for -- but it is *not* isolation between user processes, which can still
//! reach each other's pages. Separate address spaces are the next step, and
//! until then IPC capabilities are what keeps processes apart.
//!
//! Each user thread gets its own slot within the region so concurrent processes
//! do not collide in the shared space.

use core::arch::{asm, global_asm};

use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

use crate::arch::x86_64::gdt;
use crate::memory::paging::{self, MapError};

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

/// Base address of a thread's slot.
pub fn slot_base_of(slot: u64) -> u64 {
    slot_base(slot)
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

/// Map a slot and copy `code` into its first page.
///
/// The code page is left read-only afterwards. Nothing forces that -- `EFER.NXE`
/// is off, so every present page is executable -- but a program that cannot
/// rewrite its own instructions is one fewer thing to reason about.
pub fn load_program(slot: u64, code: &[u8]) -> Result<UserImage, MapError> {
    assert!(slot < MAX_SLOTS, "user slot {slot} is out of range");
    assert!(
        code.len() as u64 <= PAGE_SIZE,
        "user programs larger than one page are not supported yet"
    );

    let base = slot_base(slot);
    let user_rw = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE;

    let code_page = page_at(base + CODE_OFFSET);
    let data_page = page_at(base + DATA_OFFSET);

    paging::map(code_page, user_rw)?;
    paging::map(data_page, user_rw)?;

    for index in 0..STACK_PAGES {
        paging::map(
            page_at(base + STACK_BOTTOM_OFFSET + index * PAGE_SIZE),
            user_rw,
        )?;
    }

    // SAFETY: the code page was just mapped present and writable, it is `code.len()`
    // bytes or more, and nothing else references it yet -- the thread that will
    // run this program has not been started.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            (base + CODE_OFFSET) as *mut u8,
            code.len(),
        );
    }

    // Drop WRITABLE now the contents are in place.
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
// It has to be hand-written machine code rather than a Rust function: a Rust
// `fn` lives in the kernel's own pages, which are deliberately not
// user-accessible, so Ring 3 could not execute it. Everything here is
// RIP-relative so it runs correctly wherever it is copied to.
// AT&T syntax throughout. Intel syntax cannot tell a difference-of-labels
// immediate from a memory operand, so `mov rdx, 3f - 2f` fails to assemble;
// AT&T's `$(3f - 2f)` is unambiguous.
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_DEMO_START",
    "USER_DEMO_START:",
    // write(1, message, len)
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq 2f(%rip), %rsi",
    "  movq $(3f - 2f), %rdx",
    "  int $0x80",
    // yield()
    "  movq $2, %rax",
    "  int $0x80",
    // write(1, message_after_yield, len)
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq 4f(%rip), %rsi",
    "  movq $(5f - 4f), %rdx",
    "  int $0x80",
    // exit(0)
    "  movq $0, %rax",
    "  movq $0, %rdi",
    "  int $0x80",
    // Unreachable: exit does not return. Present so a bug lands somewhere
    // harmless instead of running off the end of the page.
    "1:",
    "  jmp 1b",
    "2:",
    "  .ascii \"  [ring 3] hello from user space\\n\"",
    "3:",
    "4:",
    "  .ascii \"  [ring 3] still running after a yield\\n\"",
    "5:",
    ".global USER_DEMO_END",
    "USER_DEMO_END:",
    ".section .text",
    options(att_syntax),
);

// A program that reaches into the kernel's heap. It must fault: the heap is
// mapped without USER_ACCESSIBLE, so Ring 3 has no business reading it. Used to
// prove the privilege boundary actually holds rather than merely existing.
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_TRESPASS_START",
    "USER_TRESPASS_START:",
    "  movabsq $0x444444440000, %rax", // memory::heap::HEAP_START
    "  movq (%rax), %rbx",             // faults here
    // Only reached if the boundary failed.
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq 2f(%rip), %rsi",
    "  movq $(3f - 2f), %rdx",
    "  int $0x80",
    "1:",
    "  jmp 1b",
    "2:",
    "  .ascii \"  [ring 3] READ KERNEL MEMORY -- boundary broken\\n\"",
    "3:",
    ".global USER_TRESPASS_END",
    "USER_TRESPASS_END:",
    ".section .text",
    options(att_syntax),
);

// A program that sends one IPC message and exits with the result.
//
// The endpoint id arrives in R15 -- see `enter_ring3`. The message is built on
// the stack, which is the only writable memory the program is handed.
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_IPC_START",
    "USER_IPC_START:",
    "  subq $64, %rsp",
    "  movq $0xCAFE, 0(%rsp)",  // tag
    "  movq $0xBEEF, 8(%rsp)",  // words[0]
    "  movq $0, 16(%rsp)",      // words[1]
    "  movq $0, 24(%rsp)",      // words[2]
    "  movq $0, 32(%rsp)",      // words[3]
    // sender: set to a lie, so the test can prove the kernel overwrites it.
    "  movq $999, 40(%rsp)",
    "  movq $5, %rax",          // IPC_SEND
    "  movq %r15, %rdi",        // endpoint from the kernel
    "  movq %rsp, %rsi",        // &message
    "  int $0x80",
    // exit(send_result), so the outcome is visible even if nothing is received.
    "  movq %rax, %rdi",
    "  movq $0, %rax",
    "  int $0x80",
    "1:",
    "  jmp 1b",
    ".global USER_IPC_END",
    "USER_IPC_END:",
    ".section .text",
    options(att_syntax),
);

extern "C" {
    static USER_DEMO_START: u8;
    static USER_DEMO_END: u8;
    static USER_TRESPASS_START: u8;
    static USER_TRESPASS_END: u8;
    static USER_IPC_START: u8;
    static USER_IPC_END: u8;
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

/// Writes to the console, yields, writes again, exits.
pub fn demo_program() -> &'static [u8] {
    // SAFETY: the symbols bound a range emitted by one `global_asm!` block, in
    // this order, immutable for the life of the kernel. Same for the two below.
    unsafe { blob(&raw const USER_DEMO_START, &raw const USER_DEMO_END) }
}

/// Attempts to read kernel memory. Should be killed by the page-fault handler.
pub fn trespass_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_TRESPASS_START, &raw const USER_TRESPASS_END) }
}

/// Sends one IPC message to the endpoint handed to it in R15, then exits with
/// the syscall's return value.
pub fn ipc_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_IPC_START, &raw const USER_IPC_END) }
}
