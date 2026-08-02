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
    let base = slot_base(slot);
    let space = crate::sched::address_space_of(owner);

    // The fixed layout `load_program` established: one code page, one data page,
    // and the stack.
    let mut pages = alloc::vec![base + CODE_OFFSET, base + DATA_OFFSET];
    for index in 0..STACK_PAGES {
        pages.push(base + STACK_BOTTOM_OFFSET + index * PAGE_SIZE);
    }

    // Unmap from the thread's own tables. Using the active ones would free
    // whatever happened to live at those addresses in whichever space is loaded
    // right now -- which, once processes have their own, is a different process's
    // memory.
    let target = space.unwrap_or_else(paging::kernel_space);
    for address in pages {
        let page = page_at(address);
        // Unmapped already if the program never got that far, which is fine.
        let _ = paging::unmap_and_free_in(&target, page);
    }

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

// A line-editing shell. Reads a line from the serial port, echoes it, and
// dispatches on it. `repe cmpsb` makes fixed-string comparison a few
// instructions, which is what keeps a command table tractable in assembly.
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_SHELL_START",
    "USER_SHELL_START:",
    // 128 bytes of line buffer at the top of the stack.
    "  subq $128, %rsp",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_banner(%rip), %rsi",
    "  movq $(.Lsh_banner_end - .Lsh_banner), %rdx",
    "  int $0x80",
    ".Lsh_prompt:",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_ps1(%rip), %rsi",
    "  movq $(.Lsh_ps1_end - .Lsh_ps1), %rdx",
    "  int $0x80",
    "  xorq %r13, %r13", // line length
    ".Lsh_read:",
    "  movq $13, %rax", // READ
    "  xorq %rdi, %rdi",
    "  movq %rsp, %rsi",
    "  addq %r13, %rsi",
    "  movq $1, %rdx",
    "  int $0x80",
    "  cmpq $1, %rax",
    "  jne .Lsh_read", // nothing arrived; ask again
    // Echo, so the operator can see what they typed.
    "  movq %rsp, %rsi",
    "  addq %r13, %rsi",
    "  movzbq (%rsi), %r14",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  movq $1, %rdx",
    "  int $0x80",
    "  cmpq $13, %r14", // CR
    "  je .Lsh_line",
    "  cmpq $10, %r14", // LF
    "  je .Lsh_line",
    "  incq %r13",
    "  cmpq $100, %r13",
    "  jl .Lsh_read",
    ".Lsh_line:",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_nl(%rip), %rsi",
    "  movq $1, %rdx",
    "  int $0x80",
    "  testq %r13, %r13",
    "  jz .Lsh_prompt", // empty line
    // help
    "  cmpq $4, %r13",
    "  jne .Lsh_try_version",
    "  leaq .Lsh_cmd_help(%rip), %rsi",
    "  movq %rsp, %rdi",
    "  movq $4, %rcx",
    "  cld",
    "  repe cmpsb",
    "  jne .Lsh_try_exit",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_help(%rip), %rsi",
    "  movq $(.Lsh_help_end - .Lsh_help), %rdx",
    "  int $0x80",
    "  jmp .Lsh_prompt",
    ".Lsh_try_exit:",
    "  cmpq $4, %r13",
    "  jne .Lsh_unknown",
    "  leaq .Lsh_cmd_exit(%rip), %rsi",
    "  movq %rsp, %rdi",
    "  movq $4, %rcx",
    "  cld",
    "  repe cmpsb",
    "  jne .Lsh_unknown",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_bye(%rip), %rsi",
    "  movq $(.Lsh_bye_end - .Lsh_bye), %rdx",
    "  int $0x80",
    "  movq $0, %rax",
    "  movq $0, %rdi",
    "  int $0x80",
    ".Lsh_try_version:",
    "  cmpq $7, %r13",
    "  jne .Lsh_try_hello",
    "  leaq .Lsh_cmd_version(%rip), %rsi",
    "  movq %rsp, %rdi",
    "  movq $7, %rcx",
    "  cld",
    "  repe cmpsb",
    "  jne .Lsh_unknown",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_version(%rip), %rsi",
    "  movq $(.Lsh_version_end - .Lsh_version), %rdx",
    "  int $0x80",
    "  jmp .Lsh_prompt",
    ".Lsh_try_hello:",
    "  cmpq $5, %r13",
    "  jne .Lsh_unknown",
    "  leaq .Lsh_cmd_hello(%rip), %rsi",
    "  movq %rsp, %rdi",
    "  movq $5, %rcx",
    "  cld",
    "  repe cmpsb",
    "  jne .Lsh_unknown",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_hello(%rip), %rsi",
    "  movq $(.Lsh_hello_end - .Lsh_hello), %rdx",
    "  int $0x80",
    "  jmp .Lsh_prompt",
    ".Lsh_unknown:",
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq .Lsh_huh(%rip), %rsi",
    "  movq $(.Lsh_huh_end - .Lsh_huh), %rdx",
    "  int $0x80",
    "  jmp .Lsh_prompt",
    ".Lsh_banner:",
    "  .ascii \"panda shell -- type 'help'\\n\"",
    ".Lsh_banner_end:",
    ".Lsh_ps1:",
    "  .ascii \"panda> \"",
    ".Lsh_ps1_end:",
    ".Lsh_nl:",
    "  .ascii \"\\n\"",
    ".Lsh_cmd_help:",
    "  .ascii \"help\"",
    ".Lsh_cmd_exit:",
    "  .ascii \"exit\"",
    ".Lsh_cmd_version:",
    "  .ascii \"version\"",
    ".Lsh_cmd_hello:",
    "  .ascii \"hello\"",
    ".Lsh_help:",
    "  .ascii \"commands: help version hello exit\\n\"",
    ".Lsh_help_end:",
    ".Lsh_version:",
    "  .ascii \"Kernel Panda, ring 3 shell\\n\"",
    ".Lsh_version_end:",
    ".Lsh_hello:",
    "  .ascii \"hello from a user-space daemon\\n\"",
    ".Lsh_hello_end:",
    ".Lsh_huh:",
    "  .ascii \"unknown command\\n\"",
    ".Lsh_huh_end:",
    ".Lsh_bye:",
    "  .ascii \"shell exiting\\n\"",
    ".Lsh_bye_end:",
    ".global USER_SHELL_END",
    "USER_SHELL_END:",
    ".section .text",
    options(att_syntax),
);

// The input daemon. Reads raw bytes from the console and forwards the ones it
// approves of to a single endpoint, handed to it in R15.
//
// It is the sanitiser the PRD asks for: control characters are dropped rather
// than passed on, so a downstream compositor never sees a byte it did not ask
// for. It is also the only thing holding a read capability on the console,
// which is what stops any other process from watching the keyboard.
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_INPUT_START",
    "USER_INPUT_START:",
    "  subq $128, %rsp",
    ".Lin_loop:",
    "  movq $13, %rax", // READ
    "  xorq %rdi, %rdi",
    "  movq %rsp, %rsi",
    "  movq $1, %rdx",
    "  int $0x80",
    "  cmpq $1, %rax",
    "  jne .Lin_loop",
    "  movzbq (%rsp), %rbx",
    // Escape ends the session.
    "  cmpq $0x1b, %rbx",
    "  je .Lin_quit",
    // Printable ASCII passes.
    "  cmpq $0x20, %rbx",
    "  jb .Lin_control",
    "  cmpq $0x7e, %rbx",
    "  ja .Lin_loop", // above printable: drop
    "  jmp .Lin_send",
    ".Lin_control:",
    // Of the control codes, only newline and carriage return mean anything.
    "  cmpq $0x0a, %rbx",
    "  je .Lin_send",
    "  cmpq $0x0d, %rbx",
    "  je .Lin_send",
    "  jmp .Lin_loop", // everything else is dropped
    ".Lin_send:",
    "  movq $1, 16(%rsp)", // tag 1: key event
    "  movq %rbx, 24(%rsp)",
    "  movq $0, 32(%rsp)",
    "  movq $0, 40(%rsp)",
    "  movq $0, 48(%rsp)",
    "  movq $0, 56(%rsp)",
    "  movq $5, %rax", // IPC_SEND
    "  movq %r15, %rdi",
    "  leaq 16(%rsp), %rsi",
    "  int $0x80",
    "  jmp .Lin_loop",
    ".Lin_quit:",
    // Tag 0 tells the consumer to shut down too.
    "  movq $0, 16(%rsp)",
    "  movq $0, 24(%rsp)",
    "  movq $0, 32(%rsp)",
    "  movq $0, 40(%rsp)",
    "  movq $0, 48(%rsp)",
    "  movq $0, 56(%rsp)",
    "  movq $5, %rax",
    "  movq %r15, %rdi",
    "  leaq 16(%rsp), %rsi",
    "  int $0x80",
    "  movq $0, %rax",
    "  movq $0, %rdi",
    "  int $0x80",
    ".global USER_INPUT_END",
    "USER_INPUT_END:",
    ".section .text",
    options(att_syntax),
);

// The compositor. Maps the scanout buffer, then blits client buffers into it as
// their handles arrive over IPC.
//
// R15 carries its endpoint. Stack layout, all offsets from RSP:
//     0   scanout BufferInfo (24 bytes)
//    32   incoming Message (48 bytes)
//    96   client BufferInfo (24 bytes)
//   128   x, 136 y, 144 row, 152 client mapping
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_COMPOSITOR_START",
    "USER_COMPOSITOR_START:",
    "  subq $256, %rsp",
    "  movq $12, %rax", // BUF_SCANOUT
    "  int $0x80",
    "  movq %rax, %r12", // scanout id
    "  movq $9, %rax",   // BUF_MAP
    "  movq %r12, %rdi",
    "  int $0x80",
    "  movq %rax, %r13", // scanout base
    "  movq $11, %rax",  // BUF_INFO
    "  movq %r12, %rdi",
    "  movq %rsp, %rsi",
    "  int $0x80",
    "  movl 8(%rsp), %r14d", // scanout stride
    ".Lco_loop:",
    "  movq $6, %rax", // IPC_RECV, parks until something arrives
    "  movq %r15, %rdi",
    "  leaq 32(%rsp), %rsi",
    "  int $0x80",
    "  movq 32(%rsp), %rbx", // tag
    "  testq %rbx, %rbx",
    "  jz .Lco_exit", // tag 0: shut down
    "  cmpq $2, %rbx",
    "  jne .Lco_loop", // only "present" is understood
    // words[0] buffer, words[1] x, words[2] y
    "  movq $9, %rax", // BUF_MAP
    "  movq 40(%rsp), %rdi",
    "  int $0x80",
    "  movq %rax, 152(%rsp)",
    "  movq $11, %rax", // BUF_INFO
    "  movq 40(%rsp), %rdi",
    "  leaq 96(%rsp), %rsi",
    "  int $0x80",
    "  movq 48(%rsp), %rax",
    "  movq %rax, 128(%rsp)", // x
    "  movq 56(%rsp), %rax",
    "  movq %rax, 136(%rsp)", // y
    "  movq $0, 144(%rsp)",   // row
    ".Lco_row:",
    "  movq 144(%rsp), %rbx",
    "  movl 100(%rsp), %eax", // client height
    "  cmpq %rax, %rbx",
    "  jae .Lco_loop",
    // destination = scanout + (y + row) * scanout_stride + x * 4
    "  movq 136(%rsp), %rax",
    "  addq %rbx, %rax",
    "  imulq %r14, %rax",
    "  addq %r13, %rax",
    "  movq 128(%rsp), %rsi",
    "  movl 108(%rsp), %ecx", // bytes per pixel, from the client's own info
    "  imulq %rcx, %rsi",
    "  addq %rsi, %rax",
    "  movq %rax, %rdi",
    // source = client + row * client_stride
    "  movl 104(%rsp), %eax",
    "  imulq %rbx, %rax",
    "  addq 152(%rsp), %rax",
    "  movq %rax, %rsi",
    // One row. The client's stride is exactly width * bpp, so it is the row
    // length in bytes as well as the pitch.
    "  movl 104(%rsp), %ecx",
    "  cld",
    "  rep movsb",
    "  incq %rbx",
    "  movq %rbx, 144(%rsp)",
    "  jmp .Lco_row",
    ".Lco_exit:",
    "  movq $0, %rax",
    "  movq $0, %rdi",
    "  int $0x80",
    ".global USER_COMPOSITOR_END",
    "USER_COMPOSITOR_END:",
    ".section .text",
    options(att_syntax),
);

// A graphics client. Allocates a buffer, fills it with one colour, shares it
// with the compositor and asks for it to be shown.
//
// Its parameters come from its own data page rather than a register, because
// there are more of them than `iretq` can carry. The page sits one page above
// the code, and the code knows where it is because it is position-independent:
//     0 colour, 8 x, 16 y, 24 endpoint, 32 width, 40 height, 48 compositor tid
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_CLIENT_START",
    "USER_CLIENT_START:",
    "  subq $128, %rsp",
    "  leaq USER_CLIENT_START(%rip), %r12",
    "  addq $0x1000, %r12", // the data page
    "  movq $8, %rax",      // BUF_CREATE
    "  movq 32(%r12), %rdi",
    "  movq 40(%r12), %rsi",
    "  int $0x80",
    "  movq %rax, %r13", // buffer id
    "  movq $9, %rax",   // BUF_MAP
    "  movq %r13, %rdi",
    "  int $0x80",
    "  movq %rax, %r14", // buffer base
    // Fill, one pixel at a time. `rep stosl` would be faster but assumes four
    // bytes per pixel, and this display uses three.
    "  movq 32(%r12), %rcx",
    "  imulq 40(%r12), %rcx", // pixel count
    "  movq 56(%r12), %rbx",  // bytes per pixel
    "  movq %r14, %rdi",
    ".Lcl_fill:",
    "  testq %rcx, %rcx",
    "  jz .Lcl_filled",
    "  movq 0(%r12), %rax", // colour, reloaded because the shifts destroy it
    "  movb %al, 0(%rdi)",
    "  shrq $8, %rax",
    "  movb %al, 1(%rdi)",
    "  shrq $8, %rax",
    "  movb %al, 2(%rdi)",
    "  addq %rbx, %rdi",
    "  decq %rcx",
    "  jmp .Lcl_fill",
    ".Lcl_filled:",
    "  movq $10, %rax", // BUF_SHARE with the compositor
    "  movq %r13, %rdi",
    "  movq 48(%r12), %rsi",
    "  int $0x80",
    // present(buffer, x, y)
    "  movq $2, 64(%rsp)",
    "  movq %r13, 72(%rsp)",
    "  movq 8(%r12), %rax",
    "  movq %rax, 80(%rsp)",
    "  movq 16(%r12), %rax",
    "  movq %rax, 88(%rsp)",
    "  movq $0, 96(%rsp)",
    "  movq $0, 104(%rsp)",
    "  movq $5, %rax", // IPC_SEND
    "  movq 24(%r12), %rdi",
    "  leaq 64(%rsp), %rsi",
    "  int $0x80",
    "  movq $0, %rax",
    "  movq $0, %rdi",
    "  int $0x80",
    ".global USER_CLIENT_END",
    "USER_CLIENT_END:",
    ".section .text",
    options(att_syntax),
);

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

// Dereferences whatever address it is handed in R15.
//
// Pointed at memory mapped in a *different* process's address space, it must
// fault. If it does not, it prints -- so the failure is loud rather than a test
// that quietly passes because nothing happened.
global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global USER_PEEK_START",
    "USER_PEEK_START:",
    "  movq (%r15), %rax",
    // Only reached if the read succeeded.
    "  movq $1, %rax",
    "  movq $1, %rdi",
    "  leaq 2f(%rip), %rsi",
    "  movq $(3f - 2f), %rdx",
    "  int $0x80",
    "  movq $0, %rax",
    "  movq $0, %rdi",
    "  int $0x80",
    "1:",
    "  jmp 1b",
    "2:",
    "  .ascii \"  [ring 3] READ ANOTHER ADDRESS SPACE -- isolation broken\\n\"",
    "3:",
    ".global USER_PEEK_END",
    "USER_PEEK_END:",
    ".section .text",
    options(att_syntax),
);

extern "C" {
    static USER_PEEK_START: u8;
    static USER_PEEK_END: u8;
    static USER_NXTEST_START: u8;
    static USER_NXTEST_END: u8;
    static USER_INPUT_START: u8;
    static USER_INPUT_END: u8;
    static USER_COMPOSITOR_START: u8;
    static USER_COMPOSITOR_END: u8;
    static USER_CLIENT_START: u8;
    static USER_CLIENT_END: u8;
    static USER_SHELL_START: u8;
    static USER_SHELL_END: u8;
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

/// Dereferences the address handed to it in R15.
pub fn peek_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_PEEK_START, &raw const USER_PEEK_END) }
}

/// Tries to execute its own stack. Should be killed by the page-fault handler.
pub fn stack_execution_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_NXTEST_START, &raw const USER_NXTEST_END) }
}

/// Reads the console and forwards sanitised key events to an endpoint.
pub fn input_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_INPUT_START, &raw const USER_INPUT_END) }
}

/// Maps the scanout buffer and blits client buffers into it.
pub fn compositor_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_COMPOSITOR_START, &raw const USER_COMPOSITOR_END) }
}

/// Allocates a buffer, fills it, and asks the compositor to show it.
pub fn client_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_CLIENT_START, &raw const USER_CLIENT_END) }
}

/// Write a program's start-up parameters into its data page.
///
/// # Safety
///
/// `data` must be the data page returned by `load_program`, mapped writable, and
/// the program must not be running yet.
pub unsafe fn write_parameters(data: VirtAddr, values: &[u64]) {
    assert!(values.len() * 8 <= PAGE_SIZE as usize);
    for (index, value) in values.iter().enumerate() {
        // SAFETY: forwarded from this function's contract; the assertion above
        // keeps every write inside the page.
        unsafe { core::ptr::write_volatile((data.as_u64() as *mut u64).add(index), *value) };
    }
}

/// A line-editing shell over the serial port.
pub fn shell_program() -> &'static [u8] {
    // SAFETY: as `demo_program`.
    unsafe { blob(&raw const USER_SHELL_START, &raw const USER_SHELL_END) }
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
