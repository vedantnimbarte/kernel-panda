//! The kernel entry point for user-space system calls.
//!
//! Entry is through a software interrupt rather than `SYSCALL`. The gate
//! switches to the stack named by `TSS.privilege_stack_table[0]` automatically,
//! where `SYSCALL` does not switch stacks at all and would need `swapgs` plus a
//! per-CPU block to find one. The gate costs more cycles and buys a great deal
//! less that can go quietly wrong; the ABI here does not depend on the
//! mechanism, so it can be swapped for `SYSCALL` later.
//!
//! It is a trap gate, so a system call runs with interrupts enabled and can be
//! preempted like any other kernel work. See [`register`].
//!
//! ## ABI
//!
//! Modelled on the Linux x86_64 convention, minus the registers `syscall`
//! clobbers -- an `int` preserves RCX and R11, so they are usable.
//!
//! ```text
//! rax  syscall number, and the return value on the way out
//! rdi  arg 0      rsi  arg 1      rdx  arg 2
//! r10  arg 3      r8   arg 4      r9   arg 5
//! ```
//!
//! A negative return value is an error code; zero or positive is success.

use core::arch::naked_asm;

use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::{PrivilegeLevel, VirtAddr};

/// The vector user code invokes. 0x80 by long tradition.
pub const SYSCALL_VECTOR: u8 = 0x80;

/// Everything the entry stub and the CPU pushed, in memory order.
///
/// The field order has to mirror the push sequence in [`syscall_entry`] exactly
/// -- the dispatcher reads arguments and writes the return value straight
/// through this struct, so a mismatch silently corrupts user registers.
#[repr(C)]
#[derive(Debug)]
pub struct SyscallFrame {
    // Pushed by the stub, last push first.
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,

    // Pushed by the CPU on the privilege transition.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl SyscallFrame {
    /// Whether the frame came from user space.
    ///
    /// The low two bits of a saved CS are the privilege level the code was
    /// running at.
    pub fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }
}

/// Assembly entry point for `int 0x80`.
///
/// The CPU has already switched to the kernel stack and pushed SS, RSP, RFLAGS,
/// CS and RIP. This saves every general-purpose register so the dispatcher can
/// both read arguments and modify the state the user resumes with.
///
/// Stack alignment works out without padding: the CPU aligns to 16 and pushes
/// five qwords, and fifteen more pushes bring RSP back to a multiple of 16, so
/// the `call` leaves the callee seeing the `rsp % 16 == 8` the ABI requires.
///
/// # Safety
///
/// Never call this. It is an interrupt entry point: it ends in `iretq` and
/// expects the CPU-pushed trap frame to already be on the stack. Its only
/// legitimate use is as the target address of an IDT entry, which is what
/// [`register`] does.
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // RSP now points at the base of a SyscallFrame; hand it over as arg 0.
        "mov rdi, rsp",
        "call {dispatch}",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
        dispatch = sym dispatch_trampoline,
    )
}

/// Bridges the assembly stub's C calling convention to the Rust dispatcher.
extern "C" fn dispatch_trampoline(frame: &mut SyscallFrame) {
    crate::syscall::dispatch(frame);
}

/// Install the syscall gate.
///
/// The DPL must be 3, or `int 0x80` from user space raises a general protection
/// fault instead of entering the kernel -- the CPU checks the caller's privilege
/// against the gate's before it will use it.
///
/// It is a *trap* gate rather than an interrupt gate, which is the difference
/// between clearing `IF` on entry and leaving it as the caller had it. As an
/// interrupt gate, a syscall ran with interrupts off from `int` to `iretq`: no
/// timer could reach the thread, so its quantum was a fiction and every call
/// had to stay short or the whole machine stuttered. That is a constraint the
/// design cannot keep -- the point of a microkernel is that calls do real work.
///
/// What it demands in return is that the dispatcher be reentrant with respect to
/// preemption, which it is: every lock it touches masks interrupts for the
/// window it holds them, the user-memory windows are bracketed by a guard that
/// does the same, and the frame it edits lives on the calling thread's own
/// kernel stack, so a preemption saves and restores it along with everything
/// else.
pub fn register(idt: &mut InterruptDescriptorTable) {
    // SAFETY: `syscall_entry` is a naked function whose body is a valid
    // interrupt entry sequence ending in `iretq`, and it is `'static`.
    unsafe {
        idt[SYSCALL_VECTOR]
            // Via a pointer: casting a function *item* straight to an integer
            // is a different and much easier thing to get subtly wrong.
            .set_handler_addr(VirtAddr::new(syscall_entry as *const () as u64))
            .set_privilege_level(PrivilegeLevel::Ring3)
            .disable_interrupts(false);
    }
}
