//! The context switch itself.
//!
//! Only the callee-saved registers are exchanged. `context_switch` is called
//! like an ordinary C function, so the compiler has already spilled anything
//! caller-saved at the call site -- saving it again here would be wasted work.
//! Between them the two halves cover the whole register file.
//!
//! Nothing here touches CR3. Every thread is a kernel thread sharing one
//! address space; separate page tables arrive with Ring 3 in Milestone 3.

use core::arch::naked_asm;

/// Swap the current CPU context for another.
///
/// Saves the callee-saved registers onto the current stack, writes the
/// resulting stack pointer through `save_to`, then loads `load_from` as the new
/// stack pointer and pops the other thread's registers back off it. The final
/// `ret` returns into whatever that thread was doing when it was switched away
/// -- either the middle of its own `schedule()` call, or, for a thread that has
/// never run, the trampoline address planted by [`init_stack`].
///
/// # Safety
///
/// `save_to` must point at a live `u64` that outlives the switch, and
/// `load_from` must be a stack pointer previously produced either by this
/// function or by [`init_stack`]. Interrupts must be disabled: an interrupt
/// arriving between the two `mov`s would run on a half-switched stack.
#[unsafe(naked)]
pub unsafe extern "C" fn context_switch(save_to: *mut u64, load_from: u64) {
    // System V puts `save_to` in RDI and `load_from` in RSI.
    naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    )
}

/// Bytes of fabricated frame: six callee-saved registers, a return address, and
/// one slot of padding.
const FRAME_BYTES: u64 = 8 * 8;

/// Build a stack that [`context_switch`] can "return" into for the first time.
///
/// The layout is exactly what `context_switch`'s pop sequence expects, with the
/// trampoline's address sitting where a return address would be.
///
/// The padding slot is not decoration. When `ret` transfers control, RSP has
/// just moved past the return address, and the System V ABI requires that a
/// function entered that way sees `RSP % 16 == 8`. Landing on a 16-byte boundary
/// instead breaks any `movaps` the compiler emits against the stack -- a fault
/// deep inside unrelated code, long after the switch that caused it.
///
/// # Safety
///
/// `top` must be the 16-byte-aligned top of a writable stack with at least
/// [`FRAME_BYTES`] to spare below it.
pub unsafe fn init_stack(top: u64, trampoline: unsafe extern "C" fn() -> !) -> u64 {
    debug_assert_eq!(top % 16, 0, "stack top must be 16-byte aligned");

    let stack_pointer = top - FRAME_BYTES;
    let slots = stack_pointer as *mut u64;

    // SAFETY: the caller guarantees `FRAME_BYTES` of writable stack below `top`,
    // and this range is not yet reachable from anywhere -- the thread it belongs
    // to has not been published to the scheduler.
    unsafe {
        slots.add(0).write(0); // r15
        slots.add(1).write(0); // r14
        slots.add(2).write(0); // r13
        slots.add(3).write(0); // r12
        slots.add(4).write(0); // rbx
        slots.add(5).write(0); // rbp
        // Via usize: a function pointer is pointer-sized, and going straight to
        // u64 would be a silent widening on a 32-bit target.
        slots.add(6).write(trampoline as usize as u64); // popped by `ret`
        slots.add(7).write(0); // alignment padding, never read
    }

    stack_pointer
}
