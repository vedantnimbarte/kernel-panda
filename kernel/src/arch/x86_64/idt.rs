//! Interrupt Descriptor Table and CPU exception handlers.
//!
//! CPU exceptions, plus the two APIC-delivered vectors the kernel currently
//! uses. Device interrupts beyond the timer belong to Ring 3 drivers and will
//! arrive through IPC rather than through entries in this table.
//!
//! The page-fault handler is the most valuable thing in this file: it is the
//! difference between "the machine rebooted" and "you tried to write to
//! 0xdeadbeef from a non-present page".

use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::println;
use crate::sync::Lazy;

use super::{apic, gdt};

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.general_protection_fault
        .set_handler_fn(general_protection_fault_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);

    // SAFETY: `DOUBLE_FAULT_IST_INDEX` is the slot `gdt.rs` filled with the
    // address of a dedicated, correctly aligned stack, and that GDT is loaded
    // before this IDT. Pointing the entry at an unpopulated IST slot would make
    // every double fault a triple fault instead.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }

    idt[apic::TIMER_VECTOR].set_handler_fn(timer_handler);
    idt[apic::SPURIOUS_VECTOR].set_handler_fn(spurious_handler);
    idt[apic::TLB_SHOOTDOWN_VECTOR].set_handler_fn(tlb_shootdown_handler);

    super::syscall::register(&mut idt);

    idt
});

/// Install the IDT. `gdt::init` must already have run.
pub fn init() {
    IDT.load();
}

/// `int3`. Recoverable by design -- this returns and execution continues, which
/// is what makes it a good liveness check for the whole IDT path.
///
/// Kept to a single line: unlike the fatal handlers below, this one can fire in
/// a loop, and a full frame dump each time buries everything else.
extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    println!(
        "EXCEPTION: BREAKPOINT at {:#018x}",
        frame.instruction_pointer.as_u64()
    );
}

extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    panic!("EXCEPTION: INVALID OPCODE\n{frame:#?}");
}

extern "x86-interrupt" fn general_protection_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) {
    // The error code is a segment selector index when the fault came from a
    // segment-related operation, and zero otherwise.
    if terminate_if_from_user(&frame, "general protection fault") {
        return;
    }
    panic!("EXCEPTION: GENERAL PROTECTION FAULT (selector {error_code:#x})\n{frame:#?}");
}

/// Kill the current thread if a fault came from Ring 3, instead of panicking.
///
/// PRD 1.2 asks that a fault in unprivileged code never take the system down. A
/// user thread that dereferences nonsense is a bug in that thread, and the
/// kernel's correct response is to destroy it and carry on -- not to halt the
/// machine.
///
/// Never returns when it returns `true`: the thread is gone.
fn terminate_if_from_user(frame: &InterruptStackFrame, reason: &str) -> bool {
    // The low two bits of the saved CS are the privilege level the faulting code
    // was running at.
    if frame.code_segment.0 & 3 != 3 {
        return false;
    }

    println!(
        "user thread '{}' killed: {reason} at {:#018x}",
        crate::sched::current_name().unwrap_or("?"),
        frame.instruction_pointer.as_u64()
    );
    crate::sched::exit_current()
}

extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    // CR2 holds the linear address whose translation failed. `read_raw` avoids
    // the non-canonical-address error case: when a fault is caused by a garbage
    // pointer, the raw bits are precisely what we want to see.
    let faulting_address = Cr2::read_raw();

    // A user thread reaching for memory it does not own is the boundary working,
    // not a kernel failure. Kill the thread and keep the system up.
    if error_code.contains(PageFaultErrorCode::USER_MODE) {
        println!(
            "user thread '{}' killed: page fault on {faulting_address:#018x} ({error_code:?})",
            crate::sched::current_name().unwrap_or("?")
        );
        crate::sched::exit_current();
    }

    // A kernel-mode fault a test asked for. Everything else falls through to the
    // panic, which is the right response to the kernel dereferencing something
    // it should not have.
    if crate::testing::take_expected_fault(crate::sched::current_id()) {
        println!(
            "expected kernel fault on {faulting_address:#018x} ({error_code:?}); \
             thread '{}' terminated",
            crate::sched::current_name().unwrap_or("?")
        );
        crate::sched::exit_current();
    }

    panic!(
        "EXCEPTION: PAGE FAULT\n\
         accessed address: {faulting_address:#018x}\n\
         error code:       {error_code:?}\n\
         {frame:#?}"
    );
}

/// The APIC timer, and the kernel's preemption point.
///
/// The end-of-interrupt goes out *before* the scheduler is called. Otherwise the
/// switch would carry us off to another thread with the interrupt still marked
/// in service, and the APIC would deliver nothing further until this thread
/// happened to be scheduled again -- if it ever were.
extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    crate::time::tick(crate::smp::cpu_index());
    apic::end_of_interrupt();

    // Drain the serial port before scheduling. There is no receive interrupt --
    // routing IRQ 4 would mean programming the IOAPIC, and finding it properly
    // means ACPI. At 100 Hz this adds at most 10 ms of latency, well inside the
    // UART's FIFO for anything a person types.
    crate::console::input::poll();

    // May not return until this thread is scheduled again. The switch happens on
    // this thread's stack, below the interrupt frame the CPU just pushed, so
    // resuming later unwinds back out through this handler and `iret`s
    // correctly.
    crate::sched::on_timer_tick();
}

/// Another processor changed a shared mapping and this one must forget what it
/// had cached.
///
/// Reloads CR3, which discards every non-global entry. Invalidating just the
/// affected page would be cheaper, but it would mean carrying the address across
/// the interrupt, and shootdowns are rare enough that the whole-TLB flush is not
/// worth the machinery.
extern "x86-interrupt" fn tlb_shootdown_handler(_frame: InterruptStackFrame) {
    x86_64::instructions::tlb::flush_all();
    apic::end_of_interrupt();
}

/// Fires when an interrupt is withdrawn between being raised and being
/// delivered.
///
/// Deliberately does *not* acknowledge. The APIC never set an in-service bit for
/// a spurious interrupt, so an EOI here would retire whichever real interrupt is
/// actually in service and lose it.
extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {}

/// Raised when the CPU hits a second fault while trying to service the first,
/// or when a fault handler is itself unreachable. Diverging: there is no
/// meaningful way to resume.
extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, error_code: u64) -> ! {
    // The double-fault error code is architecturally always zero; it is printed
    // only so a non-zero value would be visible if one ever appeared.
    panic!("EXCEPTION: DOUBLE FAULT (code {error_code})\n{frame:#?}");
}
