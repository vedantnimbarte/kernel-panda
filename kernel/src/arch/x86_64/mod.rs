//! x86_64 platform support.

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod pic;
pub mod qemu;
pub mod syscall;

use x86_64::instructions::{hlt, interrupts};

use crate::time;

/// Install the descriptor tables.
///
/// Order is not negotiable: the IDT's double-fault entry references an IST slot
/// that only exists once the GDT's TSS is loaded.
pub fn init() {
    gdt::init();
    idt::init();
}

/// Start hardware interrupt delivery.
///
/// Separate from [`init`] and called much later, because the APIC needs its
/// MMIO page mapped and so cannot come up until the memory subsystem does.
///
/// Returns the measured timer frequency, or an error if the APIC could not be
/// started. A failure here is survivable -- the kernel simply has no sense of
/// time -- so it is reported rather than fatal.
pub fn enable_interrupts() -> Result<u32, apic::ApicError> {
    // SAFETY: interrupts are still disabled at this point in boot, and both
    // calls happen exactly once. The PIC must be neutralised before the APIC is
    // enabled, or legacy IRQs arrive on vectors that mean something else.
    let frequency = unsafe {
        pic::remap_and_mask();
        apic::init()?
    };

    // The tick rate is what we asked the timer for, not the calibrated APIC
    // frequency: `frequency` is the rate the APIC counts at, and the initial
    // count was set to deliver TIMER_HZ interrupts per second out of it.
    time::set_frequency(apic::TIMER_HZ as u64);

    interrupts::enable();
    Ok(frequency)
}

/// Park the CPU forever, waking only to service interrupts.
///
/// `hlt` rather than a spin loop: a bare `loop {}` pins a core at 100% and makes
/// the host fans audible during every debugging session.
pub fn halt_loop() -> ! {
    loop {
        hlt();
    }
}
