//! x86_64 platform support.

pub mod gdt;
pub mod idt;
pub mod qemu;

use x86_64::instructions::hlt;

/// Install the descriptor tables.
///
/// Order is not negotiable: the IDT's double-fault entry references an IST slot
/// that only exists once the GDT's TSS is loaded.
pub fn init() {
    gdt::init();
    idt::init();
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
