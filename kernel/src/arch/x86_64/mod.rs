//! x86_64 platform support.

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod pic;
pub mod qemu;
pub mod syscall;

use x86_64::instructions::{hlt, interrupts};

use crate::time;

/// Turn on the CPU's memory-protection features.
///
/// Must run before any mapping sets `NO_EXECUTE`: with `EFER.NXE` clear, bit 63
/// of a page table entry is reserved, and setting it faults on every access to
/// that page rather than being ignored.
///
/// Returns what was actually enabled -- SMEP is not present on every CPU, and
/// writing an unsupported CR4 bit raises a general protection fault, so it is
/// checked rather than assumed.
pub fn enable_memory_protections() -> (bool, bool) {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    use x86_64::registers::model_specific::{Efer, EferFlags};

    // SAFETY: setting NXE only changes how bit 63 of a page table entry is
    // interpreted. Nothing has that bit set yet, so this cannot invalidate an
    // existing mapping.
    unsafe {
        Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
    }

    // CPUID leaf 7, subleaf 0, EBX bit 7. Safe to call: no target feature beyond
    // the baseline is required.
    let smep_supported = core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 7) != 0;

    if smep_supported {
        // SAFETY: SMEP only forbids Ring 0 from *executing* user-accessible
        // pages. The kernel never jumps into user memory -- it enters Ring 3 by
        // `iretq`, which is a privilege change rather than a supervisor fetch --
        // so nothing legitimate is affected.
        unsafe {
            Cr4::update(|flags| flags.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION));
        }
    }

    (true, smep_supported)
}

/// Whether NX is active.
pub fn nx_enabled() -> bool {
    use x86_64::registers::model_specific::{Efer, EferFlags};
    Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE)
}

/// Whether SMEP is active.
pub fn smep_enabled() -> bool {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION)
}

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
