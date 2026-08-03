//! x86_64 platform support.

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod ioapic;
pub mod pic;
pub mod qemu;
pub mod syscall;

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::instructions::{hlt, interrupts};

use crate::time;

/// What [`enable_memory_protections`] managed to turn on.
///
/// Each of these depends on the processor, and writing an unsupported CR4 bit
/// raises a general protection fault, so none of them is assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protections {
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
}

/// Whether STAC and CLAC may be executed at all.
///
/// Cached because every user-memory access consults it, and the alternative --
/// reading CR4 -- is a privileged, serialising instruction on a hot path. It is
/// a property of the processor model, so every core in the system agrees.
///
/// Note that this tracks *support*, not CR4.SMAP: STAC and CLAC raise an invalid
/// opcode if the CPU does not implement SMAP, but are harmless no-ops in effect
/// when the CPU implements it and the bit happens to be clear.
static SMAP_USABLE: AtomicBool = AtomicBool::new(false);

/// Turn on the CPU's memory-protection features.
///
/// Must run before any mapping sets `NO_EXECUTE`: with `EFER.NXE` clear, bit 63
/// of a page table entry is reserved, and setting it faults on every access to
/// that page rather than being ignored.
///
/// Called once per processor: EFER and CR4 are per-CPU registers, so a core that
/// skips this runs with the protections off while the rest of the system
/// believes they are on.
pub fn enable_memory_protections() -> Protections {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    use x86_64::registers::model_specific::{Efer, EferFlags};

    // SAFETY: setting NXE only changes how bit 63 of a page table entry is
    // interpreted. Nothing has that bit set yet, so this cannot invalidate an
    // existing mapping.
    unsafe {
        Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
    }

    // CPUID leaf 7, subleaf 0: EBX bit 7 is SMEP, bit 20 is SMAP. Safe to call:
    // no target feature beyond the baseline is required.
    let features = core::arch::x86_64::__cpuid_count(7, 0).ebx;
    let smep_supported = features & (1 << 7) != 0;
    let smap_supported = features & (1 << 20) != 0;

    if smep_supported {
        // SAFETY: SMEP only forbids Ring 0 from *executing* user-accessible
        // pages. The kernel never jumps into user memory -- it enters Ring 3 by
        // `iretq`, which is a privilege change rather than a supervisor fetch --
        // so nothing legitimate is affected.
        unsafe {
            Cr4::update(|flags| flags.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION));
        }
    }

    if smap_supported {
        // Published before the bit is set, so that nothing can observe SMAP
        // active while still believing STAC would fault.
        SMAP_USABLE.store(true, Ordering::Release);

        // SAFETY: SMAP forbids Ring 0 from reading or writing user-accessible
        // pages unless EFLAGS.AC is set. Every place the kernel legitimately
        // does that goes through `UserAccess`, which sets AC for the duration.
        unsafe {
            Cr4::update(|flags| flags.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION));
        }
    }

    Protections {
        nx: true,
        smep: smep_supported,
        smap: smap_supported,
    }
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

/// Whether SMAP is active.
pub fn smap_enabled() -> bool {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION)
}

/// Permission for this processor to touch user-accessible pages, for as long as
/// the guard lives.
///
/// SMAP makes every supervisor read or write of a user page fault unless
/// `EFLAGS.AC` is set. That is the point: a kernel bug that dereferences an
/// attacker-supplied pointer somewhere it did not mean to now faults instead of
/// quietly succeeding. The handful of places the kernel *does* mean to -- copying
/// a syscall's buffer, filling a program's image before it starts -- say so by
/// holding one of these.
///
/// The guard also masks interrupts. Nothing clears `AC` on the way into a
/// handler, so an interrupt landing inside the window would run the whole
/// handler with SMAP disabled, and a context switch there would carry the
/// relaxation into an unrelated thread. Every window here is a bounded copy, so
/// the latency cost is small and the alternative is a protection that lapses at
/// moments an attacker can provoke.
#[must_use = "user memory may only be touched while the guard is alive"]
pub struct UserAccess {
    interrupts_were_enabled: bool,
}

impl UserAccess {
    /// Open the window.
    pub fn begin() -> Self {
        let interrupts_were_enabled = interrupts::are_enabled();
        interrupts::disable();

        if SMAP_USABLE.load(Ordering::Acquire) {
            // SAFETY: STAC is only invalid when the processor does not implement
            // SMAP, which is exactly what the flag records. It touches no memory
            // and sets EFLAGS.AC, which `Drop` clears again.
            unsafe { asm!("stac", options(nomem, nostack)) };
        }

        Self {
            interrupts_were_enabled,
        }
    }
}

impl Drop for UserAccess {
    fn drop(&mut self) {
        if SMAP_USABLE.load(Ordering::Acquire) {
            // SAFETY: as in `begin`; CLAC has the same availability rule and
            // simply clears the bit again.
            unsafe { asm!("clac", options(nomem, nostack)) };
        }

        if self.interrupts_were_enabled {
            interrupts::enable();
        }
    }
}

/// Run `f` with permission to touch user-accessible pages.
///
/// The closure form is the one to reach for: it makes the window an expression
/// rather than a scope somebody can accidentally extend.
pub fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    let _access = UserAccess::begin();
    f()
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
