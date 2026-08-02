//! The Local APIC and its timer.
//!
//! The APIC rather than the 8259 PIC, because the PRD rules out legacy hardware
//! support and because per-CPU interrupt delivery is a prerequisite for the SMP
//! work the scheduler will eventually need. The PIC is remapped and masked in
//! `pic.rs`; nothing routes through it.
//!
//! The timer's tick rate is not knowable in advance -- the APIC counts at the
//! core crystal frequency, which varies by machine and is not reliably
//! reported by CPUID. It is measured against the PIT at boot instead.

use core::arch::x86_64::__cpuid;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::paging::{self, MapError};

/// IA32_APIC_BASE. Holds the APIC's physical base address and its hardware
/// enable bit.
const IA32_APIC_BASE: u32 = 0x1B;
/// Bit 11: APIC global enable.
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// Bits 12 and up hold the base address; the low bits are flags.
const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Where the APIC's MMIO page is mapped. Chosen to sit clear of the kernel, the
/// heap at 0x4444_4444_0000, and the bootloader's physical memory window.
const APIC_VIRT_BASE: u64 = 0x_7777_0000_0000;

// Register offsets, in bytes from the APIC base.
const REG_EOI: usize = 0x0B0;
const REG_SPURIOUS: usize = 0x0F0;
const REG_LVT_TIMER: usize = 0x320;
const REG_TIMER_INITIAL_COUNT: usize = 0x380;
const REG_TIMER_CURRENT_COUNT: usize = 0x390;
const REG_TIMER_DIVIDE: usize = 0x3E0;

/// Spurious Interrupt Vector Register, bit 8: APIC software enable. The APIC
/// delivers nothing until this is set, regardless of the MSR enable bit.
const SPURIOUS_SOFTWARE_ENABLE: u32 = 1 << 8;

/// LVT bit 16: mask this entry.
const LVT_MASKED: u32 = 1 << 16;
/// LVT bits 17-18 = 01: periodic mode.
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

/// Divide Configuration Register value for "divide by 16". The exact divisor
/// does not matter to the arithmetic below, which measures the post-divisor rate
/// directly, but it has to be the same during calibration and afterwards.
const TIMER_DIVIDE_BY_16: u32 = 0b0011;

/// Vector the timer is delivered on. Just past the 32 reserved exception
/// vectors, and clear of the remapped (but masked) PIC range at 0x20-0x2F.
pub const TIMER_VECTOR: u8 = 0x30;
/// Conventionally the highest vector. Never actually handled meaningfully.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// How often the timer should fire once calibration is done.
pub const TIMER_HZ: u32 = 100;

// PIT, used once at boot to measure the APIC's tick rate.
const PIT_CHANNEL2_DATA: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;
/// Port 0x61: bit 0 gates channel 2, bit 1 drives the speaker, bit 5 reports
/// channel 2's output line.
const PIT_CONTROL: u16 = 0x61;
const PIT_GATE: u8 = 1 << 0;
const PIT_SPEAKER: u8 = 1 << 1;
const PIT_OUTPUT: u8 = 1 << 5;
/// The PIT's input clock, fixed by history at roughly 1.193182 MHz.
const PIT_FREQUENCY: u32 = 1_193_182;
/// Long enough to measure accurately, short enough not to stall boot.
const CALIBRATION_MS: u32 = 10;

/// Bound on the calibration poll so a machine whose PIT never asserts its output
/// line fails cleanly instead of hanging the boot forever.
const CALIBRATION_SPIN_LIMIT: u64 = 500_000_000;

static APIC_VIRT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicError {
    /// CPUID says this CPU has no Local APIC.
    NotSupported,
    /// The MMIO page could not be mapped.
    MappingFailed(MapError),
    /// The PIT never signalled terminal count, or the APIC timer did not move.
    CalibrationFailed,
}

/// Bring up the Local APIC and start its timer.
///
/// Returns the measured APIC tick frequency in Hz.
///
/// # Safety
///
/// Call once, with interrupts disabled, after the memory subsystem is up and
/// after `pic::remap_and_mask`.
pub unsafe fn init() -> Result<u32, ApicError> {
    if !is_supported() {
        return Err(ApicError::NotSupported);
    }

    // SAFETY: reading IA32_APIC_BASE is unconditionally safe on a CPU that
    // reported APIC support via CPUID, which was just checked.
    let base_msr = unsafe { Msr::new(IA32_APIC_BASE).read() };
    let physical_base = base_msr & APIC_BASE_ADDR_MASK;

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(APIC_VIRT_BASE));
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(physical_base));

    // NO_CACHE and WRITE_THROUGH are not optional. APIC registers are device
    // memory: a cached mapping would let reads return stale values and let
    // writes sit in a store buffer, so the EOI at the end of every interrupt
    // might never reach the chip.
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;

    // SAFETY: `physical_base` is the APIC's MMIO window as reported by the CPU
    // itself. It sits far above the highest usable RAM address, so it is not
    // memory the frame allocator manages and mapping it cannot alias anything
    // the allocator might hand out.
    unsafe { paging::map_to_frame(page, frame, flags) }.map_err(ApicError::MappingFailed)?;

    APIC_VIRT.store(APIC_VIRT_BASE, Ordering::Release);

    // SAFETY: the MMIO page is mapped and the base recorded, so the register
    // accessors below are valid from here on.
    unsafe {
        // Set the hardware enable bit if the firmware left it clear.
        Msr::new(IA32_APIC_BASE).write(base_msr | APIC_BASE_ENABLE);

        // Software-enable the APIC and park spurious interrupts on a vector
        // with a harmless handler.
        write_reg(
            REG_SPURIOUS,
            SPURIOUS_SOFTWARE_ENABLE | SPURIOUS_VECTOR as u32,
        );

        let apic_hz = calibrate()?;

        // Periodic mode from here on: one interrupt every 1/TIMER_HZ seconds.
        write_reg(REG_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
        write_reg(REG_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
        write_reg(REG_TIMER_INITIAL_COUNT, apic_hz / TIMER_HZ);

        Ok(apic_hz)
    }
}

/// Acknowledge the interrupt currently being serviced.
///
/// Every APIC-delivered interrupt handler must call this before returning.
/// Skipping it leaves the in-service bit set and the APIC delivers nothing
/// further at that priority -- the machine goes quiet rather than crashing,
/// which makes it an unpleasant bug to track down.
pub fn end_of_interrupt() {
    if APIC_VIRT.load(Ordering::Acquire) == 0 {
        return;
    }
    // SAFETY: the base is non-zero, so `init` completed and the MMIO page is
    // mapped. Writing zero to the EOI register is the architecturally defined
    // acknowledgement and has no other effect.
    unsafe { write_reg(REG_EOI, 0) }
}

/// Whether the APIC has been brought up.
pub fn is_initialised() -> bool {
    APIC_VIRT.load(Ordering::Acquire) != 0
}

fn is_supported() -> bool {
    // Leaf 1 is present on every x86_64 CPU, and `__cpuid` needs no target
    // feature beyond the baseline, so this is a safe call.
    let cpuid = __cpuid(1);
    // EDX bit 9: the CPU has an on-chip Local APIC.
    cpuid.edx & (1 << 9) != 0
}

/// Measure the APIC timer's tick rate against the PIT.
///
/// The APIC counts at the core crystal frequency, which differs between
/// machines and is not dependably reported anywhere. Counting APIC ticks across
/// a known PIT interval is the portable way to learn it.
///
/// PIT channel 2 is used rather than channel 0 because channel 2's output is
/// readable from a port, so this needs no interrupt -- which matters, since
/// interrupts are still off at this point in boot.
///
/// # Safety
///
/// The APIC MMIO page must be mapped and `APIC_VIRT` set.
unsafe fn calibrate() -> Result<u32, ApicError> {
    let pit_count = (PIT_FREQUENCY / (1000 / CALIBRATION_MS)) as u16;

    let mut control = Port::<u8>::new(PIT_CONTROL);
    let mut command = Port::<u8>::new(PIT_COMMAND);
    let mut data = Port::<u8>::new(PIT_CHANNEL2_DATA);

    // SAFETY: the PIT and its gate port are architecturally fixed and present on
    // QEMU's machine model. The speaker bit is held low throughout, so none of
    // this is audible.
    let elapsed = unsafe {
        // Drop the gate so the channel is stopped while it is reprogrammed, and
        // keep the speaker disconnected.
        let base = control.read() & !PIT_GATE & !PIT_SPEAKER;
        control.write(base);

        // Channel 2, access lobyte then hibyte, mode 0 (interrupt on terminal
        // count). Mode 0 is what makes the output line go high exactly once,
        // when the count runs out.
        command.write(0b1011_0000);
        data.write((pit_count & 0xFF) as u8);
        data.write((pit_count >> 8) as u8);

        // Start the APIC counting down from the top, masked and one-shot: we
        // only ever read its current count, never take an interrupt from it.
        write_reg(REG_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
        write_reg(REG_LVT_TIMER, LVT_MASKED);
        write_reg(REG_TIMER_INITIAL_COUNT, u32::MAX);

        // Raising the gate starts the PIT. Both timers are now running.
        control.write(base | PIT_GATE);

        let mut spins = 0u64;
        while control.read() & PIT_OUTPUT == 0 {
            spins += 1;
            if spins > CALIBRATION_SPIN_LIMIT {
                write_reg(REG_TIMER_INITIAL_COUNT, 0);
                return Err(ApicError::CalibrationFailed);
            }
            core::hint::spin_loop();
        }

        let remaining = read_reg(REG_TIMER_CURRENT_COUNT);

        // Stop the APIC timer and drop the PIT gate again.
        write_reg(REG_TIMER_INITIAL_COUNT, 0);
        control.write(base);

        u32::MAX - remaining
    };

    if elapsed == 0 {
        return Err(ApicError::CalibrationFailed);
    }

    // `elapsed` counts post-divisor ticks over CALIBRATION_MS. Scale to one
    // second and report that: the initial-count register is denominated in the
    // same post-divisor ticks, so the caller can divide this by any target rate
    // directly.
    let ticks_per_second = elapsed as u64 * (1000 / CALIBRATION_MS) as u64;
    Ok(ticks_per_second.try_into().unwrap_or(u32::MAX))
}

/// # Safety
///
/// `APIC_VIRT` must hold the base of a mapped, uncached APIC MMIO page, and
/// `offset` must be a valid register offset within it.
unsafe fn read_reg(offset: usize) -> u32 {
    let base = APIC_VIRT.load(Ordering::Acquire) as usize;
    // SAFETY: forwarded from this function's contract.
    unsafe { read_volatile((base + offset) as *const u32) }
}

/// # Safety
///
/// As `read_reg`.
unsafe fn write_reg(offset: usize, value: u32) {
    let base = APIC_VIRT.load(Ordering::Acquire) as usize;
    // SAFETY: forwarded from this function's contract.
    unsafe { write_volatile((base + offset) as *mut u32, value) }
}
