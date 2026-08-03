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

/// Asks every other processor to drop its cached translations.
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xFD;

/// The serial port has received something. Delivered by the I/O APIC.
pub const SERIAL_VECTOR: u8 = 0x31;

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

    APIC_PHYSICAL.store(physical_base, Ordering::Release);
    APIC_VIRT.store(APIC_VIRT_BASE, Ordering::Release);

    // The bootloader's physical-memory window maps every physical address,
    // including this one, and it maps RAM cacheable. Two mappings of one page
    // with different memory types is architecturally undefined: a speculative
    // read through the cacheable view can return a value the device has since
    // changed, and nothing reports it.
    narrow_physical_window_alias(physical_base);

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
        CALIBRATED_HZ.store(apic_hz as u64, Ordering::Release);

        // Periodic mode from here on: one interrupt every 1/TIMER_HZ seconds.
        write_reg(REG_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
        write_reg(REG_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
        write_reg(REG_TIMER_INITIAL_COUNT, apic_hz / TIMER_HZ);

        Ok(apic_hz)
    }
}

/// Local APIC ID register.
const REG_ID: usize = 0x020;
/// Interrupt Command Register, low and high halves.
const REG_ICR_LOW: usize = 0x300;
const REG_ICR_HIGH: usize = 0x310;

/// ICR bit 12: the previous IPI has not been delivered yet.
const ICR_DELIVERY_PENDING: u32 = 1 << 12;
/// Delivery mode 101: INIT.
const ICR_INIT: u32 = 0x0000_4500;
/// Delivery mode 110: Startup.
const ICR_STARTUP: u32 = 0x0000_4600;

/// The measured tick rate, so secondary processors do not each repeat the PIT
/// calibration -- it is a property of the machine, not of the CPU.
static CALIBRATED_HZ: AtomicU64 = AtomicU64::new(0);

/// Make the physical-memory window's view of the APIC uncached, so it agrees
/// with the kernel's own mapping.
///
/// The bootloader covers that window with 2 MiB pages, so the alias has to be
/// split down to 4 KiB before one page of it can be treated differently --
/// changing the memory type of the whole 2 MiB would take other device
/// registers, or RAM, with it.
///
/// Failures are survivable and quiet. Without this the alias is safe in
/// practice anyway, because firmware marks the MMIO hole uncacheable by MTRR
/// and an MTRR of UC cannot be overridden to cacheable by a page-table
/// attribute. The point of doing it properly is to stop depending on that.
fn narrow_physical_window_alias(physical_base: u64) {
    if !paging::is_initialised() {
        return;
    }

    let alias = paging::physical_offset() + physical_base;
    if paging::split_huge_page(alias).is_err() {
        return;
    }

    let Some(flags) = paging::flags(alias) else {
        return;
    };
    if flags.contains(PageTableFlags::NO_CACHE) {
        return;
    }

    let page = Page::<Size4KiB>::containing_address(alias);
    let _ = paging::set_flags(
        page,
        flags | PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH,
    );
}

/// Physical base of the APIC's register window, or zero before `init`.
static APIC_PHYSICAL: AtomicU64 = AtomicU64::new(0);

pub fn physical_base() -> u64 {
    APIC_PHYSICAL.load(Ordering::Acquire)
}

/// This processor's Local APIC id.
pub fn id() -> u8 {
    if APIC_VIRT.load(Ordering::Acquire) == 0 {
        return 0;
    }
    // SAFETY: the base is non-zero, so the MMIO page is mapped. The id register
    // is read-only and has no side effects.
    let raw = unsafe { read_reg(REG_ID) };
    // The id lives in the top eight bits.
    (raw >> 24) as u8
}

/// Bring up the Local APIC on a processor that is not the boot processor.
///
/// Skips calibration: the tick rate was measured once on the boot processor and
/// is a property of the board's crystal, not of the core reading it.
///
/// # Safety
///
/// Call once per secondary processor, with interrupts disabled, after the boot
/// processor has finished `init`.
pub unsafe fn init_for_secondary() -> Result<(), ApicError> {
    if !is_supported() {
        return Err(ApicError::NotSupported);
    }
    if APIC_VIRT.load(Ordering::Acquire) == 0 {
        return Err(ApicError::NotSupported);
    }

    // SAFETY: the MMIO window was mapped by the boot processor into the page
    // tables this CPU is already using.
    unsafe {
        let base = Msr::new(IA32_APIC_BASE).read();
        Msr::new(IA32_APIC_BASE).write(base | APIC_BASE_ENABLE);

        write_reg(
            REG_SPURIOUS,
            SPURIOUS_SOFTWARE_ENABLE | SPURIOUS_VECTOR as u32,
        );

        let hz = CALIBRATED_HZ.load(Ordering::Acquire);
        if hz == 0 {
            return Err(ApicError::CalibrationFailed);
        }

        write_reg(REG_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);
        write_reg(REG_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
        write_reg(REG_TIMER_INITIAL_COUNT, (hz as u32) / TIMER_HZ);
    }

    Ok(())
}

/// Wait for the last inter-processor interrupt to be accepted.
///
/// # Safety
///
/// The APIC must be mapped.
unsafe fn wait_for_delivery() {
    for _ in 0..1_000_000 {
        // SAFETY: forwarded from this function's contract.
        if unsafe { read_reg(REG_ICR_LOW) } & ICR_DELIVERY_PENDING == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Send the INIT-SIPI-SIPI sequence that takes a processor out of reset.
///
/// The doubled startup IPI is not superstition: the Intel manual's own
/// algorithm sends two, because on some parts the first is dropped if it
/// arrives while the processor is still settling from INIT. A CPU that already
/// started ignores the second.
///
/// # Safety
///
/// `apic_id` must name a real processor, and `trampoline` must be a page-aligned
/// physical address below 1 MiB holding valid real-mode startup code.
pub unsafe fn start_processor(apic_id: u8, trampoline: u64) {
    let vector = ((trampoline >> 12) & 0xFF) as u32;
    let destination = (apic_id as u32) << 24;

    // SAFETY: the caller guarantees the target and the trampoline; the ICR is
    // the architecturally defined way to reach another processor.
    unsafe {
        write_reg(REG_ICR_HIGH, destination);
        write_reg(REG_ICR_LOW, ICR_INIT);
        wait_for_delivery();

        // The manual asks for 10 ms after INIT. Wait on real ticks where the
        // timer is running, but never unconditionally: this runs before the
        // other processors exist, and a stalled timer here would hang the boot
        // with no way to tell why.
        let deadline = crate::time::ticks() + 2;
        let mut spins = 0u64;
        while crate::time::ticks() < deadline {
            spins += 1;
            if spins > 50_000_000 {
                break;
            }
            core::hint::spin_loop();
        }

        for _ in 0..2 {
            write_reg(REG_ICR_HIGH, destination);
            write_reg(REG_ICR_LOW, ICR_STARTUP | vector);
            wait_for_delivery();

            // Roughly 200 microseconds. Precision does not matter here; being
            // too slow only delays boot.
            for _ in 0..200_000 {
                core::hint::spin_loop();
            }
        }
    }
}

/// What each processor has been asked to invalidate.
///
/// `NOTHING` means no request outstanding; `EVERYTHING` means reload CR3 and
/// discard the lot. Anything else is a single page address.
const NOTHING: u64 = 0;
const EVERYTHING: u64 = u64::MAX;
static SHOOTDOWN_REQUEST: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(NOTHING) }; crate::smp::MAX_CPUS];

/// Tell every other processor to forget one page, and wait until they have.
///
/// The TLB is per-CPU and the hardware does not keep them coherent. Unmapping a
/// page that other processors share -- anything in the kernel's own address
/// space -- leaves them translating an address whose frame has been handed to
/// someone else. Nothing faults; they simply keep reading and writing memory
/// that is no longer theirs, which is the worst shape a bug can take.
///
/// Two things changed here from the first version, which flushed everything and
/// did not wait. Naming the page means one `invlpg` instead of discarding every
/// translation the processor had learned. Waiting means the unmap has actually
/// taken effect everywhere by the time it returns, rather than at some point
/// afterwards -- the old comment argued the gap was harmless because the sender
/// had already finished, which is true only if nothing reuses the frame in the
/// meantime, and freeing it is precisely what happens next.
///
/// A process's own tables need no shootdown: only one CPU runs it at a time, and
/// the CR3 reload on the way in flushes everything non-global.
pub fn shoot_down_page(address: u64) {
    broadcast_shootdown(if address == NOTHING { EVERYTHING } else { address });
}

/// Tell every other processor to discard all of its cached translations.
///
/// For the cases where naming one page is not enough -- freeing an intermediate
/// page table invalidates whatever the processors cached *about the structure*,
/// not just one leaf.
pub fn broadcast_tlb_shootdown() {
    broadcast_shootdown(EVERYTHING);
}

fn broadcast_shootdown(what: u64) {
    if APIC_VIRT.load(Ordering::Acquire) == 0 {
        return;
    }

    let mut targeted = 0u64;
    crate::smp::for_each_other_online_processor(|index, apic_id| {
        let slot = &SHOOTDOWN_REQUEST[index];

        // Merge rather than overwrite. Another processor may already have asked
        // this one for a different page, and dropping that request would leave
        // a stale translation alive with nothing left to report it. Two
        // different pages become "everything", which is always a safe answer.
        let _ = slot.try_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
            Some(match pending {
                NOTHING => what,
                already if already == what => already,
                _ => EVERYTHING,
            })
        });

        targeted |= 1 << index;

        // SAFETY: the id came from the online set, so that processor has its
        // descriptor tables loaded and can take the vector.
        unsafe { send_ipi(apic_id, TLB_SHOOTDOWN_VECTOR) };
    });

    if targeted == 0 {
        return;
    }

    // Wait for every target to report in. The budget exists because a hang here
    // would be worse than a stale translation, not because exceeding it is
    // expected -- a processor that never answers has already stopped being a
    // processor.
    for _ in 0..50_000_000u64 {
        // Servicing our own slot while waiting is what makes this deadlock-free.
        // Two processors can be inside this loop at the same time, each waiting
        // on the other, and callers reach it with interrupts masked -- so
        // neither would ever take the other's IPI. Doing the work inline instead
        // of relying on delivery breaks that cycle.
        service_shootdown_request();

        let outstanding = (0..crate::smp::MAX_CPUS).any(|index| {
            targeted & (1 << index) != 0
                && SHOOTDOWN_REQUEST[index].load(Ordering::Acquire) != NOTHING
        });
        if !outstanding {
            return;
        }
        core::hint::spin_loop();
    }

    crate::println!("warning: a TLB shootdown went unacknowledged");
}

/// Carry out whatever this processor has been asked to invalidate.
///
/// Idempotent and safe to call at any time: it takes the request, so a second
/// call with nothing outstanding does nothing.
pub fn service_shootdown_request() {
    let index = crate::smp::cpu_index();
    let Some(slot) = SHOOTDOWN_REQUEST.get(index) else {
        return;
    };

    match slot.swap(NOTHING, Ordering::AcqRel) {
        NOTHING => {}
        EVERYTHING => x86_64::instructions::tlb::flush_all(),
        page => x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(page)),
    }
}

/// Send a fixed-delivery interrupt to one processor.
///
/// Addressed individually rather than with the "all except self" shorthand.
/// The shorthand reaches *every* processor, including one still climbing
/// through the startup trampoline with no IDT loaded -- which turns a routine
/// shootdown into a triple fault on the CPU that was almost ready.
///
/// # Safety
///
/// `apic_id` must name a processor that has installed an IDT handling `vector`.
pub unsafe fn send_ipi(apic_id: u8, vector: u8) {
    const LEVEL_ASSERT: u32 = 1 << 14;

    // SAFETY: the APIC is mapped, and this is the architecturally defined way to
    // interrupt another processor. The caller vouches for the target.
    unsafe {
        write_reg(REG_ICR_HIGH, (apic_id as u32) << 24);
        write_reg(REG_ICR_LOW, LEVEL_ASSERT | vector as u32);
        wait_for_delivery();
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
    // Several samples, and the median of them.
    //
    // One 10 ms sample is at the mercy of whatever else the machine was doing
    // during those 10 ms. Under a hypervisor -- which is the only place this has
    // ever run -- the host can deschedule the guest mid-measurement, and the
    // APIC count then reflects the pause rather than the tick rate. That is a
    // timer running at the wrong speed for the life of the boot, silently.
    //
    // The median rather than the mean, because the errors are not symmetric: a
    // stolen slice makes a sample far too large and nothing makes one too
    // small, so an outlier drags a mean but cannot move a median past its
    // neighbours.
    const SAMPLES: usize = 5;
    let mut measurements = [0u32; SAMPLES];

    for measurement in measurements.iter_mut() {
        // SAFETY: forwarded from this function's contract.
        *measurement = unsafe { calibrate_once()? };
    }

    measurements.sort_unstable();
    let median = measurements[SAMPLES / 2];

    // `median` counts post-divisor ticks over CALIBRATION_MS. Scale to one
    // second and report that: the initial-count register is denominated in the
    // same post-divisor ticks, so the caller can divide this by any target rate
    // directly.
    let ticks_per_second = median as u64 * (1000 / CALIBRATION_MS) as u64;
    Ok(ticks_per_second.try_into().unwrap_or(u32::MAX))
}

/// One PIT-gated measurement of the APIC tick rate, in post-divisor ticks over
/// [`CALIBRATION_MS`].
///
/// # Safety
///
/// As [`calibrate`].
unsafe fn calibrate_once() -> Result<u32, ApicError> {
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

    Ok(elapsed)
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
