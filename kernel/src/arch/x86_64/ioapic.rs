//! The I/O APIC: where device interrupts come from once the legacy PIC is off.
//!
//! The Local APIC handles interrupts a processor raises for itself -- its timer,
//! IPIs from its neighbours. Everything a *device* raises arrives here first,
//! and this chip decides which vector it becomes and which processor sees it.
//! Without it, the only device interrupt the kernel can receive is none, which
//! is why the console has been polling from the timer.
//!
//! Two 32-bit registers, both MMIO, and every other register reached through
//! them: write an index to `IOREGSEL`, read or write the value at `IOWIN`. The
//! interesting ones are the redirection entries, two 32-bit halves each,
//! starting at index 0x10.
//!
//! ```text
//!  7..0   vector the interrupt becomes
//!  10..8  delivery mode (0 = fixed)
//!  11     destination mode (0 = physical, an APIC id)
//!  13     polarity (0 = active high, 1 = active low)
//!  15     trigger mode (0 = edge, 1 = level)
//!  16     mask
//!  63..56 destination APIC id
//! ```

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::acpi::IoApic;
use crate::memory::paging;
use crate::sync::IrqMutex;

/// Where I/O APIC registers are mapped, one page apiece.
///
/// Clear of the heap, the kernel stacks, the Local APIC window and user space.
const IOAPIC_VIRT_BASE: u64 = 0x0000_7000_0000_0000;

/// Chips this kernel will map. A machine with more than a handful is a machine
/// with more sockets than this scheduler is built for.
pub const MAX_IO_APICS: usize = 4;

const REG_SELECT: u64 = 0x00;
const REG_WINDOW: u64 = 0x10;

/// Index of the first redirection entry. Each occupies two indices.
const REDIRECTION_BASE: u32 = 0x10;

/// Register 0x01: how many inputs this chip has, minus one, in bits 23..16.
const REG_VERSION: u32 = 0x01;

const ENTRY_MASKED: u64 = 1 << 16;
const ENTRY_LEVEL_TRIGGERED: u64 = 1 << 15;
const ENTRY_ACTIVE_LOW: u64 = 1 << 13;

/// MPS INTI flags, bits 0-1: 3 means active low. 0 means "conforms", which for
/// an ISA interrupt means active high.
const FLAG_POLARITY_ACTIVE_LOW: u16 = 0b11;
/// Bits 2-3: 3 means level triggered. 0 conforms, which for ISA means edge.
const FLAG_TRIGGER_LEVEL: u16 = 0b11 << 2;

/// Virtual address of each mapped chip's registers, or zero for an unused slot.
static REGISTERS: [AtomicU64; MAX_IO_APICS] = [const { AtomicU64::new(0) }; MAX_IO_APICS];

/// Physical base of each mapped chip, so a repeat `init` recognises one it has
/// already seen rather than consuming another slot.
static PHYSICAL: [AtomicU64; MAX_IO_APICS] = [const { AtomicU64::new(0) }; MAX_IO_APICS];

/// Serialises the two-step select-then-access sequence.
///
/// The index register is shared state on the chip itself: two processors
/// interleaving would have one read the value the other selected. A timer
/// landing between the select and the access would be the same bug, so this
/// masks interrupts -- and that is also what keeps it inside the kernel-wide
/// rule that a lock holder is never preemptible. See [`crate::sync`].
static ACCESS: IrqMutex<()> = IrqMutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    /// The firmware reported no I/O APIC.
    NotPresent,
    /// Its registers could not be mapped.
    Mapping,
    /// The requested pin is beyond what the chip has.
    NoSuchPin,
    /// More I/O APICs than this kernel will map.
    TooMany,
}

/// Map one I/O APIC's registers, returning the slot it occupies.
///
/// Idempotent per chip: mapping one already mapped returns its existing slot
/// rather than consuming another.
///
/// # Safety
///
/// `io_apic` must be an entry the firmware reported. Call from the boot
/// processor, after paging is up.
pub unsafe fn init(io_apic: IoApic) -> Result<usize, IoApicError> {
    if let Some(slot) = slot_of(io_apic) {
        return Ok(slot);
    }

    let slot = (0..MAX_IO_APICS)
        .find(|&index| REGISTERS[index].load(Ordering::Acquire) == 0)
        .ok_or(IoApicError::TooMany)?;

    let virtual_base = IOAPIC_VIRT_BASE + slot as u64 * 4096;
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_base));
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(io_apic.address));

    // Uncached, and not executable. A cached mapping of a register window lets
    // the processor answer a read from a line it fetched earlier, which for a
    // device means reading a value that has since changed and never noticing.
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;

    // SAFETY: the frame is device memory the firmware named, and this virtual
    // range belongs to nothing else.
    unsafe { paging::map_to_frame(page, frame, flags) }.map_err(|_| IoApicError::Mapping)?;

    // Offset within the page, so an I/O APIC not on a page boundary still works.
    let offset = io_apic.address & 0xFFF;
    PHYSICAL[slot].store(io_apic.address, Ordering::Relaxed);
    REGISTERS[slot].store(virtual_base + offset, Ordering::Release);
    Ok(slot)
}

/// The slot a chip already occupies, if it has been mapped.
fn slot_of(io_apic: IoApic) -> Option<usize> {
    (0..MAX_IO_APICS).find(|&index| {
        REGISTERS[index].load(Ordering::Acquire) != 0
            && PHYSICAL[index].load(Ordering::Relaxed) == io_apic.address
    })
}

pub fn is_initialised() -> bool {
    REGISTERS[0].load(Ordering::Acquire) != 0
}

/// How many input pins a mapped chip has.
///
/// Only the chip knows: the MADT gives each one a starting global interrupt and
/// no length, so without asking, a machine with two I/O APICs has no way to tell
/// which owns a given interrupt.
pub fn inputs_of(io_apic: IoApic) -> Option<u8> {
    let slot = slot_of(io_apic)?;
    let version = read_register(slot, REG_VERSION);
    // Bits 23..16 hold the highest input, so the count is one more.
    Some((((version >> 16) & 0xFF) as u8).saturating_add(1))
}

/// Whether serial input is arriving by interrupt rather than by polling.
///
/// The timer handler asks, because it keeps polling the console as a fallback
/// when routing did not work out -- a machine whose only interface is the serial
/// port should be slow rather than deaf.
static SERIAL_ROUTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn serial_is_routed() -> bool {
    SERIAL_ROUTED.load(Ordering::Acquire)
}

/// Route the serial port's interrupt to `apic_id` and turn on the UART's
/// receive interrupt.
///
/// Order matters. The UART is told to raise the line only once something is
/// listening for it: a level-triggered input asserted with the entry still
/// masked stays asserted, and the first unmask delivers an interrupt for a byte
/// that was consumed long ago.
pub fn route_serial(topology: &crate::acpi::Topology, apic_id: u8) -> Result<(), IoApicError> {
    let (gsi, flags) = topology.resolve_irq(crate::console::uart::COM1_IRQ);
    let (chip, pin) = topology
        .pin_for_gsi(gsi, inputs_of)
        .ok_or(IoApicError::NoSuchPin)?;

    route(chip, pin, crate::arch::x86_64::apic::SERIAL_VECTOR, apic_id, flags)?;
    crate::console::uart::enable_receive_interrupt();
    SERIAL_ROUTED.store(true, Ordering::Release);

    // Anything typed before this point is sitting in the FIFO, and on an
    // edge-triggered line the edge that would have announced it has already
    // been and gone.
    crate::console::input::poll();
    Ok(())
}

/// How many input pins the first chip has. Diagnostic, and used by tests.
pub fn pin_count() -> u8 {
    pin_count_of_slot(0)
}

fn pin_count_of_slot(slot: usize) -> u8 {
    if slot >= MAX_IO_APICS || REGISTERS[slot].load(Ordering::Acquire) == 0 {
        return 0;
    }
    let version = read_register(slot, REG_VERSION);
    // Bits 23..16 hold the highest input, so the count is one more.
    (((version >> 16) & 0xFF) as u8).saturating_add(1)
}

/// Route a pin on `chip` to `vector` on `apic_id`, and unmask it.
///
/// `flags` is the MPS INTI word from the ACPI override, or zero for the ISA
/// defaults of edge-triggered and active high.
pub fn route(
    chip: IoApic,
    pin: u8,
    vector: u8,
    apic_id: u8,
    flags: u16,
) -> Result<(), IoApicError> {
    let slot = slot_of(chip).ok_or(IoApicError::NotPresent)?;
    if pin >= pin_count_of_slot(slot) {
        return Err(IoApicError::NoSuchPin);
    }

    let mut entry = vector as u64;
    entry |= (apic_id as u64) << 56;

    // Delivery mode fixed, destination mode physical, and unmasked: all zero
    // bits, so nothing to set. Polarity and trigger come from the firmware.
    if flags & 0b11 == FLAG_POLARITY_ACTIVE_LOW {
        entry |= ENTRY_ACTIVE_LOW;
    }
    if flags & (0b11 << 2) == FLAG_TRIGGER_LEVEL {
        entry |= ENTRY_LEVEL_TRIGGERED;
    }

    write_entry(slot, pin, entry);
    Ok(())
}

/// Stop delivering a pin on the first chip without forgetting how it was routed.
pub fn mask(pin: u8) -> Result<(), IoApicError> {
    if !is_initialised() {
        return Err(IoApicError::NotPresent);
    }
    let index = REDIRECTION_BASE + pin as u32 * 2;
    let _guard = ACCESS.lock();
    // SAFETY: initialised, so the window is mapped.
    unsafe {
        let low = read_locked(0, index);
        write_locked(0, index, low | ENTRY_MASKED as u32);
    }
    Ok(())
}

/// Whether a pin on the first chip is currently masked. Diagnostic, and used by
/// tests.
pub fn is_masked(pin: u8) -> Option<bool> {
    if !is_initialised() || pin >= pin_count() {
        return None;
    }
    let index = REDIRECTION_BASE + pin as u32 * 2;
    Some(read_register(0, index) as u64 & ENTRY_MASKED != 0)
}

/// The vector a pin on the first chip delivers. Diagnostic, and used by tests.
pub fn vector_of(pin: u8) -> Option<u8> {
    if !is_initialised() || pin >= pin_count() {
        return None;
    }
    let index = REDIRECTION_BASE + pin as u32 * 2;
    Some((read_register(0, index) & 0xFF) as u8)
}

/// Write both halves of a redirection entry.
///
/// High half first. The low half carries the mask bit, so writing it last means
/// the entry is never briefly live with a destination that has not been set --
/// which on a machine with more than one processor is an interrupt delivered to
/// whoever happens to be APIC id zero.
fn write_entry(slot: usize, pin: u8, entry: u64) {
    let index = REDIRECTION_BASE + pin as u32 * 2;
    let _guard = ACCESS.lock();
    // SAFETY: the caller resolved `slot` from a mapped chip, and the lock makes
    // the select-then-access pair atomic.
    unsafe {
        write_locked(slot, index + 1, (entry >> 32) as u32);
        write_locked(slot, index, entry as u32);
    }
}

fn read_register(slot: usize, index: u32) -> u32 {
    let _guard = ACCESS.lock();
    // SAFETY: as above.
    unsafe { read_locked(slot, index) }
}

/// # Safety
///
/// `slot` must name a mapped chip, and `ACCESS` must be held.
unsafe fn read_locked(slot: usize, index: u32) -> u32 {
    let base = REGISTERS[slot].load(Ordering::Acquire);
    // SAFETY: forwarded from this function's contract. Both accesses are
    // volatile because the device, not the compiler, decides what they mean.
    unsafe {
        core::ptr::write_volatile((base + REG_SELECT) as *mut u32, index);
        core::ptr::read_volatile((base + REG_WINDOW) as *const u32)
    }
}

/// # Safety
///
/// As [`read_locked`].
unsafe fn write_locked(slot: usize, index: u32, value: u32) {
    let base = REGISTERS[slot].load(Ordering::Acquire);
    // SAFETY: forwarded from this function's contract.
    unsafe {
        core::ptr::write_volatile((base + REG_SELECT) as *mut u32, index);
        core::ptr::write_volatile((base + REG_WINDOW) as *mut u32, value);
    }
}
