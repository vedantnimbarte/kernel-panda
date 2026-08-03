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
use crate::sync::Mutex;

/// Where the first I/O APIC's registers are mapped.
///
/// Clear of the heap, the kernel stacks, the Local APIC window and user space.
const IOAPIC_VIRT_BASE: u64 = 0x0000_7000_0000_0000;

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

/// Virtual address of the mapped registers, or zero before [`init`].
static REGISTERS: AtomicU64 = AtomicU64::new(0);

/// Serialises the two-step select-then-access sequence.
///
/// The index register is shared state on the chip itself: two processors
/// interleaving would have one read the value the other selected. Nothing here
/// runs from an interrupt handler, but the lock masks interrupts anyway -- a
/// timer landing between the select and the access would be the same bug.
static ACCESS: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    /// The firmware reported no I/O APIC.
    NotPresent,
    /// Its registers could not be mapped.
    Mapping,
    /// The requested pin is beyond what the chip has.
    NoSuchPin,
}

/// Map the first I/O APIC's registers.
///
/// # Safety
///
/// `io_apic` must be an entry the firmware reported. Call once, from the boot
/// processor, after paging is up.
pub unsafe fn init(io_apic: IoApic) -> Result<(), IoApicError> {
    if REGISTERS.load(Ordering::Acquire) != 0 {
        return Ok(());
    }

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(IOAPIC_VIRT_BASE));
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
    REGISTERS.store(IOAPIC_VIRT_BASE + offset, Ordering::Release);
    Ok(())
}

pub fn is_initialised() -> bool {
    REGISTERS.load(Ordering::Acquire) != 0
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
    let (_, pin) = topology.pin_for_gsi(gsi).ok_or(IoApicError::NoSuchPin)?;

    route(pin, crate::arch::x86_64::apic::SERIAL_VECTOR, apic_id, flags)?;
    crate::console::uart::enable_receive_interrupt();
    SERIAL_ROUTED.store(true, Ordering::Release);

    // Anything typed before this point is sitting in the FIFO, and on an
    // edge-triggered line the edge that would have announced it has already
    // been and gone.
    crate::console::input::poll();
    Ok(())
}

/// How many input pins this chip has.
pub fn pin_count() -> u8 {
    if !is_initialised() {
        return 0;
    }
    let version = read_register(REG_VERSION);
    // Bits 23..16 hold the highest input, so the count is one more.
    (((version >> 16) & 0xFF) as u8).saturating_add(1)
}

/// Route a pin to `vector` on `apic_id`, and unmask it.
///
/// `flags` is the MPS INTI word from the ACPI override, or zero for the ISA
/// defaults of edge-triggered and active high.
pub fn route(pin: u8, vector: u8, apic_id: u8, flags: u16) -> Result<(), IoApicError> {
    if !is_initialised() {
        return Err(IoApicError::NotPresent);
    }
    if pin >= pin_count() {
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

    write_entry(pin, entry);
    Ok(())
}

/// Stop delivering a pin without forgetting how it was routed.
pub fn mask(pin: u8) -> Result<(), IoApicError> {
    if !is_initialised() {
        return Err(IoApicError::NotPresent);
    }
    let index = REDIRECTION_BASE + pin as u32 * 2;
    let _guard = ACCESS.lock();
    // SAFETY: initialised, so the window is mapped.
    unsafe {
        let low = read_locked(index);
        write_locked(index, low | ENTRY_MASKED as u32);
    }
    Ok(())
}

/// Whether a pin is currently masked. Diagnostic, and used by tests.
pub fn is_masked(pin: u8) -> Option<bool> {
    if !is_initialised() || pin >= pin_count() {
        return None;
    }
    let index = REDIRECTION_BASE + pin as u32 * 2;
    Some(read_register(index) as u64 & ENTRY_MASKED != 0)
}

/// The vector a pin currently delivers. Diagnostic, and used by tests.
pub fn vector_of(pin: u8) -> Option<u8> {
    if !is_initialised() || pin >= pin_count() {
        return None;
    }
    let index = REDIRECTION_BASE + pin as u32 * 2;
    Some((read_register(index) & 0xFF) as u8)
}

/// Write both halves of a redirection entry.
///
/// High half first. The low half carries the mask bit, so writing it last means
/// the entry is never briefly live with a destination that has not been set --
/// which on a machine with more than one processor is an interrupt delivered to
/// whoever happens to be APIC id zero.
fn write_entry(pin: u8, entry: u64) {
    let index = REDIRECTION_BASE + pin as u32 * 2;
    let _guard = ACCESS.lock();
    // SAFETY: callers check `is_initialised`, so the window is mapped, and the
    // lock makes the select-then-access pair atomic.
    unsafe {
        write_locked(index + 1, (entry >> 32) as u32);
        write_locked(index, entry as u32);
    }
}

fn read_register(index: u32) -> u32 {
    let _guard = ACCESS.lock();
    // SAFETY: as above.
    unsafe { read_locked(index) }
}

/// # Safety
///
/// The register window must be mapped and `ACCESS` held.
unsafe fn read_locked(index: u32) -> u32 {
    let base = REGISTERS.load(Ordering::Acquire);
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
unsafe fn write_locked(index: u32, value: u32) {
    let base = REGISTERS.load(Ordering::Acquire);
    // SAFETY: forwarded from this function's contract.
    unsafe {
        core::ptr::write_volatile((base + REG_SELECT) as *mut u32, index);
        core::ptr::write_volatile((base + REG_WINDOW) as *mut u32, value);
    }
}
