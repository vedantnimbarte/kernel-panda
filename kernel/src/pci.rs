//! PCI / PCI Express bus enumeration.
//!
//! Two ways to reach configuration space, and the kernel uses whichever it has.
//!
//! The legacy mechanism is a pair of ports: latch an address in 0xCF8, read or
//! write 0xCFC. It works on everything, and it reaches PCIe devices perfectly
//! well -- but only the first 256 bytes of each function's configuration space,
//! because the selector has nowhere to put a wider offset. Everything PCI
//! Express added lives above that: capability structures for MSI-X, AER, link
//! control, and the rest.
//!
//! ECAM is the memory-mapped alternative, and bus, device and function are
//! simply address bits in a window the firmware describes in the ACPI MCFG
//! table. No latch, no pair of accesses to keep together, no lock, and 4 KiB
//! per function instead of 256 bytes.
//!
//! ECAM is preferred when the firmware describes it, and the port mechanism
//! remains as the fallback. They must agree about the low 256 bytes -- they are
//! two views of the same registers -- and `both_mechanisms_agree` checks that
//! rather than assuming it.
//!
//! Enumeration is a brute-force sweep rather than a recursive walk across
//! bridges. 64k config reads cost microseconds, and a flat scan cannot get lost
//! in a misreported bridge topology.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use x86_64::instructions::port::Port;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::acpi::EcamRegion;
use crate::memory::paging;
use crate::sync::{without_interrupts, Mutex};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

/// Where the ECAM window is mapped. Clear of the heap, the kernel stacks, both
/// APIC windows and user space.
const ECAM_VIRT_BASE: u64 = 0x0000_7100_0000_0000;

/// Virtual base of the mapped window, or zero if there is none.
static ECAM_VIRT: AtomicU64 = AtomicU64::new(0);
static ECAM_START_BUS: AtomicU8 = AtomicU8::new(0);
static ECAM_END_BUS: AtomicU8 = AtomicU8::new(0);

/// Largest configuration offset the legacy port mechanism can reach.
pub const LEGACY_CONFIG_LIMIT: u16 = 0x100;
/// Largest offset ECAM can reach: 4 KiB per function.
pub const EXTENDED_CONFIG_LIMIT: u16 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcamError {
    /// The firmware described no configuration window.
    NotDescribed,
    /// The window could not be mapped.
    Mapping,
}

/// Buses the firmware described.
pub fn ecam_bus_range() -> Option<(u8, u8)> {
    if !ecam_available() {
        return None;
    }
    Some((
        ECAM_START_BUS.load(Ordering::Relaxed),
        ECAM_END_BUS.load(Ordering::Relaxed),
    ))
}

/// Physical base of the described window, or zero.
static ECAM_PHYSICAL: AtomicU64 = AtomicU64::new(0);

/// Buses kept mapped at once.
///
/// Firmware routinely describes all 256 buses whether or not anything is on
/// them -- QEMU's q35 does. Mapping that eagerly is 256 MiB of window and 65,536
/// page-table entries for buses that will never answer, so each bus is mapped
/// the first time something reaches past offset 0xFF on it. That alone still
/// ended with the whole window mapped once something had walked every bus, so
/// the set is also bounded: past this many, the bus used least recently is
/// unmapped to make room. Three buses with devices on them fit many times over.
pub const MAX_MAPPED_BUSES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BusState {
    Unmapped,
    Mapped,
    /// Chosen for eviction, and being unmapped outside the lock. Nobody may
    /// start reading it, and nobody may map it again until it is done.
    Evicting,
}

struct Buses {
    state: [BusState; 256],
    /// Accesses in flight. Only a bus with none can be evicted: callers read
    /// through a raw address, and unmapping underneath one is a page fault.
    readers: [u8; 256],
    /// When each bus was last reached for, in `clock` ticks.
    last_used: [u64; 256],
    clock: u64,
}

impl Buses {
    fn mapped(&self) -> usize {
        self.state.iter().filter(|state| **state == BusState::Mapped).count()
    }

    /// The idle mapped bus used longest ago, if the set is full.
    fn victim(&self) -> Option<u8> {
        if self.mapped() < MAX_MAPPED_BUSES {
            return None;
        }
        (0..256)
            .filter(|&bus| self.state[bus] == BusState::Mapped && self.readers[bus] == 0)
            .min_by_key(|&bus| self.last_used[bus])
            .map(|bus| bus as u8)
    }
}

static BUSES: Mutex<Buses> = Mutex::new(Buses {
    state: [BusState::Unmapped; 256],
    readers: [0; 256],
    last_used: [0; 256],
    clock: 0,
});

/// Note the window and make the first bus reachable.
///
/// # Safety
///
/// `region` must come from the firmware's own MCFG table. Call once, from the
/// boot processor, after paging is up.
pub unsafe fn init_ecam(region: EcamRegion) -> Result<(), EcamError> {
    if ECAM_VIRT.load(Ordering::Acquire) != 0 {
        return Ok(());
    }

    ECAM_PHYSICAL.store(region.base, Ordering::Relaxed);
    ECAM_START_BUS.store(region.start_bus, Ordering::Relaxed);
    ECAM_END_BUS.store(region.end_bus, Ordering::Relaxed);
    ECAM_VIRT.store(ECAM_VIRT_BASE, Ordering::Release);

    // Bus zero eagerly, because something is always on it and the first read
    // would otherwise map it anyway.
    let result = with_config_space(Address::new(region.start_bus, 0, 0), 0x100, true, |_| ());
    if result.is_none() {
        ECAM_VIRT.store(0, Ordering::Release);
        return Err(EcamError::Mapping);
    }
    Ok(())
}

/// First page of a bus's megabyte of window.
fn bus_page(bus: u8) -> Page<Size4KiB> {
    let start = ECAM_START_BUS.load(Ordering::Relaxed);
    let offset = ((bus - start) as u64) << 20;
    Page::containing_address(VirtAddr::new(ECAM_VIRT_BASE + offset))
}

/// Map one bus: 256 pages, one per (device, function) pair.
///
/// On failure, returns how many pages did get mapped. The caller unmaps them
/// once it has released the bus lock -- unmapping shoots down, and a shootdown
/// must not wait under a lock.
fn map_bus(bus: u8) -> Result<(), u64> {
    let start = ECAM_START_BUS.load(Ordering::Relaxed);
    let base = ECAM_PHYSICAL.load(Ordering::Relaxed) + (((bus - start) as u64) << 20);

    // Uncached: configuration space is device registers, and a cached read can
    // answer from a line fetched before the device changed.
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;

    for page_index in 0..256u64 {
        let page = bus_page(bus) + page_index;
        let frame =
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(base + page_index * 4096));
        // SAFETY: device memory the firmware named, at a virtual range belonging
        // to nothing else.
        if unsafe { paging::map_to_frame(page, frame, flags) }.is_err() {
            return Err(page_index);
        }
    }
    Ok(())
}

/// Buses whose configuration space is currently mapped. Diagnostic, and used by
/// tests.
pub fn mapped_bus_count() -> usize {
    without_interrupts(|| BUSES.lock().mapped())
}

/// Whether configuration space is reachable by memory rather than by ports.
pub fn ecam_available() -> bool {
    ECAM_VIRT.load(Ordering::Acquire) != 0
}

/// The highest configuration offset that can be read on this machine.
pub fn config_limit() -> u16 {
    if ecam_available() {
        EXTENDED_CONFIG_LIMIT
    } else {
        LEGACY_CONFIG_LIMIT
    }
}

/// Run `access` against a function's configuration register through ECAM, or
/// return `None` if ECAM does not cover it.
///
/// `map_if_needed` decides whether reaching an unmapped bus is worth mapping it.
/// It is false for offsets the ports can also reach, and that is what keeps
/// enumeration cheap: a full sweep touches all 256 buses at offset zero, and
/// mapping on every access would churn the whole window through the bounded set
/// during the first scan. Above 0xFF there is no alternative, so the bus is
/// mapped -- evicting another if the set is full.
///
/// The bus is held for the duration of `access`, so it cannot be evicted from
/// under the address `access` is given. The eviction itself -- 256 unmaps and a
/// shootdown -- happens after the lock is released: holding a lock with
/// interrupts masked while waiting on other processors to acknowledge would
/// wait on exactly the processors that are spinning for that lock.
fn with_config_space<R>(
    address: Address,
    offset: u16,
    map_if_needed: bool,
    access: impl FnOnce(u64) -> R,
) -> Option<R> {
    let base = ECAM_VIRT.load(Ordering::Acquire);
    if base == 0 || offset >= EXTENDED_CONFIG_LIMIT {
        return None;
    }
    let start = ECAM_START_BUS.load(Ordering::Relaxed);
    let end = ECAM_END_BUS.load(Ordering::Relaxed);
    let bus = address.bus;
    if bus < start || bus > end {
        return None;
    }

    let mut half_mapped = 0;
    let evict = loop {
        let claimed = without_interrupts(|| -> Option<Option<Option<u8>>> {
            let mut buses = BUSES.lock();
            match buses.state[bus as usize] {
                BusState::Mapped => {}
                // Not worth waiting for when the ports can answer instead.
                BusState::Evicting if !map_if_needed => return None,
                BusState::Evicting => return Some(None),
                BusState::Unmapped if !map_if_needed => return None,
                BusState::Unmapped => {
                    if let Err(mapped) = map_bus(bus) {
                        // Whatever did map is removed below, outside the lock.
                        // Marked meanwhile so nobody maps over it.
                        if mapped > 0 {
                            buses.state[bus as usize] = BusState::Evicting;
                        }
                        half_mapped = mapped;
                        return None;
                    }
                    buses.state[bus as usize] = BusState::Mapped;
                }
            }

            buses.readers[bus as usize] += 1;
            buses.clock += 1;
            buses.last_used[bus as usize] = buses.clock;

            let victim = buses.victim();
            if let Some(victim) = victim {
                buses.state[victim as usize] = BusState::Evicting;
            }
            Some(Some(victim))
        });
        let Some(claimed) = claimed else {
            if half_mapped > 0 {
                // A half-mapped bus would read correctly for some devices and
                // fault for others.
                paging::unmap_kernel_range(bus_page(bus), half_mapped);
                without_interrupts(|| BUSES.lock().state[bus as usize] = BusState::Unmapped);
            }
            return None;
        };

        match claimed {
            Some(victim) => break victim,
            // Being evicted and needed: wait for the unmap to finish, then map it
            // afresh. Nothing is held while waiting.
            None => core::hint::spin_loop(),
        }
    };

    let register = base
        + (((bus - start) as u64) << 20)
        + ((address.device as u64) << 15)
        + ((address.function as u64) << 12)
        + (offset & !0x3) as u64;
    let result = access(register);

    without_interrupts(|| BUSES.lock().readers[bus as usize] -= 1);

    if let Some(victim) = evict {
        paging::unmap_kernel_range(bus_page(victim), 256);
        without_interrupts(|| BUSES.lock().state[victim as usize] = BusState::Unmapped);
    }
    Some(result)
}

/// Returned by a config read for a device that is not there. The bus floats
/// high when nothing answers.
const NO_DEVICE: u16 = 0xFFFF;

/// Bit 7 of the header-type byte: the device has more than one function.
const MULTIFUNCTION: u8 = 0x80;

/// Class code 0x03: display controller.
pub const CLASS_DISPLAY: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// The 0xCF8 selector: enable bit, then bus, device, function and a
    /// dword-aligned register offset.
    fn selector(self, offset: u8) -> u32 {
        (1 << 31)
            | ((self.bus as u32) << 16)
            | ((self.device as u32) << 11)
            | ((self.function as u32) << 8)
            | ((offset as u32) & 0xFC)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    pub address: Address,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
}

impl DeviceInfo {
    /// A human-readable guess at what the device is, from its class code.
    pub fn class_name(&self) -> &'static str {
        match (self.class, self.subclass) {
            (0x00, _) => "legacy",
            (0x01, 0x06) => "SATA controller",
            (0x01, 0x08) => "NVMe controller",
            (0x01, _) => "storage controller",
            (0x02, _) => "network controller",
            (0x03, _) => "display controller",
            (0x04, _) => "multimedia",
            (0x06, 0x00) => "host bridge",
            (0x06, 0x01) => "ISA bridge",
            (0x06, 0x04) => "PCI-to-PCI bridge",
            (0x06, _) => "bridge",
            (0x0C, 0x03) => "USB controller",
            (0x0C, _) => "serial bus controller",
            _ => "unknown",
        }
    }
}

/// A decoded base address register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bar {
    Memory {
        address: u64,
        size: u64,
        prefetchable: bool,
        /// 64-bit BARs consume the following register too.
        wide: bool,
    },
    Io {
        port: u16,
        size: u32,
    },
}

/// Read a 32-bit configuration register, through whichever mechanism exists.
pub fn read_config(address: Address, offset: u8) -> u32 {
    read_config_extended(address, offset as u16)
}

/// Read a configuration register at any offset ECAM can reach.
///
/// Offsets at or above 0x100 return all-ones without ECAM, which is what the
/// bus returns for a register that is not there -- so a caller walking the
/// extended capability list terminates rather than looping on a value it
/// invented.
pub fn read_config_extended(address: Address, offset: u16) -> u32 {
    // Above 0xFF only ECAM will do, so the bus is mapped if it is not already.
    let map_if_needed = offset >= LEGACY_CONFIG_LIMIT;
    // SAFETY: the address is inside a bus the call holds mapped, and dword
    // aligned by construction. Volatile because the device, not the compiler,
    // decides what a read means.
    let read = |register: u64| unsafe { core::ptr::read_volatile(register as *const u32) };
    if let Some(value) = with_config_space(address, offset, map_if_needed, read) {
        return value;
    }

    if offset >= LEGACY_CONFIG_LIMIT {
        return u32::MAX;
    }

    // Interrupts are held off across the pair of port accesses: the address
    // latch and the data port are separate, so anything that slipped in between
    // would read from whatever device it selected instead. ECAM needs none of
    // this, which is a real part of its appeal.
    without_interrupts(|| {
        // SAFETY: 0xCF8/0xCFC are the architecturally fixed PCI configuration
        // ports. Reading configuration space has no side effects.
        unsafe {
            Port::<u32>::new(CONFIG_ADDRESS).write(address.selector(offset as u8));
            Port::<u32>::new(CONFIG_DATA).read()
        }
    })
}

/// Write a 32-bit configuration register.
///
/// # Safety
///
/// Writing configuration space reprograms hardware. The caller must know what
/// the register does; a careless write can remap or disable a device.
pub unsafe fn write_config(address: Address, offset: u8, value: u32) {
    // SAFETY: forwarded from this function's contract; the address is inside a
    // bus the call holds mapped, and dword aligned.
    let write = |register: u64| unsafe { core::ptr::write_volatile(register as *mut u32, value) };
    if with_config_space(address, offset as u16, false, write).is_some() {
        return;
    }

    without_interrupts(|| {
        // SAFETY: forwarded from this function's contract.
        unsafe {
            Port::<u32>::new(CONFIG_ADDRESS).write(address.selector(offset));
            Port::<u32>::new(CONFIG_DATA).write(value);
        }
    })
}

/// Read a register through ECAM specifically, mapping the bus if need be.
///
/// `None` when there is no window, or the bus is outside it, or it could not be
/// mapped. Only useful for checking the two views agree; everything else should
/// go through [`read_config`].
pub fn read_config_ecam(address: Address, offset: u16) -> Option<u32> {
    // SAFETY: inside a bus the call holds mapped, dword aligned by construction,
    // and volatile because the device decides what a read means.
    with_config_space(address, offset, true, |register| unsafe {
        core::ptr::read_volatile(register as *const u32)
    })
}

/// Read a register through the port mechanism specifically.
///
/// Only useful for checking the two views agree; everything else should go
/// through [`read_config`].
pub fn read_config_legacy(address: Address, offset: u8) -> u32 {
    without_interrupts(|| {
        // SAFETY: as in `read_config_extended`.
        unsafe {
            Port::<u32>::new(CONFIG_ADDRESS).write(address.selector(offset));
            Port::<u32>::new(CONFIG_DATA).read()
        }
    })
}

fn probe(address: Address) -> Option<DeviceInfo> {
    let identity = read_config(address, 0x00);
    let vendor_id = (identity & 0xFFFF) as u16;
    if vendor_id == NO_DEVICE {
        return None;
    }

    let classes = read_config(address, 0x08);
    let header = read_config(address, 0x0C);

    Some(DeviceInfo {
        address,
        vendor_id,
        device_id: (identity >> 16) as u16,
        revision: (classes & 0xFF) as u8,
        prog_if: ((classes >> 8) & 0xFF) as u8,
        subclass: ((classes >> 16) & 0xFF) as u8,
        class: ((classes >> 24) & 0xFF) as u8,
        header_type: ((header >> 16) & 0xFF) as u8,
    })
}

/// Sweep every bus, device and function, returning everything that answers.
pub fn enumerate() -> Vec<DeviceInfo> {
    let mut found = Vec::new();

    for bus in 0..=255u8 {
        for device in 0..32u8 {
            let base = Address::new(bus, device, 0);
            let Some(info) = probe(base) else {
                continue;
            };

            let multifunction = info.header_type & MULTIFUNCTION != 0;
            found.push(info);

            // Functions 1-7 only exist when function 0 says so. Probing them
            // regardless is harmless but wastes most of the scan.
            if multifunction {
                for function in 1..8u8 {
                    if let Some(info) = probe(Address::new(bus, device, function)) {
                        found.push(info);
                    }
                }
            }
        }
    }

    found
}

/// The first display controller on the bus, if there is one.
pub fn find_display() -> Option<DeviceInfo> {
    enumerate()
        .into_iter()
        .find(|device| device.class == CLASS_DISPLAY)
}

/// A PCI Express extended capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedCapability {
    pub id: u16,
    pub version: u8,
    /// Offset of the capability header within configuration space.
    pub offset: u16,
}

/// Where the extended capability list starts. Fixed by the specification.
const EXTENDED_CAPABILITY_BASE: u16 = 0x100;

/// Walk a device's extended capability list.
///
/// Empty without ECAM: the whole list lives above offset 0xFF, which the port
/// mechanism cannot address. This is the concrete thing the MCFG table buys.
pub fn extended_capabilities(address: Address) -> Vec<ExtendedCapability> {
    let mut found = Vec::new();
    if !ecam_available() {
        return found;
    }

    let mut offset = EXTENDED_CAPABILITY_BASE;
    // Bounded by the space itself: a device whose list points in a circle would
    // otherwise spin here forever, and firmware bugs of that shape are real.
    for _ in 0..(EXTENDED_CONFIG_LIMIT / 4) {
        if !(EXTENDED_CAPABILITY_BASE..EXTENDED_CONFIG_LIMIT).contains(&offset) {
            break;
        }

        let header = read_config_extended(address, offset);
        // All-ones is an absent device; all-zeroes is a device with no extended
        // capabilities at all. Both mean stop.
        if header == 0 || header == u32::MAX {
            break;
        }

        found.push(ExtendedCapability {
            id: (header & 0xFFFF) as u16,
            version: ((header >> 16) & 0xF) as u8,
            offset,
        });

        let next = ((header >> 20) & 0xFFF) as u16;
        if next == 0 {
            break;
        }
        offset = next;
    }

    found
}

/// Walk a device's standard capability list: `(id, offset)` pairs.
///
/// These live in the first 256 bytes, so either configuration mechanism reaches
/// them. MSI and MSI-X are here; everything PCI Express added is in the extended
/// list above.
pub fn capabilities(address: Address) -> Vec<(u8, u8)> {
    let mut found = Vec::new();
    // Status bit 4: the device has a capability list at all.
    if (read_config(address, 0x04) >> 16) & (1 << 4) == 0 {
        return found;
    }

    let mut offset = (read_config(address, 0x34) & 0xFC) as u8;
    // Bounded, because a list that points in a circle is a real firmware bug and
    // the space holds at most 48 capabilities.
    for _ in 0..48 {
        // The first 0x40 bytes are the standard header; nothing lives there.
        if offset < 0x40 {
            break;
        }
        let header = read_config(address, offset);
        found.push(((header & 0xFF) as u8, offset));
        offset = ((header >> 8) & 0xFC) as u8;
    }
    found
}

/// Capability id of MSI-X.
const CAPABILITY_MSIX: u8 = 0x11;
/// Capability id of MSI, MSI-X's predecessor: one address and one value in
/// configuration space rather than a table in a BAR.
const CAPABILITY_MSI: u8 = 0x05;

/// Interrupt vectors handed out to MSI-X entries.
pub const MSI_VECTOR_BASE: u8 = 0x50;
pub const MSI_VECTORS: usize = 16;

/// The function each MSI vector calls, as a raw pointer, or zero for a free one.
/// Atomic so the interrupt handler can read it without a lock.
static MSI_HANDLERS: [AtomicU64; MSI_VECTORS] = [const { AtomicU64::new(0) }; MSI_VECTORS];
/// What each handler is passed: which device, when one driver serves several.
static MSI_CONTEXTS: [AtomicU64; MSI_VECTORS] = [const { AtomicU64::new(0) }; MSI_VECTORS];

/// Claim a free vector for `handler`.
///
/// The CAS decides ownership; the context is written only after it is won, so
/// two callers racing the same free slot cannot have the loser's context land
/// after the winner's. Safe to write second rather than first because nothing
/// can interrupt on a vector before the device that will use it is told about
/// it, which happens later in the caller, after this returns.
fn claim_vector(handler: fn(usize), context: usize) -> Result<usize, MsiError> {
    (0..MSI_VECTORS)
        .find(|&slot| {
            let won = MSI_HANDLERS[slot]
                .compare_exchange(0, handler as usize as u64, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
            if won {
                MSI_CONTEXTS[slot].store(context as u64, Ordering::Release);
            }
            won
        })
        .ok_or(MsiError::NoVector)
}

/// Where MSI-X tables are mapped, one page per routed entry.
const MSIX_VIRT_BASE: u64 = 0x0000_7300_0000_0000;
static MSIX_NEXT_PAGE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsiError {
    /// The device has no MSI-X capability, or not that many entries.
    NotSupported,
    /// Every MSI vector is taken.
    NoVector,
    /// The table's BAR is not a memory BAR, or could not be mapped.
    Table,
}

/// Point MSI-X table entry `entry` of a device at a vector of its own, which
/// calls `handler` with `context` on this processor, and turn MSI-X on.
///
/// Message-signalled interrupts are why no ACPI interpreter is needed. A
/// device's legacy interrupt pin reaches the I/O APIC through wiring only the
/// firmware's AML describes; an MSI-X entry is just an address and a value the
/// device writes when it wants attention, and the address is the Local APIC's.
///
/// `handler` runs in interrupt context with interrupts masked. It must not
/// block.
pub fn route_msix(address: Address, entry: u16, handler: fn(usize), context: usize) -> Result<u8, MsiError> {
    let capability = capabilities(address)
        .into_iter()
        .find(|(id, _)| *id == CAPABILITY_MSIX)
        .map(|(_, offset)| offset)
        .ok_or(MsiError::NotSupported)?;

    let header = read_config(address, capability);
    let control = (header >> 16) as u16;
    let table_size = (control & 0x7FF) + 1;
    if entry >= table_size {
        return Err(MsiError::NotSupported);
    }

    // Table offset and BAR indicator share a register: the low three bits say
    // which BAR, the rest is the offset into it.
    let table = read_config(address, capability + 4);
    let bar_offset = 0x10 + (table & 0b111) as u8 * 4;
    let raw = read_config(address, bar_offset);
    if raw & 1 != 0 {
        return Err(MsiError::Table);
    }
    let mut base = (raw & !0xF) as u64;
    if (raw >> 1) & 0b11 == 0b10 {
        base |= (read_config(address, bar_offset + 4) as u64) << 32;
    }
    let physical = base + (table & !0b111) as u64 + entry as u64 * 16;

    // A vector first, so a device that fires the moment it is unmasked has
    // somewhere to go.
    let slot = claim_vector(handler, context)?;
    let vector = MSI_VECTOR_BASE + slot as u8;

    let virtual_page = MSIX_VIRT_BASE + MSIX_NEXT_PAGE.fetch_add(1, Ordering::AcqRel) * 4096;
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;
    // SAFETY: the device's own register space, named by its BAR, at a virtual
    // page nothing else uses.
    let mapped = unsafe {
        paging::map_to_frame(
            Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_page)),
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(physical)),
            flags,
        )
    };
    if mapped.is_err() {
        MSI_HANDLERS[slot].store(0, Ordering::Release);
        return Err(MsiError::Table);
    }
    let register = virtual_page + (physical & 0xFFF);

    // Memory decoding, so the table is reachable, and bus mastering, which is
    // what lets the device send the message at all.
    let command = read_config(address, 0x04);
    // SAFETY: enabling decoding and mastering on a device its driver owns.
    unsafe { write_config(address, 0x04, command | 0b110) };

    let apic_id = crate::arch::x86_64::apic::id();
    // SAFETY: an MSI-X table entry -- address low, address high, data, vector
    // control -- inside the page just mapped. Unmasked last, once the entry is
    // complete.
    unsafe {
        core::ptr::write_volatile(register as *mut u32, 0xFEE0_0000 | (apic_id as u32) << 12);
        core::ptr::write_volatile((register + 4) as *mut u32, 0);
        core::ptr::write_volatile((register + 8) as *mut u32, vector as u32);
        core::ptr::write_volatile((register + 12) as *mut u32, 0);
    }

    // Enabled, and the function-wide mask cleared.
    let control = (control | 1 << 15) & !(1 << 14);
    // SAFETY: the MSI-X control word of this device's own capability.
    unsafe { write_config(address, capability, (header & 0xFFFF) | (control as u32) << 16) };

    Ok(vector)
}

/// Point a device's MSI capability at a vector of its own, which calls `handler`
/// with `context` on this processor, and turn MSI on. One message only.
pub fn route_msi(address: Address, handler: fn(usize), context: usize) -> Result<u8, MsiError> {
    let capability = capabilities(address)
        .into_iter()
        .find(|(id, _)| *id == CAPABILITY_MSI)
        .map(|(_, offset)| offset)
        .ok_or(MsiError::NotSupported)?;
    let header = read_config(address, capability);
    let control = (header >> 16) as u16;
    // A 64-bit capable function has an upper address word, which moves the data
    // register along by four bytes.
    let data_offset = if control & (1 << 7) != 0 { 12 } else { 8 };

    let slot = claim_vector(handler, context)?;
    let vector = MSI_VECTOR_BASE + slot as u8;
    let apic_id = crate::arch::x86_64::apic::id();

    // SAFETY: the MSI capability of a device its driver owns. Address and data
    // are written before the enable bit that lets the device use them, and the
    // legacy pin is switched off so the interrupt does not also arrive there.
    unsafe {
        write_config(address, capability + 4, 0xFEE0_0000 | (apic_id as u32) << 12);
        if data_offset == 12 {
            write_config(address, capability + 8, 0);
        }
        write_config(address, capability + data_offset, vector as u32);

        let command = read_config(address, 0x04);
        write_config(address, 0x04, command | 0b110 | 1 << 10);

        // Enabled, asking for one message.
        let control = (control & !(0b111 << 4)) | 1;
        write_config(address, capability, (header & 0xFFFF) | (control as u32) << 16);
    }
    Ok(vector)
}

/// Called by the interrupt handler for MSI vector `slot`.
pub fn msi_dispatch(slot: usize) {
    let raw = MSI_HANDLERS[slot].load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only ever stored from a `fn(usize)` in `claim_vector`.
        let handler: fn(usize) = unsafe { core::mem::transmute::<usize, fn(usize)>(raw as usize) };
        handler(MSI_CONTEXTS[slot].load(Ordering::Acquire) as usize);
    }
}

/// Check the two views of configuration space describe the same registers.
///
/// They are two windows onto one set of registers, so they must agree about the
/// low 256 bytes. If they do not, the MCFG table describes a window that is not
/// where the firmware says -- and every ECAM read after that is of some
/// unrelated physical memory, which is a far worse failure than not having ECAM
/// at all.
///
/// Returns `None` when there is nothing to compare.
pub fn both_mechanisms_agree() -> Option<bool> {
    if !ecam_available() {
        return None;
    }

    let mut compared = 0;
    for device in enumerate() {
        // The identity register: vendor and device id, the one register whose
        // value is certain to be stable between two reads.
        //
        // `read_config_ecam` rather than `read_config`, which would fall back to
        // the ports for a low offset on an unmapped bus and compare them with
        // themselves.
        let through_ports = read_config_legacy(device.address, 0x00);
        let Some(through_memory) = read_config_ecam(device.address, 0x00) else {
            continue;
        };
        if through_ports != through_memory {
            return Some(false);
        }
        compared += 1;
    }

    Some(compared > 0)
}

/// Decode base address register `index` (0-5) of a device.
///
/// Sizing a BAR means writing all-ones and reading back which bits stuck, which
/// momentarily points the register somewhere meaningless. The original value is
/// restored before returning, and the whole sequence runs with interrupts off so
/// nothing can touch the device while its BAR is scrambled.
pub fn read_bar(address: Address, index: u8) -> Option<Bar> {
    if index > 5 {
        return None;
    }
    let offset = 0x10 + index * 4;

    without_interrupts(|| {
        let original = read_config(address, offset);
        if original == 0 {
            return None;
        }

        // SAFETY: the all-ones write is the architecturally defined way to
        // discover a BAR's size, and the original value is written straight back
        // below. Interrupts are off, so no driver can observe the intermediate
        // state.
        let mask = unsafe {
            write_config(address, offset, 0xFFFF_FFFF);
            let probed = read_config(address, offset);
            write_config(address, offset, original);
            probed
        };

        if original & 1 == 1 {
            // I/O space BAR: bit 0 set, address in bits 2 and up.
            let size = (!(mask & 0xFFFF_FFFC)).wrapping_add(1);
            return Some(Bar::Io {
                port: (original & 0xFFFC) as u16,
                size,
            });
        }

        // Memory BAR. Bits 2:1 give the width, bit 3 prefetchability.
        let wide = (original >> 1) & 0b11 == 0b10;
        let prefetchable = original & 0b1000 != 0;
        let low = (original & 0xFFFF_FFF0) as u64;

        let (address_bits, size) = if wide {
            let high = read_config(address, offset + 4) as u64;

            // SAFETY: as above, for the upper half of a 64-bit BAR.
            let high_mask = unsafe {
                let saved = read_config(address, offset + 4);
                write_config(address, offset + 4, 0xFFFF_FFFF);
                let probed = read_config(address, offset + 4);
                write_config(address, offset + 4, saved);
                probed
            } as u64;

            let combined_mask = (high_mask << 32) | (mask & 0xFFFF_FFF0) as u64;
            (
                (high << 32) | low,
                (!combined_mask).wrapping_add(1),
            )
        } else {
            let size = (!(mask & 0xFFFF_FFF0)).wrapping_add(1) as u64;
            (low, size)
        };

        Some(Bar::Memory {
            address: address_bits,
            size,
            prefetchable,
            wide,
        })
    })
}

/// Print the bus, one line per device.
pub fn log_devices() {
    let devices = enumerate();
    crate::println!("pci: {} devices", devices.len());

    for device in &devices {
        crate::println!(
            "  {:02x}:{:02x}.{}  {:04x}:{:04x}  class {:02x}.{:02x}  {}",
            device.address.bus,
            device.address.device,
            device.address.function,
            device.vendor_id,
            device.device_id,
            device.class,
            device.subclass,
            device.class_name(),
        );
    }
}
