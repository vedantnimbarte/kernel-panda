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

/// Which buses have had their megabyte of configuration space mapped.
///
/// Firmware routinely describes all 256 buses whether or not anything is on
/// them -- QEMU's q35 does. Mapping that eagerly is 256 MiB of window and 65,536
/// page-table entries established at boot for buses that will never answer, so
/// each bus is mapped the first time something reaches for it instead. A machine
/// with devices on three buses pays for three.
static MAPPED_BUSES: Mutex<[bool; 256]> = Mutex::new([false; 256]);

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
    ensure_bus_mapped(region.start_bus).inspect_err(|_| {
        ECAM_VIRT.store(0, Ordering::Release);
    })
}

/// Map one bus's megabyte of configuration space if it is not mapped already.
///
/// 256 pages: one per (device, function) pair, since each function gets 4 KiB
/// and a bus holds 32 devices of 8 functions.
fn ensure_bus_mapped(bus: u8) -> Result<(), EcamError> {
    let base = ECAM_PHYSICAL.load(Ordering::Relaxed);
    if base == 0 {
        return Err(EcamError::NotDescribed);
    }

    let start = ECAM_START_BUS.load(Ordering::Relaxed);
    let end = ECAM_END_BUS.load(Ordering::Relaxed);
    if bus < start || bus > end {
        return Err(EcamError::NotDescribed);
    }

    // Held across the mapping, so two processors reaching for the same bus at
    // once cannot both decide it is unmapped and race to map it -- the second
    // would fail with AlreadyMapped and report a window that is in fact fine.
    crate::sync::without_interrupts(|| {
        let mut mapped = MAPPED_BUSES.lock();
        if mapped[bus as usize] {
            return Ok(());
        }

        // Uncached: configuration space is device registers, and a cached read
        // can answer from a line fetched before the device changed.
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH
            | PageTableFlags::NO_EXECUTE;

        let offset = ((bus - start) as u64) << 20;
        for page_index in 0..256u64 {
            let virtual_address = VirtAddr::new(ECAM_VIRT_BASE + offset + page_index * 4096);
            let physical = PhysAddr::new(base + offset + page_index * 4096);
            let page = Page::<Size4KiB>::containing_address(virtual_address);
            let frame = PhysFrame::<Size4KiB>::containing_address(physical);

            // SAFETY: device memory the firmware named, at a virtual range
            // belonging to nothing else.
            if unsafe { paging::map_to_frame(page, frame, flags) }.is_err() {
                // Unwind: a half-mapped bus would read correctly for some
                // devices and fault for others.
                for done in 0..page_index {
                    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                        ECAM_VIRT_BASE + offset + done * 4096,
                    ));
                    let _ = paging::unmap(page);
                }
                return Err(EcamError::Mapping);
            }
        }

        mapped[bus as usize] = true;
        Ok(())
    })
}

fn bus_is_mapped(bus: u8) -> bool {
    crate::sync::without_interrupts(|| MAPPED_BUSES.lock()[bus as usize])
}

/// Buses whose configuration space is currently mapped. Diagnostic, and used by
/// tests.
pub fn mapped_bus_count() -> usize {
    crate::sync::without_interrupts(|| MAPPED_BUSES.lock().iter().filter(|m| **m).count())
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

/// Virtual address of a function's configuration space, if ECAM covers it.
///
/// `map_if_needed` decides whether reaching an unmapped bus is worth mapping it.
/// It is false for offsets the ports can also reach, and that is what keeps
/// enumeration cheap: a full sweep touches all 256 buses at offset zero, so
/// mapping on every access would map the entire window during the first scan
/// and lazy mapping would have bought nothing. Above 0xFF there is no
/// alternative, so the bus is mapped.
///
/// A failure is not fatal -- the caller falls back to the port mechanism, which
/// reaches the low 256 bytes of any bus.
fn ecam_address(address: Address, offset: u16, map_if_needed: bool) -> Option<u64> {
    let base = ECAM_VIRT.load(Ordering::Acquire);
    if base == 0 || offset >= EXTENDED_CONFIG_LIMIT {
        return None;
    }

    let start = ECAM_START_BUS.load(Ordering::Relaxed);
    let end = ECAM_END_BUS.load(Ordering::Relaxed);
    if address.bus < start || address.bus > end {
        return None;
    }

    if map_if_needed {
        ensure_bus_mapped(address.bus).ok()?;
    } else if !bus_is_mapped(address.bus) {
        return None;
    }

    Some(
        base + (((address.bus - start) as u64) << 20)
            + ((address.device as u64) << 15)
            + ((address.function as u64) << 12)
            + (offset & !0x3) as u64,
    )
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
    if let Some(virtual_address) = ecam_address(address, offset, map_if_needed) {
        // SAFETY: the address is inside the window mapped by `init_ecam`, and
        // is dword aligned by construction. Volatile because the device, not
        // the compiler, decides what a read means.
        return unsafe { core::ptr::read_volatile(virtual_address as *const u32) };
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
    if let Some(virtual_address) = ecam_address(address, offset as u16, false) {
        // SAFETY: forwarded from this function's contract; the address is
        // inside the mapped window and dword aligned.
        unsafe { core::ptr::write_volatile(virtual_address as *mut u32, value) };
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
    let virtual_address = ecam_address(address, offset, true)?;
    // SAFETY: inside the window mapped by `ensure_bus_mapped`, dword aligned by
    // construction, and volatile because the device decides what a read means.
    Some(unsafe { core::ptr::read_volatile(virtual_address as *const u32) })
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
