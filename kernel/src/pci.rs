//! PCI / PCI Express bus enumeration.
//!
//! Uses the legacy port-based configuration mechanism (0xCF8/0xCFC) rather than
//! memory-mapped ECAM. ECAM is the modern path and reaches extended config space
//! beyond offset 0xFF, but finding its window means parsing the ACPI MCFG table,
//! and nothing here needs a register above 0xFF yet. The port mechanism reaches
//! PCIe devices perfectly well for enumeration and BAR discovery.
//!
//! Enumeration is a brute-force sweep rather than a recursive walk across
//! bridges. 64k config reads cost microseconds, and a flat scan cannot get lost
//! in a misreported bridge topology.

use alloc::vec::Vec;

use x86_64::instructions::port::Port;

use crate::sync::without_interrupts;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

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

/// Read a 32-bit configuration register.
///
/// Interrupts are held off across the pair of port accesses: the address latch
/// and the data port are separate, so anything that slipped in between would
/// read from whatever device it selected instead.
pub fn read_config(address: Address, offset: u8) -> u32 {
    without_interrupts(|| {
        // SAFETY: 0xCF8/0xCFC are the architecturally fixed PCI configuration
        // ports. Reading configuration space has no side effects.
        unsafe {
            Port::<u32>::new(CONFIG_ADDRESS).write(address.selector(offset));
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
    without_interrupts(|| {
        // SAFETY: forwarded from this function's contract.
        unsafe {
            Port::<u32>::new(CONFIG_ADDRESS).write(address.selector(offset));
            Port::<u32>::new(CONFIG_DATA).write(value);
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
            let size = (!(mask & 0xFFFF_FFF0) as u32).wrapping_add(1) as u64;
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
