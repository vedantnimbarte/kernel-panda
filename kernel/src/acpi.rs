//! Just enough ACPI to find the other CPUs.
//!
//! Walks the RSDP to the MADT and reads out the Local APIC entries. Nothing
//! else in ACPI is parsed -- no AML, no interpreter, none of the machinery that
//! makes ACPI a liability in a kernel that is meant to be auditable. The tables
//! read here are fixed-layout binary structures a few dozen bytes long.
//!
//! Every address in ACPI is physical, so everything is reached through the
//! kernel's physical memory window rather than by mapping tables individually.

use alloc::vec::Vec;

use x86_64::VirtAddr;

use crate::memory::paging;

/// Physical address of a table, as ACPI reports them.
type Physical = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// The bootloader did not report an RSDP.
    NoRsdp,
    /// The signature or checksum did not hold up.
    Corrupt,
    /// The tables are valid but contain no MADT.
    NoMadt,
    /// The tables are valid but do not contain the one asked for. Not an error
    /// in itself: MCFG is absent on anything predating PCI Express.
    NoSuchTable,
}

/// One I/O APIC, and where in the global interrupt space its inputs start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApic {
    pub address: u64,
    /// The global system interrupt its first input pin corresponds to.
    pub gsi_base: u32,
}

/// The firmware saying an ISA IRQ is not wired where the ISA convention says.
///
/// The one that matters in practice is IRQ 0: on almost every machine the timer
/// arrives on GSI 2 rather than GSI 0. Ignoring these and assuming IRQ number
/// equals pin number is the classic way to program a redirection entry that
/// nothing is connected to, and then wait forever for an interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceOverride {
    pub irq: u8,
    pub gsi: u32,
    /// The MPS INTI flags as reported: bits 0-1 polarity, bits 2-3 trigger mode.
    pub flags: u16,
}

/// What the MADT says about the machine.
#[derive(Debug, Clone)]
pub struct Topology {
    /// Physical address of the Local APIC registers, as ACPI reports it.
    pub local_apic_address: u64,
    /// APIC ids of every enabled processor, boot processor included.
    pub processors: Vec<u8>,
    /// Every I/O APIC the firmware reported.
    pub io_apics: Vec<IoApic>,
    /// ISA interrupts the firmware says are wired somewhere unexpected.
    pub overrides: Vec<SourceOverride>,
}

impl Topology {
    /// Physical address of the first I/O APIC, if there is one.
    pub fn io_apic_address(&self) -> Option<u64> {
        self.io_apics.first().map(|io_apic| io_apic.address)
    }

    /// Where an ISA IRQ actually lands, and how it is signalled.
    ///
    /// Identity-mapped unless the firmware said otherwise, which is what the
    /// ACPI specification prescribes for anything without an override.
    pub fn resolve_irq(&self, irq: u8) -> (u32, u16) {
        match self.overrides.iter().find(|entry| entry.irq == irq) {
            Some(entry) => (entry.gsi, entry.flags),
            None => (irq as u32, 0),
        }
    }

    /// The I/O APIC owning a global interrupt, and the pin within it.
    pub fn pin_for_gsi(&self, gsi: u32) -> Option<(IoApic, u8)> {
        // No redirection-entry count is read from the chip here, so ownership is
        // decided by base address alone: the last I/O APIC whose base is at or
        // below the interrupt. With one I/O APIC -- every machine this runs on
        // so far -- that is exact.
        let owner = self
            .io_apics
            .iter()
            .filter(|io_apic| io_apic.gsi_base <= gsi)
            .max_by_key(|io_apic| io_apic.gsi_base)?;
        u8::try_from(gsi - owner.gsi_base)
            .ok()
            .map(|pin| (*owner, pin))
    }
}

/// Read `count` bytes at a physical address through the offset window.
///
/// # Safety
///
/// The range must be inside physical memory the bootloader mapped.
unsafe fn physical_slice(address: Physical, count: usize) -> &'static [u8] {
    let virtual_address = paging::physical_offset() + address;
    // SAFETY: forwarded from this function's contract.
    unsafe { core::slice::from_raw_parts(virtual_address.as_ptr::<u8>(), count) }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

/// ACPI's checksum: every byte of the structure must sum to zero.
fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

/// Length of a system description table header.
const SDT_HEADER_LEN: usize = 36;

/// Parse the tables and report what CPUs exist.
///
/// # Safety
///
/// `rsdp` must be the physical address the bootloader reported, and physical
/// memory must be mapped at the offset window.
pub unsafe fn topology(rsdp: Physical) -> Result<Topology, AcpiError> {
    if rsdp == 0 {
        return Err(AcpiError::NoRsdp);
    }

    // SAFETY: the bootloader found this address in firmware memory, which is
    // inside the mapped physical range.
    let header = unsafe { physical_slice(rsdp, 20) };
    if &header[..8] != b"RSD PTR " || !checksum_ok(&header[..20]) {
        return Err(AcpiError::Corrupt);
    }

    let revision = header[15];

    // Revision 2 and up carry a 64-bit XSDT and a second checksum over the
    // longer structure. Preferring the XSDT matters on machines whose tables
    // live above 4 GiB, where the 32-bit RSDT cannot describe them.
    let (table_pointer_size, table_directory) = if revision >= 2 {
        // SAFETY: as above; revision 2 RSDPs are 36 bytes.
        let extended = unsafe { physical_slice(rsdp, 36) };
        if !checksum_ok(extended) {
            return Err(AcpiError::Corrupt);
        }
        (8usize, read_u64(extended, 24))
    } else {
        (4usize, read_u32(header, 16) as u64)
    };

    // SAFETY: a table directory reported by a validated RSDP.
    let directory_header = unsafe { physical_slice(table_directory, SDT_HEADER_LEN) };
    let directory_length = read_u32(directory_header, 4) as usize;
    if directory_length < SDT_HEADER_LEN {
        return Err(AcpiError::Corrupt);
    }

    // SAFETY: the length came from the table's own header.
    let directory = unsafe { physical_slice(table_directory, directory_length) };
    if !checksum_ok(directory) {
        return Err(AcpiError::Corrupt);
    }

    let entries = (directory_length - SDT_HEADER_LEN) / table_pointer_size;
    for index in 0..entries {
        let offset = SDT_HEADER_LEN + index * table_pointer_size;
        let table = if table_pointer_size == 8 {
            read_u64(directory, offset)
        } else {
            read_u32(directory, offset) as u64
        };

        // SAFETY: a pointer from a checksum-validated table directory.
        let table_header = unsafe { physical_slice(table, SDT_HEADER_LEN) };
        if &table_header[..4] != b"APIC" {
            continue;
        }

        let length = read_u32(table_header, 4) as usize;
        // SAFETY: the length came from the table's own header.
        let madt = unsafe { physical_slice(table, length) };
        if !checksum_ok(madt) {
            return Err(AcpiError::Corrupt);
        }
        return Ok(parse_madt(madt));
    }

    Err(AcpiError::NoMadt)
}

/// Entry type 0: a processor's Local APIC.
const ENTRY_LOCAL_APIC: u8 = 0;
/// Entry type 1: an I/O APIC.
const ENTRY_IO_APIC: u8 = 1;
/// Entry type 2: an ISA IRQ wired somewhere other than the obvious pin.
const ENTRY_SOURCE_OVERRIDE: u8 = 2;
/// Entry type 9: a Local APIC for a processor with an id above 255.
const ENTRY_LOCAL_X2APIC: u8 = 9;

/// Local APIC flags, bit 0: this processor is usable.
const PROCESSOR_ENABLED: u32 = 1;

fn parse_madt(madt: &[u8]) -> Topology {
    let local_apic_address = read_u32(madt, SDT_HEADER_LEN) as u64;
    let mut processors = Vec::new();
    let mut io_apics = Vec::new();
    let mut overrides = Vec::new();

    // Entries begin after the header, the 32-bit APIC address and the flags.
    let mut offset = SDT_HEADER_LEN + 8;

    while offset + 2 <= madt.len() {
        let kind = madt[offset];
        let length = madt[offset + 1] as usize;

        // A zero length would loop forever on a malformed table.
        if length < 2 || offset + length > madt.len() {
            break;
        }

        match kind {
            ENTRY_LOCAL_APIC if length >= 8 => {
                let apic_id = madt[offset + 3];
                let flags = read_u32(madt, offset + 4);
                // Disabled processors are listed but must not be started.
                if flags & PROCESSOR_ENABLED != 0 {
                    processors.push(apic_id);
                }
            }
            ENTRY_IO_APIC if length >= 12 => {
                io_apics.push(IoApic {
                    address: read_u32(madt, offset + 4) as u64,
                    gsi_base: read_u32(madt, offset + 8),
                });
            }
            ENTRY_SOURCE_OVERRIDE if length >= 10 => {
                overrides.push(SourceOverride {
                    irq: madt[offset + 3],
                    gsi: read_u32(madt, offset + 4),
                    flags: u16::from_le_bytes([madt[offset + 8], madt[offset + 9]]),
                });
            }
            ENTRY_LOCAL_X2APIC if length >= 16 => {
                let apic_id = read_u32(madt, offset + 4);
                let flags = read_u32(madt, offset + 8);
                // Only ids that fit the 8-bit APIC addressing this kernel uses.
                if flags & PROCESSOR_ENABLED != 0 && apic_id < 256 {
                    let apic_id = apic_id as u8;
                    if !processors.contains(&apic_id) {
                        processors.push(apic_id);
                    }
                }
            }
            _ => {}
        }

        offset += length;
    }

    Topology {
        local_apic_address,
        processors,
        io_apics,
        overrides,
    }
}

/// One PCI segment's memory-mapped configuration window, from the MCFG table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcamRegion {
    /// Physical base of the window.
    pub base: u64,
    /// PCI segment group. Almost always zero; a machine with more than one is
    /// large enough that nothing here would run on it.
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamRegion {
    /// Physical address of a device's configuration space.
    ///
    /// The layout is fixed by the PCI Express specification: bus, device and
    /// function are simply address bits, which is the whole appeal -- no latch,
    /// no pair of port accesses to keep together, and 4 KiB per function
    /// instead of 256 bytes.
    pub fn address_of(&self, bus: u8, device: u8, function: u8) -> Option<u64> {
        if bus < self.start_bus || bus > self.end_bus || device >= 32 || function >= 8 {
            return None;
        }
        let bus_offset = (bus - self.start_bus) as u64;
        Some(
            self.base
                + (bus_offset << 20)
                + ((device as u64) << 15)
                + ((function as u64) << 12),
        )
    }

    /// Bytes the whole window spans.
    pub fn length(&self) -> u64 {
        ((self.end_bus - self.start_bus) as u64 + 1) << 20
    }
}

/// Find the memory-mapped configuration windows, if the firmware describes any.
///
/// Separate from [`topology`] because the two tables answer unrelated questions
/// and a machine can perfectly well have one and not the other -- MCFG is absent
/// on anything that predates PCI Express.
///
/// # Safety
///
/// As [`topology`].
pub unsafe fn ecam_regions(rsdp: Physical) -> Result<Vec<EcamRegion>, AcpiError> {
    // SAFETY: forwarded from this function's contract.
    let table = unsafe { find_table(rsdp, b"MCFG")? };

    // Header, then eight reserved bytes, then 16-byte allocation entries.
    let mut regions = Vec::new();
    let mut offset = SDT_HEADER_LEN + 8;
    while offset + 16 <= table.len() {
        regions.push(EcamRegion {
            base: read_u64(&table, offset),
            segment: u16::from_le_bytes([table[offset + 8], table[offset + 9]]),
            start_bus: table[offset + 10],
            end_bus: table[offset + 11],
        });
        offset += 16;
    }

    Ok(regions)
}

/// Walk the table directory and return the table with `signature`, validated.
///
/// # Safety
///
/// As [`topology`].
unsafe fn find_table(rsdp: Physical, signature: &[u8; 4]) -> Result<Vec<u8>, AcpiError> {
    if rsdp == 0 {
        return Err(AcpiError::NoRsdp);
    }

    // SAFETY: forwarded from this function's contract.
    let header = unsafe { physical_slice(rsdp, 20) };
    if &header[..8] != b"RSD PTR " || !checksum_ok(&header[..20]) {
        return Err(AcpiError::Corrupt);
    }

    let revision = header[15];
    let (pointer_size, directory_address) = if revision >= 2 {
        // SAFETY: as above.
        let extended = unsafe { physical_slice(rsdp, 36) };
        if !checksum_ok(extended) {
            return Err(AcpiError::Corrupt);
        }
        (8usize, read_u64(extended, 24))
    } else {
        (4usize, read_u32(header, 16) as u64)
    };

    // SAFETY: a directory reported by a validated RSDP.
    let directory_header = unsafe { physical_slice(directory_address, SDT_HEADER_LEN) };
    let directory_length = read_u32(directory_header, 4) as usize;
    if directory_length < SDT_HEADER_LEN {
        return Err(AcpiError::Corrupt);
    }

    // SAFETY: the length came from the table's own header.
    let directory = unsafe { physical_slice(directory_address, directory_length) };
    if !checksum_ok(directory) {
        return Err(AcpiError::Corrupt);
    }

    let entries = (directory_length - SDT_HEADER_LEN) / pointer_size;
    for index in 0..entries {
        let offset = SDT_HEADER_LEN + index * pointer_size;
        let table = if pointer_size == 8 {
            read_u64(directory, offset)
        } else {
            read_u32(directory, offset) as u64
        };

        // SAFETY: a pointer from a checksum-validated directory.
        let table_header = unsafe { physical_slice(table, SDT_HEADER_LEN) };
        if &table_header[..4] != signature {
            continue;
        }

        let length = read_u32(table_header, 4) as usize;
        if length < SDT_HEADER_LEN {
            return Err(AcpiError::Corrupt);
        }
        // SAFETY: the length came from the table's own header.
        let body = unsafe { physical_slice(table, length) };
        if !checksum_ok(body) {
            return Err(AcpiError::Corrupt);
        }
        // Copied out rather than borrowed: the caller will map pages and take
        // locks, and holding a reference into firmware memory across that is a
        // lifetime nobody is checking.
        return Ok(body.to_vec());
    }

    Err(AcpiError::NoSuchTable)
}

/// Log what the firmware says the machine looks like.
pub fn log_topology(topology: &Topology) {
    crate::println!(
        "acpi: {} processor(s), local APIC at {:#x}",
        topology.processors.len(),
        topology.local_apic_address
    );
    for io_apic in &topology.io_apics {
        crate::println!(
            "  io apic at {:#x}, interrupts from {}",
            io_apic.address,
            io_apic.gsi_base
        );
    }
    for entry in &topology.overrides {
        crate::println!(
            "  irq {} is wired to interrupt {} (flags {:#06x})",
            entry.irq,
            entry.gsi,
            entry.flags
        );
    }
}

/// The address the kernel should use for the Local APIC.
///
/// ACPI reports it, but the MSR is authoritative -- firmware is allowed to have
/// relocated it, and a table written before that would still name the old one.
pub fn preferred_local_apic(topology: &Topology, from_msr: u64) -> u64 {
    if from_msr != 0 {
        from_msr
    } else {
        topology.local_apic_address
    }
}

/// Convenience: the physical memory window as a `VirtAddr`, for callers that
/// want to read a table themselves.
pub fn window() -> VirtAddr {
    paging::physical_offset()
}
