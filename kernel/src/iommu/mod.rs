//! VT-d: confining a device's DMA to memory its driver actually owns.
//!
//! This is the inventory stage only. It parses the firmware's DMAR table
//! ([`crate::acpi::dmar`]), maps each remapping unit's register page, and
//! reads back its capabilities -- nothing here enables translation yet, and no
//! device is any more confined than it was before. That comes with `Domain`,
//! built on top of this once the inventory it depends on is trustworthy.
//!
//! A machine with no DMAR table, or a unit that answers with floating-bus
//! garbage, boots on without it exactly as a missing I/O APIC does: a warning,
//! and the drivers that would otherwise move behind a domain stay exactly
//! where they are. See [`is_present`].

use alloc::vec::Vec;

use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::acpi;
use crate::memory::paging;
use crate::sync::{without_interrupts, Mutex};

/// Where remapping-unit register pages are mapped. Clear of every existing
/// device window (`0x7000_..` through `0x7600_..`) and the APIC, which sits
/// at `0x7777_..` -- inside what looks like the next free slab and is not.
const IOMMU_VIRT_BASE: u64 = 0x0000_7800_0000_0000;

const REG_VER: u64 = 0x00;
const REG_CAP: u64 = 0x08;
const REG_ECAP: u64 = 0x10;

/// One remapping unit, mapped and read.
#[derive(Debug, Clone, Copy)]
pub struct UnitInfo {
    pub register_base: u64,
    pub version: u32,
    pub capability: u64,
    pub extended_capability: u64,
}

/// Units that answered. Empty means DMA on this machine is not confined to a
/// domain by anything here.
static UNITS: Mutex<Vec<UnitInfo>> = Mutex::new(Vec::new());

/// Discover VT-d remapping hardware, map each unit's registers, and read back
/// its capabilities.
///
/// # Safety
///
/// Call once, during boot, after PCI and paging are up. `rsdp` must be the
/// address the bootloader reported.
pub unsafe fn init(rsdp: u64) {
    // SAFETY: forwarded from this function's contract.
    let dmar = match unsafe { acpi::dmar(rsdp) } {
        Ok(dmar) => dmar,
        Err(_) => {
            crate::println!("iommu: no DMAR table; DMA is not confined to a domain");
            return;
        }
    };

    if dmar.drhds.is_empty() {
        crate::println!("iommu: DMAR table describes no remapping hardware");
        return;
    }

    let mut window = IOMMU_VIRT_BASE;
    let mut units = Vec::new();
    for drhd in &dmar.drhds {
        // SAFETY: the address came from the firmware's own DMAR table, and
        // `window` points at virtual space reserved for this module and
        // advanced past on every iteration, so no two units share a page.
        match unsafe { bring_up(drhd.register_base, window) } {
            Some(info) => units.push(info),
            None => crate::println!(
                "warning: remapping unit at {:#x} did not answer; treating it as absent",
                drhd.register_base
            ),
        }
        window += 4096;
    }

    if units.is_empty() {
        crate::println!("iommu: every remapping unit failed to answer; DMA is not confined");
        return;
    }

    crate::println!(
        "iommu: {} remapping unit(s), address width {}, {} reserved memory region(s)",
        units.len(),
        dmar.address_width as u16 + 1,
        dmar.rmrrs.len(),
    );
    for info in &units {
        crate::println!(
            "  unit at {:#x}: version {}.{}, cap {:#018x}, ecap {:#018x}",
            info.register_base,
            (info.version >> 4) & 0xF,
            info.version & 0xF,
            info.capability,
            info.extended_capability,
        );
    }

    *UNITS.lock() = units;
}

/// Map one remapping unit's register page at `virtual_base` and read it back.
///
/// `None` if the mapping fails, or the unit answers with values nothing real
/// would report -- all-ones or all-zeros is what a misaddressed MMIO page
/// reads back as, the same failure `pci::both_mechanisms_agree` exists to
/// catch for ECAM.
///
/// # Safety
///
/// `register_base` must be the physical address the firmware's own DMAR table
/// gave for this unit, and `virtual_base` must name unused virtual space.
unsafe fn bring_up(register_base: u64, virtual_base: u64) -> Option<UnitInfo> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_base));
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(register_base));
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;
    // SAFETY: forwarded from this function's contract.
    unsafe { paging::map_to_frame(page, frame, flags) }.ok()?;

    // SAFETY: just mapped uncached, and every offset read is within the page.
    let (version, capability, extended_capability) = unsafe {
        (
            core::ptr::read_volatile((virtual_base + REG_VER) as *const u32),
            core::ptr::read_volatile((virtual_base + REG_CAP) as *const u64),
            core::ptr::read_volatile((virtual_base + REG_ECAP) as *const u64),
        )
    };

    if version == 0 || version == u32::MAX || capability == u64::MAX {
        return None;
    }

    Some(UnitInfo {
        register_base,
        version,
        capability,
        extended_capability,
    })
}

/// Whether at least one remapping unit answered.
pub fn is_present() -> bool {
    without_interrupts(|| !UNITS.lock().is_empty())
}

/// The remapping units found and mapped. Diagnostic, and used by tests.
pub fn units() -> Vec<UnitInfo> {
    without_interrupts(|| UNITS.lock().clone())
}
