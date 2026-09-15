//! VT-d: the remapping hardware inventory.
//!
//! Translation is not enabled yet -- these only check that the firmware's
//! DMAR table parses correctly (including the one structure QEMU never emits,
//! an RMRR, which is why it is tested against bytes built by hand) and that
//! whatever hardware answered did so plausibly rather than as a misaddressed
//! page reading back all-ones.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use core::panic::PanicInfo;

use alloc::vec;
use bootloader_api::{entry_point, BootInfo};
use panda_kernel::{acpi, arch::x86_64::halt_loop, iommu, testing, BOOTLOADER_CONFIG};

entry_point!(test_kernel_main, config = &BOOTLOADER_CONFIG);

fn test_kernel_main(boot_info: &'static mut BootInfo) -> ! {
    panda_kernel::init(boot_info);
    test_main();
    halt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    testing::panic_handler(info)
}

#[test_case]
fn the_firmware_describes_a_remapping_unit() {
    if !iommu::is_present() {
        panda_kernel::serial_println!("  (skipped: no VT-d on this machine)");
        return;
    }
    let units = iommu::units();
    assert!(!units.is_empty(), "is_present() said yes but units() is empty");
    for unit in &units {
        assert_ne!(unit.register_base, 0, "a remapping unit with no register base");
    }
}

#[test_case]
fn the_remapping_unit_answers_rather_than_floating() {
    // All-ones or all-zeros is what a misaddressed MMIO page reads back as,
    // not anything a real unit reports -- the same failure
    // `pci::both_mechanisms_agree` exists to catch for ECAM. `iommu::init`
    // already filters this before a unit reaches `units()`, so this asserts
    // the property held, not merely that nothing crashed.
    let units = iommu::units();
    if units.is_empty() {
        panda_kernel::serial_println!("  (skipped: no VT-d on this machine)");
        return;
    }
    for unit in &units {
        assert_ne!(unit.version, 0, "a unit reporting version 0");
        assert_ne!(unit.version, u32::MAX, "a unit reporting an all-ones version");
        assert_ne!(unit.capability, u64::MAX, "a unit reporting all-ones capabilities");
    }
}

/// Bytes for a DMAR table body: the 36-byte SDT header (content irrelevant --
/// `parse_dmar` trusts the caller the way `find_table` trusts its checksum),
/// then width, flags and 10 reserved bytes, then whatever structures are
/// appended.
fn synthetic_header(address_width: u8) -> alloc::vec::Vec<u8> {
    let mut table = vec![0u8; 36 + 12];
    table[36] = address_width;
    table
}

#[test_case]
fn a_synthetic_dmar_with_an_rmrr_parses() {
    // QEMU emits no RMRR structures, so this is the only coverage that parsing
    // path will ever have.
    let mut table = synthetic_header(47); // reported width 47 -> actual 48

    // One DRHD: type 0, length 16, INCLUDE_PCI_ALL set, register base as QEMU
    // itself places it.
    let mut drhd = vec![0u8; 16];
    drhd[2..4].copy_from_slice(&16u16.to_le_bytes());
    drhd[4] = 1; // flags: INCLUDE_PCI_ALL
    drhd[8..16].copy_from_slice(&0xFED9_0000u64.to_le_bytes());
    table.extend_from_slice(&drhd);

    // One RMRR: type 1, length 24, a small reserved range.
    let mut rmrr = vec![0u8; 24];
    rmrr[0..2].copy_from_slice(&1u16.to_le_bytes());
    rmrr[2..4].copy_from_slice(&24u16.to_le_bytes());
    rmrr[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    rmrr[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
    table.extend_from_slice(&rmrr);

    let dmar = acpi::parse_dmar(&table);

    assert_eq!(dmar.address_width, 47);
    assert_eq!(dmar.drhds.len(), 1, "the DRHD was not parsed");
    assert_eq!(dmar.drhds[0].register_base, 0xFED9_0000);
    assert!(dmar.drhds[0].include_all, "INCLUDE_PCI_ALL was not read");
    assert_eq!(dmar.rmrrs.len(), 1, "the RMRR was not parsed");
    assert_eq!(dmar.rmrrs[0].base, 0x1000);
    assert_eq!(dmar.rmrrs[0].limit, 0x1FFF);
}

#[test_case]
fn a_dmar_structure_of_zero_length_does_not_loop_forever() {
    let mut table = synthetic_header(47);
    // A structure claiming length 0 must not be walked: it would never
    // advance the offset, and the loop would spin until the test timed out
    // rather than returning. The call completing at all is most of the proof.
    table.extend_from_slice(&[0u8, 0, 0, 0]);

    let dmar = acpi::parse_dmar(&table);
    assert!(dmar.drhds.is_empty());
    assert!(dmar.rmrrs.is_empty());
}

#[test_case]
fn a_dmar_structure_running_past_the_table_is_rejected() {
    let mut table = synthetic_header(47);
    // Claims a DRHD of length 16 but only 8 bytes actually follow.
    let mut short = vec![0u8; 8];
    short[2..4].copy_from_slice(&16u16.to_le_bytes());
    table.extend_from_slice(&short);

    let dmar = acpi::parse_dmar(&table);
    assert!(dmar.drhds.is_empty(), "a structure overrunning the table was accepted");
}
