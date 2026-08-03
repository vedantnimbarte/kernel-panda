//! Storage: the first thing in this kernel whose state outlives the run.
//!
//! The harness attaches a fresh 16 MiB scratch disk to QEMU's ICH9 AHCI
//! controller -- the same interface a real x86 machine exposes for SATA -- so
//! what these cases exercise is the driver a physical machine would need.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::vec;
use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::block::{self, BlockError, SECTOR_SIZE};
use panda_kernel::{arch::x86_64::halt_loop, serial_println, testing, BOOTLOADER_CONFIG};

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

/// Sectors the tests are allowed to scribble on.
///
/// Well away from sector zero, so a bug here cannot turn into a bug that
/// destroys a partition table on a real machine.
const SCRATCH_LBA: u64 = 2048;

/// The harness creates the scratch disk at exactly this size.
const SCRATCH_SECTORS: u64 = 16 * 1024 * 1024 / SECTOR_SIZE as u64;

/// The disk the tests may write to.
///
/// Emphatically not "device 0". Two disks are attached -- the boot image and
/// the scratch -- and which enumerates first is decided by the order the
/// controller reports its ports, which is not this test's business to assume.
/// The first version of this file did assume it, and every write went to the
/// boot image.
///
/// Identified by size, and the test fails rather than falling back to another
/// disk if nothing matches: writing to the wrong one destroys the image the
/// machine booted from.
fn scratch() -> alloc::sync::Arc<dyn panda_kernel::block::BlockDevice> {
    for index in 0..block::count() {
        let disk = block::device(index).expect("device vanished");
        if disk.sector_count() == SCRATCH_SECTORS {
            return disk;
        }
    }
    panic!(
        "no disk of {SCRATCH_SECTORS} sectors was found among {}; refusing to \
         write to a disk this test cannot identify",
        block::count()
    );
}

#[test_case]
fn a_disk_was_found() {
    assert!(
        block::count() > 0,
        "no block device was found; the AHCI controller was not brought up, or \
         no disk answered on any of its ports"
    );

    for index in 0..block::count() {
        let disk = block::device(index).expect("device vanished");
        assert!(
            disk.sector_count() > 0,
            "disk {index} reports no sectors, so IDENTIFY did not come back"
        );
        serial_println!(
            "  (disk {index}: {} sectors, {} MiB)",
            disk.sector_count(),
            disk.capacity() / (1024 * 1024)
        );
    }

    // Both the boot image and the scratch disk are attached, and every write in
    // this file has to land on the second one.
    assert!(
        block::count() >= 2,
        "only {} disk(s) found; the harness attaches two",
        block::count()
    );
}

#[test_case]
fn the_reported_size_matches_the_image() {
    // The harness makes a 16 MiB image. A driver that misreads IDENTIFY tends
    // to report something wildly wrong -- byte-swapped, or the 28-bit field when
    // it meant the 48-bit one -- rather than something slightly wrong.
    let disk = scratch();
    let expected = 16 * 1024 * 1024 / SECTOR_SIZE as u64;
    assert_eq!(
        disk.sector_count(),
        expected,
        "the disk reports {} sectors against the {expected} the harness created",
        disk.sector_count()
    );
}

#[test_case]
fn a_sector_written_reads_back() {
    let disk = scratch();

    let mut written = vec![0u8; SECTOR_SIZE];
    for (index, byte) in written.iter_mut().enumerate() {
        // A pattern that depends on position, so a driver transferring the
        // right number of bytes from the wrong offset fails rather than passing
        // on a buffer of identical values.
        *byte = (index as u8).wrapping_mul(7).wrapping_add(0x5A);
    }

    disk.write(SCRATCH_LBA, &written).expect("write failed");

    let mut read = vec![0u8; SECTOR_SIZE];
    disk.read(SCRATCH_LBA, &mut read).expect("read failed");

    assert_eq!(
        read, written,
        "a sector did not read back as it was written"
    );
}

#[test_case]
fn a_multi_sector_transfer_lands_in_order() {
    // Eight sectors at once, each stamped with its own number. A driver that
    // gets the scatter-gather byte count wrong -- the count field is a byte
    // count *minus one*, which is easy to miss -- transfers one sector too few
    // and the last one keeps its old contents.
    const SECTORS: usize = 8;
    let disk = scratch();

    let mut written = vec![0u8; SECTORS * SECTOR_SIZE];
    for sector in 0..SECTORS {
        for byte in 0..SECTOR_SIZE {
            written[sector * SECTOR_SIZE + byte] = (sector as u8).wrapping_add(byte as u8);
        }
    }

    disk.write(SCRATCH_LBA + 16, &written).expect("write failed");

    let mut read = vec![0u8; SECTORS * SECTOR_SIZE];
    disk.read(SCRATCH_LBA + 16, &mut read).expect("read failed");

    for sector in 0..SECTORS {
        let start = sector * SECTOR_SIZE;
        assert_eq!(
            &read[start..start + SECTOR_SIZE],
            &written[start..start + SECTOR_SIZE],
            "sector {sector} of a multi-sector transfer came back wrong"
        );
    }
}

#[test_case]
fn a_transfer_larger_than_the_bounce_buffer_still_works() {
    // The driver copies through a fixed staging buffer, so a request bigger
    // than it has to be split. The seam between chunks is where an off-by-one
    // in the loop shows up.
    const SECTORS: usize = 40;
    let disk = scratch();

    let mut written = vec![0u8; SECTORS * SECTOR_SIZE];
    for (index, byte) in written.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }

    disk.write(SCRATCH_LBA + 64, &written).expect("write failed");

    let mut read = vec![0u8; SECTORS * SECTOR_SIZE];
    disk.read(SCRATCH_LBA + 64, &mut read).expect("read failed");

    assert!(
        read == written,
        "a transfer spanning several staging-buffer chunks did not round-trip"
    );
}

#[test_case]
fn writing_does_not_disturb_the_neighbours() {
    // A transfer that runs long corrupts whatever is next to it, and nothing
    // reports it -- the write succeeds. This is the case that catches it.
    let disk = scratch();

    let guard = vec![0xC3u8; SECTOR_SIZE];
    disk.write(SCRATCH_LBA + 200, &guard).expect("write failed");
    disk.write(SCRATCH_LBA + 202, &guard).expect("write failed");

    let payload = vec![0x11u8; SECTOR_SIZE];
    disk.write(SCRATCH_LBA + 201, &payload).expect("write failed");

    let mut before = vec![0u8; SECTOR_SIZE];
    let mut after = vec![0u8; SECTOR_SIZE];
    disk.read(SCRATCH_LBA + 200, &mut before).expect("read failed");
    disk.read(SCRATCH_LBA + 202, &mut after).expect("read failed");

    assert_eq!(before, guard, "the sector before the write was modified");
    assert_eq!(after, guard, "the sector after the write was modified");
}

#[test_case]
fn a_request_past_the_end_is_refused() {
    // The controller is a DMA engine pointed at physical memory. A request it
    // cannot satisfy must be rejected here rather than handed over to find out.
    let disk = scratch();
    let mut buffer = vec![0u8; SECTOR_SIZE];

    assert_eq!(
        disk.read(disk.sector_count(), &mut buffer),
        Err(BlockError::OutOfRange),
        "a read starting past the last sector was accepted"
    );
    assert_eq!(
        disk.read(disk.sector_count() - 1, &mut vec![0u8; SECTOR_SIZE * 4]),
        Err(BlockError::OutOfRange),
        "a read running off the end was accepted"
    );
    assert_eq!(
        disk.read(u64::MAX, &mut buffer),
        Err(BlockError::OutOfRange),
        "an address that overflows when the length is added was accepted"
    );
}

#[test_case]
fn a_partial_sector_is_refused() {
    let disk = scratch();
    let mut buffer = vec![0u8; SECTOR_SIZE - 1];
    assert_eq!(
        disk.read(SCRATCH_LBA, &mut buffer),
        Err(BlockError::Unaligned),
        "a request for part of a sector was accepted"
    );
    assert_eq!(
        disk.read(SCRATCH_LBA, &mut []),
        Err(BlockError::Unaligned),
        "an empty request was accepted"
    );
}

#[test_case]
fn the_disk_accepts_a_flush() {
    // A write the drive has accepted is not a write that has survived. Anything
    // above this that claims to be crash-safe needs the barrier to work.
    let disk = scratch();
    let payload = vec![0x77u8; SECTOR_SIZE];
    disk.write(SCRATCH_LBA + 300, &payload).expect("write failed");
    disk.flush().expect("the disk refused to flush its cache");
}
