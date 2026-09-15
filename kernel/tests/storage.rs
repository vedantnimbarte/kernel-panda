//! The NVMe and virtio-blk drivers, through the same block interface as SATA.
//!
//! The harness attaches a blank 32 MiB NVMe disk and a blank 24 MiB virtio-blk
//! disk. Each case runs against both, found by size -- enumeration order is not
//! this file's business, and the boot image is on SATA where a stray write
//! would destroy it.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::block::partition::{self, PartitionDevice};
use panda_kernel::block::{self, BlockDevice, BlockError, SECTOR_SIZE};
use panda_kernel::fs::{format, FileSystem, NodeKind};
use panda_kernel::{arch::x86_64::halt_loop, sched, serial_println, testing, BOOTLOADER_CONFIG};

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

const NVME_SECTORS: u64 = 32 * 1024 * 1024 / SECTOR_SIZE as u64;
const VIRTIO_SECTORS: u64 = 24 * 1024 * 1024 / SECTOR_SIZE as u64;

/// Both disks, named for messages.
fn disks() -> [(&'static str, Arc<dyn BlockDevice>); 2] {
    let find = |sectors: u64, name: &str| {
        (0..block::count())
            .filter_map(block::device)
            .find(|disk| disk.sector_count() == sectors)
            .unwrap_or_else(|| panic!("no {name} disk of {sectors} sectors was found"))
    };
    [("NVMe", find(NVME_SECTORS, "NVMe")), ("virtio-blk", find(VIRTIO_SECTORS, "virtio-blk"))]
}

#[test_case]
fn both_disks_were_found() {
    for (name, disk) in disks() {
        serial_println!("  ({name}: {} sectors)", disk.sector_count());
    }
}

#[test_case]
fn sectors_written_read_back_across_many_transfers() {
    // Forty sectors is 20 KiB, more than one bounce buffer holds, so this spans
    // several commands -- and every sector is different, so one landing in the
    // wrong place shows.
    const SECTORS: usize = 40;
    const LBA: u64 = 1000;

    for (name, disk) in disks() {
        let mut written = vec![0u8; SECTORS * SECTOR_SIZE];
        for (index, byte) in written.iter_mut().enumerate() {
            *byte = ((index / SECTOR_SIZE) as u8).wrapping_mul(7) ^ (index as u8);
        }
        disk.write(LBA, &written).unwrap_or_else(|e| panic!("{name}: write failed: {e:?}"));
        disk.flush().unwrap_or_else(|e| panic!("{name}: flush failed: {e:?}"));

        let mut read = vec![0u8; SECTORS * SECTOR_SIZE];
        disk.read(LBA, &mut read).unwrap_or_else(|e| panic!("{name}: read failed: {e:?}"));
        if let Some(sector) = (0..SECTORS)
            .find(|s| read[s * SECTOR_SIZE..(s + 1) * SECTOR_SIZE] != written[s * SECTOR_SIZE..(s + 1) * SECTOR_SIZE])
        {
            panic!("{name}: sector {} came back different", LBA + sector as u64);
        }
    }
}

#[test_case]
fn the_last_sector_is_reachable_and_the_one_after_is_not() {
    for (name, disk) in disks() {
        let last = disk.sector_count() - 1;
        let sector = [0x5Au8; SECTOR_SIZE];
        disk.write(last, &sector).unwrap_or_else(|e| panic!("{name}: the last sector refused: {e:?}"));
        let mut back = [0u8; SECTOR_SIZE];
        disk.read(last, &mut back).expect("read failed");
        assert_eq!(back, sector, "{name}: the last sector read back wrong");

        assert_eq!(
            disk.read(last + 1, &mut back),
            Err(BlockError::OutOfRange),
            "{name}: a read past the end was not refused"
        );
        assert_eq!(
            disk.write(0, &[0u8; 100]),
            Err(BlockError::Unaligned),
            "{name}: a partial sector was not refused"
        );
    }
}

#[test_case]
fn the_panic_path_write_works_on_both() {
    for (name, disk) in disks() {
        let sector = [0xC3u8; SECTOR_SIZE];
        disk.write_now(2000, &sector).unwrap_or_else(|e| panic!("{name}: write_now failed: {e:?}"));
        let mut back = [0u8; SECTOR_SIZE];
        disk.read(2000, &mut back).expect("read failed");
        assert_eq!(back, sector, "{name}: write_now did not land");
    }
}

#[test_case]
fn a_filesystem_lives_on_both() {
    const TYPE: [u8; 16] = *b"PandaFilesystem!";
    const CONTENTS: &[u8] = b"persisted through a non-SATA driver";

    for (name, disk) in disks() {
        let entry = partition::write_single_partition_gpt(&*disk, TYPE)
            .unwrap_or_else(|e| panic!("{name}: no partition table: {e:?}"));
        let view: Arc<dyn BlockDevice> =
            Arc::new(PartitionDevice::new(disk.clone(), &entry).expect("could not open the partition"));

        let fs = format::format(view.clone()).unwrap_or_else(|e| panic!("{name}: format failed: {e:?}"));
        fs.create("/note", NodeKind::File).expect("create failed");
        fs.write_file("/note", CONTENTS).expect("write failed");
        drop(fs);

        // Mounted again from what is on the disk, not from anything in memory.
        let fs = FileSystem::mount(view).unwrap_or_else(|e| panic!("{name}: remount failed: {e:?}"));
        assert_eq!(
            fs.read_file("/note").expect("read failed"),
            CONTENTS,
            "{name}: the file did not survive a remount"
        );
    }
}

// ---------------------------------------------------------------------------
// Many requests at once
// ---------------------------------------------------------------------------

const WORKERS: usize = 4;
const ROUNDS: u64 = 24;
const WORKER_SECTORS: usize = 12;

static TARGET: AtomicUsize = AtomicUsize::new(0);
static FINISHED: AtomicUsize = AtomicUsize::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
static NEXT_WORKER: AtomicU64 = AtomicU64::new(0);

/// Write a pattern of its own to a range of its own, read it back, over and
/// over, alongside the others.
fn worker() {
    let disk = disks()[TARGET.load(Ordering::Acquire)].1.clone();
    let me = NEXT_WORKER.fetch_add(1, Ordering::AcqRel);
    let lba = 4000 + me * 100;
    let mut written = vec![0u8; WORKER_SECTORS * SECTOR_SIZE];
    let mut read = vec![0u8; WORKER_SECTORS * SECTOR_SIZE];
    for round in 0..ROUNDS {
        for (index, byte) in written.iter_mut().enumerate() {
            *byte = (index as u8) ^ (me as u8).wrapping_mul(31) ^ (round as u8).wrapping_mul(17);
        }
        let ok = disk.write(lba, &written).is_ok() && disk.read(lba, &mut read).is_ok() && read == written;
        if !ok {
            FAILURES.fetch_add(1, Ordering::AcqRel);
        }
    }
    FINISHED.fetch_add(1, Ordering::AcqRel);
}

#[test_case]
fn requests_overlap_and_are_answered_by_interrupt() {
    for (index, (name, disk)) in disks().into_iter().enumerate() {
        TARGET.store(index, Ordering::Release);
        FINISHED.store(0, Ordering::Release);
        FAILURES.store(0, Ordering::Release);
        let before = disk.stats();

        for _ in 0..WORKERS {
            sched::spawn("disk-worker", worker).expect("spawn failed");
        }
        while FINISHED.load(Ordering::Acquire) < WORKERS {
            sched::yield_now();
        }

        let stats = disk.stats();
        serial_println!("  ({name}: {stats:?})");
        assert_eq!(FAILURES.load(Ordering::Acquire), 0, "{name}: a request came back wrong alongside others");
        assert!(stats.peak_in_flight >= 2, "{name}: requests never overlapped");
        assert!(
            stats.interrupt_completions > before.interrupt_completions,
            "{name}: no request was answered by interrupt"
        );
    }
}
