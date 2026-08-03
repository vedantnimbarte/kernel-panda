//! A filesystem that survives a power cut.
//!
//! The ordinary cases -- create, write, read, list, remove -- are the easy half.
//! The half that matters is what a disk looks like after a crash, and that is
//! testable here without crashing anything: a commit is a single sector write,
//! so "what if the machine died before it" is the same as "what if that sector
//! still holds the previous value".

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::block::partition::{self, PartitionDevice};
use panda_kernel::block::{self, BlockDevice, SECTOR_SIZE};
use panda_kernel::fs::{format, FileSystem, FsError, NodeKind};
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

const SCRATCH_SECTORS: u64 = 16 * 1024 * 1024 / SECTOR_SIZE as u64;
const PANDA_TYPE: [u8; 16] = *b"PandaFileSystem\0";

/// The disk the tests may write to, found by size rather than by index.
///
/// The boot image is also attached, and writing a filesystem over it would
/// destroy the thing the machine booted from.
fn scratch() -> Arc<dyn BlockDevice> {
    for index in 0..block::count() {
        let disk = block::device(index).expect("device vanished");
        if disk.sector_count() == SCRATCH_SECTORS {
            return disk;
        }
    }
    panic!("no scratch disk of {SCRATCH_SECTORS} sectors; refusing to guess");
}

/// A freshly formatted filesystem in a partition of the scratch disk.
fn fresh() -> (Arc<dyn BlockDevice>, FileSystem) {
    let disk = scratch();
    let entry = partition::write_single_partition_gpt(&*disk, PANDA_TYPE)
        .expect("could not write a partition table");
    let view: Arc<dyn BlockDevice> =
        Arc::new(PartitionDevice::new(disk.clone(), &entry).expect("could not open the partition"));
    let fs = format::format(view.clone()).expect("could not format");
    (view, fs)
}

#[test_case]
fn a_fresh_filesystem_mounts_and_is_empty() {
    let (view, fs) = fresh();

    let names = fs.list("/").expect("could not list the root");
    assert!(names.is_empty(), "a fresh filesystem already has {names:?}");
    serial_println!("  ({} free blocks)", fs.free_blocks());

    // And it mounts again from what is on the disk, rather than only working
    // for the handle that formatted it.
    let remounted = FileSystem::mount(view).expect("could not remount");
    assert!(
        remounted.list("/").expect("could not list").is_empty(),
        "the remounted filesystem is not empty"
    );
}

#[test_case]
fn a_file_written_reads_back_after_remount() {
    // The point of the whole exercise: bytes that are still there next time.
    let (view, fs) = fresh();

    fs.create("/notes", NodeKind::File).expect("create failed");
    let payload = b"the state of this machine outlives the run".to_vec();
    fs.write_file("/notes", &payload).expect("write failed");

    drop(fs);
    let fs = FileSystem::mount(view).expect("could not remount");

    let read = fs.read_file("/notes").expect("read failed");
    assert_eq!(read, payload, "the file did not survive the remount");
}

#[test_case]
fn directories_nest() {
    let (_, fs) = fresh();

    fs.create("/etc", NodeKind::Directory).expect("mkdir failed");
    fs.create("/etc/panda", NodeKind::Directory).expect("mkdir failed");
    fs.create("/etc/panda/config", NodeKind::File).expect("create failed");
    fs.write_file("/etc/panda/config", b"cores=4\n").expect("write failed");

    assert_eq!(
        fs.read_file("/etc/panda/config").expect("read failed"),
        b"cores=4\n".to_vec()
    );

    let names = fs.list("/etc").expect("list failed");
    assert_eq!(names, vec![String::from("panda")]);

    let (kind, _) = fs.stat("/etc/panda").expect("stat failed");
    assert_eq!(kind, NodeKind::Directory);
}

#[test_case]
fn a_file_spanning_several_blocks_round_trips() {
    let (_, fs) = fresh();

    // Deliberately not a whole number of blocks: the last partial block is
    // where a length that is rounded up rather than kept exactly shows up.
    let mut payload = Vec::new();
    for index in 0..(SECTOR_SIZE * 5 + 137) {
        payload.push((index % 251) as u8);
    }

    fs.create("/big", NodeKind::File).expect("create failed");
    fs.write_file("/big", &payload).expect("write failed");

    let read = fs.read_file("/big").expect("read failed");
    assert_eq!(read.len(), payload.len(), "the file came back a different size");
    assert_eq!(read, payload, "a multi-block file did not round-trip");
}

#[test_case]
fn rewriting_a_file_does_not_leak_blocks() {
    let (_, fs) = fresh();

    fs.create("/churn", NodeKind::File).expect("create failed");
    fs.write_file("/churn", &vec![1u8; SECTOR_SIZE * 4]).expect("write failed");

    let after_first = fs.free_blocks();
    for _ in 0..8 {
        fs.write_file("/churn", &vec![2u8; SECTOR_SIZE * 4]).expect("write failed");
    }

    // Copy-on-write allocates new blocks and releases the old ones. If the
    // release is missing, the disk fills up under nothing but repeated writes
    // to one file -- which is the shape of bug that only shows up in production.
    assert_eq!(
        fs.free_blocks(),
        after_first,
        "eight rewrites of the same file changed the free-block count; the old \
         blocks are not being released"
    );
}

#[test_case]
fn removing_a_file_gives_its_blocks_back() {
    let (_, fs) = fresh();

    // Warm up first. A freshly formatted root has its inode in the reserved
    // area and no directory block at all; the first transaction copies it into
    // the data area and gives it one. Measuring across that migration counts
    // two permanent blocks as a leak, which is what the first version of this
    // case did.
    fs.create("/warmup", NodeKind::File).expect("create failed");
    fs.remove("/warmup").expect("remove failed");

    let before = fs.free_blocks();

    fs.create("/temp", NodeKind::File).expect("create failed");
    fs.write_file("/temp", &vec![9u8; SECTOR_SIZE * 6]).expect("write failed");
    assert!(fs.free_blocks() < before, "writing consumed no blocks");

    fs.remove("/temp").expect("remove failed");
    assert_eq!(
        fs.free_blocks(),
        before,
        "removing a file did not return every block it held"
    );
    assert_eq!(fs.read_file("/temp"), Err(FsError::NotFound));
}

#[test_case]
fn a_directory_with_entries_cannot_be_removed() {
    let (_, fs) = fresh();

    fs.create("/full", NodeKind::Directory).expect("mkdir failed");
    fs.create("/full/thing", NodeKind::File).expect("create failed");

    assert_eq!(
        fs.remove("/full"),
        Err(FsError::NotEmpty),
        "a directory with entries was removed, orphaning what was inside it"
    );

    fs.remove("/full/thing").expect("remove failed");
    fs.remove("/full").expect("the emptied directory could not be removed");
}

#[test_case]
fn bad_names_are_refused() {
    let (_, fs) = fresh();

    // A name with a separator would make one file reachable by two paths; `.`
    // and `..` would make walking the tree cyclic.
    assert_eq!(fs.create("/a/b", NodeKind::File), Err(FsError::NotFound));
    assert_eq!(fs.create("/", NodeKind::File), Err(FsError::BadName));

    let long = "x".repeat(200);
    assert!(matches!(
        fs.create(&alloc::format!("/{long}"), NodeKind::File),
        Err(FsError::BadName)
    ));

    fs.create("/once", NodeKind::File).expect("create failed");
    assert_eq!(fs.create("/once", NodeKind::File), Err(FsError::Exists));
}

#[test_case]
fn a_file_is_not_a_directory() {
    let (_, fs) = fresh();
    fs.create("/plain", NodeKind::File).expect("create failed");

    assert_eq!(fs.list("/plain"), Err(FsError::WrongType));
    assert_eq!(
        fs.create("/plain/under", NodeKind::File),
        Err(FsError::WrongType)
    );
}

// --- crash safety ------------------------------------------------------------

#[test_case]
fn an_unformatted_device_is_not_mounted() {
    let disk = scratch();
    // Wipe both superblock slots.
    disk.write(0, &vec![0u8; SECTOR_SIZE]).expect("write failed");
    disk.write(1, &vec![0u8; SECTOR_SIZE]).expect("write failed");

    assert_eq!(
        FileSystem::mount(disk).err(),
        Some(FsError::NotFormatted),
        "a disk with no superblock was mounted anyway"
    );
}

#[test_case]
fn a_crash_before_the_commit_leaves_the_previous_state() {
    // A commit is one sector write. Dying before it is the same as that sector
    // still holding what it held -- which is what this reproduces, by putting
    // the old contents back rather than by actually cutting the power.
    let (view, fs) = fresh();

    fs.create("/keep", NodeKind::File).expect("create failed");
    fs.write_file("/keep", b"committed").expect("write failed");

    // Which slot the last commit wrote, and what the *other* one holds. The
    // guarantee is one commit deep -- that is exactly what two superblocks buy,
    // and no more: once a second commit lands, the blocks of the version before
    // it are free and may be reused. Rolling back further is not a property
    // this design has, and a test that assumed otherwise was testing something
    // the filesystem never claimed.
    let live = fs.generation();
    let mut slot_a = vec![0u8; SECTOR_SIZE];
    view.read(0, &mut slot_a).expect("read failed");
    let a_generation = u64::from_le_bytes(slot_a[16..24].try_into().unwrap());
    let stale_slot = if a_generation == live { 1 } else { 0 };

    let mut stale = vec![0u8; SECTOR_SIZE];
    view.read(stale_slot, &mut stale).expect("read failed");

    // One more transaction. It writes its blocks to free space and then the
    // stale slot, which is the single sector that makes it real.
    fs.create("/lost", NodeKind::File).expect("create failed");
    drop(fs);

    // Put that sector back as it was: the power cut happened just before it
    // landed. Every block the transaction wrote is still on the disk, sitting
    // in space nothing points at.
    view.write(stale_slot, &stale).expect("write failed");
    view.flush().expect("flush failed");

    let fs = FileSystem::mount(view).expect("the filesystem did not mount after the crash");

    assert_eq!(
        fs.read_file("/keep").expect("the committed file is gone"),
        b"committed".to_vec(),
        "work committed before the crash did not survive it"
    );
    assert_eq!(
        fs.stat("/lost").err(),
        Some(FsError::NotFound),
        "work that never committed came back after the crash"
    );
}

#[test_case]
fn a_torn_superblock_loses_to_its_sibling() {
    // The final write is one sector, but a sector write is not atomic on every
    // drive -- a cut mid-sector leaves it half old and half new. The checksum
    // is what makes that survivable: a torn superblock fails it and the other
    // slot, which holds the previous commit, wins.
    let (view, fs) = fresh();
    fs.create("/before", NodeKind::File).expect("create failed");
    fs.write_file("/before", b"intact").expect("write failed");

    let generation = fs.generation();
    drop(fs);

    // Find the live slot -- the one the last commit wrote -- and corrupt it.
    let mut slot_a = vec![0u8; SECTOR_SIZE];
    view.read(0, &mut slot_a).expect("read failed");
    let a_generation = u64::from_le_bytes(slot_a[16..24].try_into().unwrap());
    let live = if a_generation == generation { 0 } else { 1 };

    let mut torn = vec![0u8; SECTOR_SIZE];
    view.read(live, &mut torn).expect("read failed");
    // Change a field without fixing the checksum, which is what a half-written
    // sector amounts to.
    torn[48] ^= 0xFF;
    view.write(live, &torn).expect("write failed");
    view.flush().expect("flush failed");

    let fs = FileSystem::mount(view).expect("a torn superblock made the disk unmountable");
    assert!(
        fs.generation() < generation,
        "the torn superblock was accepted rather than losing to its sibling"
    );
    // The older commit is a real filesystem, just an earlier one.
    fs.list("/").expect("the surviving superblock does not describe a usable tree");
}

#[test_case]
fn a_commit_advances_the_generation() {
    // The generation is what decides which superblock wins after a crash. If it
    // does not move, two slots look equally current and recovery picks by
    // accident.
    let (_, fs) = fresh();
    let first = fs.generation();

    fs.create("/one", NodeKind::File).expect("create failed");
    let second = fs.generation();
    assert!(second > first, "creating a file did not commit");

    fs.write_file("/one", b"x").expect("write failed");
    assert!(fs.generation() > second, "writing a file did not commit");
}

// --- the Ring 3 surface ------------------------------------------------------

static PROBE_RESULT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(u64::MAX);

fn file_probe_thread() {
    use panda_kernel::{sched, userspace};

    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_probe(owner, userspace::probe::FILES, 0)
        .expect("failed to load the probe");
    // SAFETY: load_probe mapped the entry user-executable, the stack
    // user-writable, and filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

#[test_case]
fn a_ring3_process_can_use_the_filesystem() {
    use panda_kernel::sched;

    // A filesystem the kernel can reach and user space cannot is half a
    // filesystem. This drives the whole surface -- create, write, read back,
    // stat, mkdir, list, remove -- from Ring 3, through validated pointers and
    // the SMAP window.
    let (_, fs) = fresh();
    panda_kernel::fs::set_root(Arc::new(fs));

    PROBE_RESULT.store(u64::MAX, core::sync::atomic::Ordering::Release);
    let thread = sched::spawn("file-probe", file_probe_thread).expect("spawn failed");

    for _ in 0..2_000_000_000u64 {
        if !sched::is_alive(thread) {
            break;
        }
        core::hint::spin_loop();
    }
    assert!(!sched::is_alive(thread), "the probe never finished");

    // What the probe left behind is the evidence: the directory it made
    // survives, and the file it removed is gone.
    let fs = panda_kernel::fs::root().expect("the filesystem was unmounted");
    let names = fs.list("/").expect("could not list the root");
    assert!(
        names.iter().any(|name| name == "ring3-dir"),
        "the directory the Ring 3 process created is not there; it has {names:?}"
    );
    assert!(
        !names.iter().any(|name| name == "ring3-probe"),
        "the file the Ring 3 process removed is still there"
    );
}

#[test_case]
fn a_bad_path_from_ring3_is_refused() {
    // Every argument here is attacker-controlled. A pointer outside the
    // caller's own mappings has to be rejected before the kernel dereferences
    // it, and a length it cannot back up has to be rejected before the kernel
    // copies it.
    use panda_kernel::syscall::Error;

    let (_, fs) = fresh();
    panda_kernel::fs::set_root(Arc::new(fs));

    // These go through the same validation the syscall entry uses. A kernel
    // address is not a user address however plausible it looks.
    assert!(!panda_kernel::userspace::validate_user_buffer(
        panda_kernel::memory::heap::HEAP_START as u64,
        16,
        false
    ));

    // And the error mapping does not leak what the disk is doing: a device
    // fault and a corrupt structure both report the same thing.
    assert_eq!(Error::from(FsError::NotFound), Error::NotFound);
    assert_eq!(Error::from(FsError::Exists), Error::AlreadyExists);
    assert_eq!(Error::from(FsError::Corrupt), Error::NoFileSystem);
    assert_eq!(
        Error::from(FsError::Device(panda_kernel::block::BlockError::DeviceFault)),
        Error::NoFileSystem
    );
}

#[test_case]
fn the_allocator_never_hands_out_metadata() {
    // A filesystem whose allocator can return the superblock or the bitmap will
    // eventually destroy itself, and the failure lands far from the cause.
    let (_, fs) = fresh();

    // Fill the disk, then check the structures are still readable.
    let mut created = 0;
    loop {
        let name = alloc::format!("/f{created}");
        if fs.create(&name, NodeKind::File).is_err() {
            break;
        }
        if fs.write_file(&name, &vec![0xABu8; SECTOR_SIZE * 8]).is_err() {
            break;
        }
        created += 1;
        if created > 400 {
            break;
        }
    }

    serial_println!("  ({created} files before the disk filled)");
    assert!(created > 0, "not a single file could be written");

    // Everything must still be there and readable: if a data block had been
    // allocated over the bitmap or an inode, this is where it shows.
    let names = fs.list("/").expect("the root became unreadable as the disk filled");
    assert_eq!(
        names.len(),
        created,
        "the root lists {} entries against the {created} created",
        names.len()
    );
    for index in 0..created {
        let name = alloc::format!("/f{index}");
        let data = fs.read_file(&name).expect("a file became unreadable");
        assert!(
            data.iter().all(|byte| *byte == 0xAB),
            "{name} came back with contents it was never given"
        );
    }
}
