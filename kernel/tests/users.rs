//! Users: who a process is, and what its files let others do.
//!
//! Identity is assigned by whoever spawns a thread and inherited from there;
//! messages carry the sender's user as the kernel saw it; and files record an
//! owner and permission bits that every file system call checks -- for the
//! system's own user too, since there is no superuser.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::block::partition::{self, PartitionDevice};
use panda_kernel::block::{self, BlockDevice, SECTOR_SIZE};
use panda_kernel::fs::{self, format, FileSystem, FsError, NodeKind};
use panda_kernel::ipc::{self, Rights};
use panda_kernel::sched::{self, ThreadId};
use panda_kernel::users::{self, SYSTEM};
use panda_kernel::{arch::x86_64::halt_loop, sync, syscall, testing, userspace, BOOTLOADER_CONFIG};

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

const ALICE: u32 = 1000;
const BOB: u32 = 1001;

fn me() -> ThreadId {
    sched::current_id().expect("no thread")
}

fn spin_until(condition: impl Fn() -> bool) -> bool {
    (0..2_000_000_000u64).any(|_| {
        let done = condition();
        core::hint::spin_loop();
        done
    })
}

/// A fresh filesystem on the 16 MiB scratch disk.
fn fresh() -> FileSystem {
    let disk = (0..block::count())
        .filter_map(block::device)
        .find(|disk| disk.sector_count() == 16 * 1024 * 1024 / SECTOR_SIZE as u64)
        .expect("no scratch disk");
    let entry = partition::write_single_partition_gpt(&*disk, *b"PandaFilesystem!").expect("no GPT");
    let view: Arc<dyn BlockDevice> = Arc::new(PartitionDevice::new(disk, &entry).expect("no partition"));
    format::format(view).expect("could not format")
}

static PROBE: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

fn probe_thread() {
    let [mode, argument] = [0, 1].map(|index| PROBE[index].load(Ordering::Acquire));
    let owner = me();
    let image = userspace::load_probe(owner, mode, argument).expect("failed to load the probe");
    // SAFETY: load_probe mapped the entry executable, the stack writable, and
    // filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

/// A probe running as `user`, holding `SEND` on `endpoint`.
fn spawn_probe_as(user: u32, mode: u64, endpoint: ipc::EndpointId) -> ThreadId {
    PROBE[0].store(mode, Ordering::Release);
    PROBE[1].store(endpoint.0, Ordering::Release);
    let id = sync::without_interrupts(|| {
        let id = sched::spawn_as("user-probe", probe_thread, user).expect("spawn failed");
        ipc::grant(me(), id, endpoint, Rights::SEND).expect("grant failed");
        id
    });
    assert!(spin_until(|| !sched::is_alive(id) || userspace::slot_of(id).is_some()));
    id
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

static PARENT_READY: AtomicBool = AtomicBool::new(false);
static CHILD_USER: AtomicU64 = AtomicU64::new(u64::MAX);

fn record_user() {
    CHILD_USER.store(users::of(me()) as u64, Ordering::Release);
}

fn spawn_a_child() {
    while !PARENT_READY.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    sched::spawn("child", record_user).expect("spawn failed");
}

#[test_case]
fn a_thread_is_its_spawners_user() {
    assert_eq!(users::of(me()), SYSTEM, "the boot thread is not the system's");

    let parent = sched::spawn("parent", spawn_a_child).expect("spawn failed");
    users::assign(parent, ALICE);
    PARENT_READY.store(true, Ordering::Release);

    assert!(spin_until(|| CHILD_USER.load(Ordering::Acquire) != u64::MAX), "the child never ran");
    assert_eq!(
        CHILD_USER.load(Ordering::Acquire),
        ALICE as u64,
        "a thread spawned by alice did not run as alice"
    );
}

#[test_case]
fn a_process_learns_its_user_and_messages_carry_it() {
    let endpoint = ipc::create(me(), 4).expect("create failed");

    spawn_probe_as(BOB, userspace::probe::WHOAMI, endpoint);
    assert!(spin_until(|| ipc::queued(endpoint) > 0), "the probe never reported");
    let report = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(report.words[0], BOB as u64, "the probe does not know it is bob");
    assert_eq!(report.sender_user, BOB as u64, "the message does not say it came from bob");

    // A sender that writes someone else's user into its message is overwritten.
    let liar = spawn_probe_as(ALICE, userspace::probe::IPC, endpoint);
    assert!(spin_until(|| ipc::queued(endpoint) > 0), "the probe never sent");
    let message = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(message.sender, liar.0 as u64);
    assert_eq!(message.sender_user, ALICE as u64, "a forged sender user was believed");

    // And the kernel's own messages carry no user at all.
    ipc::notify(endpoint, ipc::Message::default()).expect("notify failed");
    let notification = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(notification.sender_user, ipc::KERNEL_SENDER);
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

#[test_case]
fn owners_and_bits_decide_who_reads_and_writes() {
    let fs = fresh();
    let (alice, bob) = (Some(ALICE), Some(BOB));

    // The root is the system's: readable by all, writable by the system alone.
    assert_eq!(fs.create_as("/stray", NodeKind::File, alice), Err(FsError::Denied));

    // The system makes a directory anyone may write in.
    fs.create_as("/shared", NodeKind::Directory, Some(SYSTEM)).expect("mkdir failed");
    fs.set_mode_as("/shared", 0b1111, Some(SYSTEM)).expect("chmod failed");

    fs.create_as("/shared/diary", NodeKind::File, alice).expect("alice could not create");
    fs.write_file_as("/shared/diary", b"dear diary", alice).expect("alice could not write");
    assert_eq!(fs.owner_as("/shared/diary", bob), Ok((ALICE, fs::DEFAULT_MODE)));

    // Others may read by default, but not write.
    assert_eq!(fs.read_file_as("/shared/diary", bob).as_deref(), Ok(&b"dear diary"[..]));
    assert_eq!(fs.write_file_as("/shared/diary", b"graffiti", bob), Err(FsError::Denied));

    // Only the owner changes the bits, and once private it is private -- to
    // the system too.
    assert_eq!(fs.set_mode_as("/shared/diary", 0b1111, bob), Err(FsError::Denied));
    fs.set_mode_as("/shared/diary", fs::OWNER_READ | fs::OWNER_WRITE, alice).expect("chmod failed");
    assert_eq!(fs.read_file_as("/shared/diary", bob), Err(FsError::Denied));
    assert_eq!(
        fs.read_file_as("/shared/diary", Some(SYSTEM)),
        Err(FsError::Denied),
        "the system read a private file; there is no superuser"
    );
    assert_eq!(fs.read_file_as("/shared/diary", alice).as_deref(), Ok(&b"dear diary"[..]));

    // The kernel acting on its own account is not a user and is not checked.
    assert!(fs.read_file("/shared/diary").is_ok());
}

#[test_case]
fn a_private_directory_hides_what_is_in_it() {
    let fs = fresh();
    fs.create_as("/shared", NodeKind::Directory, Some(SYSTEM)).expect("mkdir failed");
    fs.set_mode_as("/shared", 0b1111, Some(SYSTEM)).expect("chmod failed");

    fs.create_as("/shared/alice", NodeKind::Directory, Some(ALICE)).expect("mkdir failed");
    fs.create_as("/shared/alice/notes", NodeKind::File, Some(ALICE)).expect("create failed");
    fs.set_mode_as("/shared/alice", fs::OWNER_READ | fs::OWNER_WRITE, Some(ALICE)).expect("chmod failed");

    // The file is readable by others on its own bits, but the path to it is not.
    assert_eq!(fs.stat_as("/shared/alice/notes", Some(BOB)), Err(FsError::Denied));
    assert_eq!(fs.list_as("/shared/alice", Some(BOB)), Err(FsError::Denied));
    assert!(fs.stat_as("/shared/alice/notes", Some(ALICE)).is_ok());
}

#[test_case]
fn the_file_system_calls_enforce_it_from_ring_3() {
    let fs = Arc::new(fresh());
    fs.create_as("/shared", NodeKind::Directory, Some(SYSTEM)).expect("mkdir failed");
    fs.set_mode_as("/shared", 0b1111, Some(SYSTEM)).expect("chmod failed");
    panda_kernel::fs::set_root(fs.clone());

    let endpoint = ipc::create(me(), 4).expect("create failed");
    spawn_probe_as(ALICE, userspace::probe::PERMISSIONS, endpoint);
    assert!(spin_until(|| ipc::queued(endpoint) > 0), "the probe never reported");
    let report = ipc::receive(me(), endpoint).expect("receive failed");

    let denied = syscall::Error::PermissionDenied as i64 as u64;
    assert_eq!(report.words[0], denied, "alice created a file in the system's root");
    assert_eq!(report.words[1] as u32, 0, "alice could not create in /shared");
    assert_eq!(report.words[1] >> 32, 0, "alice could not change her own file's bits");
    assert_eq!(report.words[2], (ALICE as u64) << 16 | 0b0011, "the file's owner or bits are wrong");
    assert_eq!(report.words[3], denied, "alice changed the bits of a directory she does not own");

    assert_eq!(fs.read_file_as("/shared/mine", Some(BOB)), Err(FsError::Denied));
}
