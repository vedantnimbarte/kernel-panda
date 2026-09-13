//! Logging in: the one way a running thread changes user, and it takes the
//! account's password.
//!
//! Its own kernel because each password check is thousands of hash rounds, which
//! in a debug build is seconds.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::block::partition::{self, PartitionDevice};
use panda_kernel::block::{self, BlockDevice, SECTOR_SIZE};
use panda_kernel::fs::{format, FileSystem, FsError};
use panda_kernel::ipc::{self, Rights};
use panda_kernel::sched::{self, ThreadId};
use panda_kernel::users::{self, AccountError, ACCOUNTS, SYSTEM};
use panda_kernel::{arch::x86_64::halt_loop, serial_println, sha256, sync, syscall, testing, time, userspace, BOOTLOADER_CONFIG};

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
// Logging in
// ---------------------------------------------------------------------------

const PASSWORD: &str = "correct horse battery staple";

fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|byte| alloc::format!("{byte:02x}")).collect()
}

#[test_case]
fn the_hash_matches_the_published_vectors() {
    assert_eq!(hex(&sha256::sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex(&sha256::sha256(&[b'a'; 1000])),
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
    );
    assert_eq!(
        hex(&sha256::pbkdf2(b"password", b"salt", 1)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    let start = time::uptime_ms();
    assert_eq!(
        hex(&sha256::pbkdf2(b"password", b"salt", 4096)),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
    serial_println!("  (4096 rounds in {} ms)", time::uptime_ms() - start);
}

/// A fresh filesystem as the root, holding an account for alice.
fn with_alice() -> Arc<FileSystem> {
    let fs = Arc::new(fresh());
    panda_kernel::fs::set_root(fs.clone());
    users::add_account("alice", ALICE, PASSWORD).expect("could not add alice");
    fs
}

#[test_case]
fn an_account_logs_in_with_its_password_and_nothing_else() {
    let fs = with_alice();

    assert_eq!(users::add_account("alice", BOB, "x"), Err(AccountError::Exists));
    assert_eq!(users::add_account("bob", ALICE, "x"), Err(AccountError::Exists));
    assert_eq!(users::add_account("accounts", ACCOUNTS, "x"), Err(AccountError::Exists));
    assert_eq!(users::add_account("bob:1", BOB, "x"), Err(AccountError::BadName));
    assert_eq!(users::add_account("bob", BOB, ""), Err(AccountError::BadPassword));
    users::add_account("bob", BOB, "hunter2").expect("could not add bob");

    let thread = me();
    assert_eq!(users::login(thread, "alice", "hunter2"), Err(AccountError::Incorrect));
    assert_eq!(users::login(thread, "nobody", PASSWORD), Err(AccountError::Incorrect));
    assert_eq!(users::of(thread), SYSTEM, "a refused login changed the user");

    assert_eq!(users::login(thread, "alice", PASSWORD), Ok(ALICE));
    assert_eq!(users::of(thread), ALICE);
    assert_eq!(users::login(thread, "bob", "hunter2"), Ok(BOB));
    users::assign(thread, SYSTEM);

    // The database holds no password, and no user can read it or open it up --
    // the system's included.
    let database = fs.read_file(users::DATABASE).expect("no database");
    assert!(!database.windows(PASSWORD.len()).any(|w| w == PASSWORD.as_bytes()));

    // The same password twice is two different hashes: the salts differ.
    users::add_account("carol", 1002, "hunter2").expect("could not add carol");
    let database = fs.read_file(users::DATABASE).expect("no database");
    let text = core::str::from_utf8(&database).expect("not text");
    let hash_of = |name: &str| text.lines().find(|line| line.starts_with(name)).and_then(|line| line.rsplit(':').next());
    assert_ne!(hash_of("bob:"), hash_of("carol:"), "two accounts with one password share a hash");
    assert_eq!(fs.owner_as(users::DATABASE, None), Ok((ACCOUNTS, 0)));
    assert_eq!(fs.read_file_as(users::DATABASE, Some(SYSTEM)), Err(FsError::Denied));
    assert_eq!(fs.set_mode_as(users::DATABASE, 0b1111, Some(SYSTEM)), Err(FsError::Denied));
}

#[test_case]
fn a_process_logs_in_through_the_system_call() {
    with_alice();
    let endpoint = ipc::create(me(), 4).expect("create failed");
    spawn_probe_as(BOB, userspace::probe::LOGIN, endpoint);
    assert!(spin_until(|| ipc::queued(endpoint) > 0), "the probe never reported");
    let report = ipc::receive(me(), endpoint).expect("receive failed");

    let denied = syscall::Error::PermissionDenied as i64 as u64;
    assert_eq!(report.words[0], denied, "a wrong password was accepted");
    assert_eq!(report.words[1], BOB as u64, "a refused login changed the user");
    assert_eq!(report.words[2], ALICE as u64, "the right password was refused");
    assert_eq!(report.words[3] >> 32, ALICE as u64, "the process is not alice after logging in");
    assert_eq!(report.words[3] as u32, denied as u32, "a logged-in user read the account database");
}
