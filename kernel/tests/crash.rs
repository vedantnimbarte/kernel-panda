//! A panic stops the other processors and leaves a record the next boot finds.
//!
//! Drives itself rather than using `#[test_case]`: the thing under test is the
//! panic handler, and a case cannot survive reaching it.
//!
//! "The next boot" is the same boot reading the partition back through the
//! ordinary block path. The harness hands every launch a fresh disk, so a real
//! reboot would find nothing; what this proves is that the bytes reached the
//! device, in a form `take_previous` accepts.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::arch::x86_64::qemu::{self, ExitCode};
use panda_kernel::block::{self, partition, SECTOR_SIZE};
use panda_kernel::{crash, sched, serial_print, serial_println, smp, testing, BOOTLOADER_CONFIG};

entry_point!(test_kernel_main, config = &BOOTLOADER_CONFIG);

const MESSAGE: &str = "a deliberate panic, for the crash test";

/// The harness creates the scratch disk at exactly this size.
const SCRATCH_SECTORS: u64 = 16 * 1024 * 1024 / SECTOR_SIZE as u64;

/// Set just before the deliberate panic, so a failed setup step is reported as
/// itself rather than as a crash record that says the wrong thing.
static DELIBERATE: AtomicBool = AtomicBool::new(false);

static SPINS: AtomicU64 = AtomicU64::new(0);
static SPINNER_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);

fn test_kernel_main(boot_info: &'static mut BootInfo) -> ! {
    panda_kernel::init(boot_info);
    serial_print!("crash::a_panic_is_recorded_and_found ... ");

    // The scratch disk, by size: the boot image is attached too, and writing a
    // partition table over that one destroys it.
    let disk = (0..block::count())
        .filter_map(block::device)
        .find(|disk| disk.sector_count() == SCRATCH_SECTORS)
        .expect("no scratch disk");
    partition::write_single_partition_gpt(&*disk, crash::PARTITION_TYPE)
        .expect("could not write a GPT");
    crash::init();
    assert!(crash::take_previous().is_none(), "a blank partition held a record");

    // Something running elsewhere, for the panic to stop.
    sched::spawn("spinner", spin).expect("spawn failed");
    while SPINS.load(Ordering::Relaxed) < 1000 {
        core::hint::spin_loop();
    }

    DELIBERATE.store(true, Ordering::Relaxed);
    nested_call();
}

fn spin() {
    loop {
        SPINNER_CPU.store(smp::cpu_index(), Ordering::Relaxed);
        SPINS.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// A frame or two of depth, so the backtrace has something to walk.
#[inline(never)]
fn nested_call() -> ! {
    panic!("{MESSAGE}");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if !DELIBERATE.load(Ordering::Relaxed) {
        testing::panic_handler(info);
    }

    if !crash::report(info) {
        fail("the report was not written");
    }

    // If the spinner was on another processor, the NMI must have stopped it.
    if SPINNER_CPU.load(Ordering::Relaxed) != smp::cpu_index() {
        let before = SPINS.load(Ordering::Relaxed);
        for _ in 0..50_000_000u64 {
            core::hint::spin_loop();
        }
        if SPINS.load(Ordering::Relaxed) != before {
            fail("another processor kept running after the panic");
        }
    }

    let Some(record) = crash::take_previous() else {
        fail("no record was found after the panic");
    };
    if !record.contains(MESSAGE) {
        fail("the record does not carry the panic message");
    }
    if !record.contains("thread '") {
        fail("the record does not say which thread panicked");
    }
    if record.lines().filter(|line| line.starts_with("  0x")).count() < 2 {
        fail("the backtrace has fewer than two frames");
    }
    if crash::take_previous().is_some() {
        fail("the record was not cleared; every boot would report it again");
    }

    serial_println!("[ok]");
    qemu::exit(ExitCode::Success)
}

fn fail(why: &str) -> ! {
    serial_println!("[FAILED]");
    serial_println!("{why}");
    qemu::exit(ExitCode::Failed)
}
