//! A panic stops the other processors and leaves a record the next boot finds.
//!
//! Drives itself rather than using `#[test_case]`: the thing under test is the
//! panic handler, and a case cannot survive reaching it.
//!
//! Two boots of the same kernel. The first finds no record, panics, and asks
//! the harness to boot it again on the same crash disk; the second must find
//! what the first left, with the backtrace named.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::arch::x86_64::qemu::{self, ExitCode};
use panda_kernel::{crash, sched, serial_print, serial_println, smp, testing, BOOTLOADER_CONFIG};

entry_point!(test_kernel_main, config = &BOOTLOADER_CONFIG);

const MESSAGE: &str = "a deliberate panic, for the crash test";

/// Set just before the deliberate panic, so a failed setup step is reported as
/// itself rather than as a crash record that says the wrong thing.
static DELIBERATE: AtomicBool = AtomicBool::new(false);

static SPINS: AtomicU64 = AtomicU64::new(0);
static SPINNER_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);

fn test_kernel_main(boot_info: &'static mut BootInfo) -> ! {
    panda_kernel::init(boot_info);

    match crash::previous() {
        None => first_boot(),
        Some(record) => second_boot(record),
    }
}

fn first_boot() -> ! {
    serial_print!("crash::a_panic_is_recorded ... ");

    // Something running elsewhere, for the panic to stop.
    sched::spawn("spinner", spin).expect("spawn failed");
    while SPINS.load(Ordering::Relaxed) < 1000 {
        core::hint::spin_loop();
    }

    DELIBERATE.store(true, Ordering::Relaxed);
    nested_call();
}

fn second_boot(record: &str) -> ! {
    serial_print!("crash::the_next_boot_finds_it ... ");

    if !record.contains(MESSAGE) {
        fail("the record does not carry the panic message");
    }
    if !record.contains("thread '") {
        fail("the record does not say which thread panicked");
    }
    let frames = || record.lines().filter(|line| line.starts_with("  0x"));
    if frames().count() < 2 {
        fail("the backtrace has fewer than two frames");
    }
    if !frames().any(|line| line.contains(" crash::nested_call+0x")) {
        fail("no frame of the backtrace is named for the function that panicked");
    }
    if crash::take_previous().is_some() {
        fail("the record was not cleared; every boot would report it again");
    }

    serial_println!("[ok]");
    qemu::exit(ExitCode::Success)
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

    serial_println!("[ok]");
    qemu::exit(ExitCode::Reboot)
}

fn fail(why: &str) -> ! {
    serial_println!("[FAILED]");
    serial_println!("{why}");
    qemu::exit(ExitCode::Failed)
}
