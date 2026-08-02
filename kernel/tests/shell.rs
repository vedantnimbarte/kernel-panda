//! The Ring 3 shell daemon.
//!
//! Drives the shell by injecting bytes as though they had arrived on the serial
//! line, then checks it reacted. That covers the whole path: timer-driven input
//! buffering, a blocking `read` that parks the thread, dispatch inside Ring 3,
//! and `write` back out.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::console::input;
use panda_kernel::sched::ThreadId;
use panda_kernel::{arch::x86_64::halt_loop, sched, syscall, testing, userspace, BOOTLOADER_CONFIG};

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

const SPIN_BUDGET: u64 = 2_000_000_000;

fn spin_until(condition: impl Fn() -> bool) -> bool {
    for _ in 0..SPIN_BUDGET {
        if condition() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

static SHELL_ID: AtomicUsize = AtomicUsize::new(usize::MAX);

fn shell_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_program(owner, userspace::shell_program())
        .expect("failed to map the shell image");
    // SAFETY: load_program mapped the entry user-executable and the stack
    // user-writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, 0) }
}

fn type_line(text: &str) {
    for byte in text.bytes() {
        input::inject(byte);
    }
    input::inject(b'\n');
}

#[test_case]
fn a_blocked_reader_is_woken_by_input() {
    let reader = sched::spawn("reader", shell_thread).expect("spawn failed");
    SHELL_ID.store(reader.0, Ordering::Release);

    // The shell prints a banner and a prompt, then blocks in `read`. That it
    // parks rather than spins is the point -- a busy-waiting shell would peg the
    // CPU for the rest of the run.
    assert!(
        spin_until(|| sched::is_blocked(ThreadId(SHELL_ID.load(Ordering::Acquire)))),
        "the shell never parked in read; it is busy-waiting on the console"
    );
}

#[test_case]
fn the_shell_answers_a_command() {
    let before = syscall::user_bytes_written();
    type_line("help");

    assert!(
        spin_until(|| syscall::user_bytes_written() > before + 20),
        "the shell produced no output for 'help'"
    );
}

#[test_case]
fn an_unknown_command_is_reported() {
    let before = syscall::user_bytes_written();
    type_line("nonsense");

    assert!(
        spin_until(|| syscall::user_bytes_written() > before + 10),
        "the shell said nothing about an unknown command"
    );
}

#[test_case]
fn every_command_produces_output() {
    for command in ["version", "hello"] {
        let before = syscall::user_bytes_written();
        type_line(command);
        assert!(
            spin_until(|| syscall::user_bytes_written() > before + 10),
            "the shell produced no output for '{command}'"
        );
    }
}

#[test_case]
fn the_shell_exits_on_command() {
    let shell = ThreadId(SHELL_ID.load(Ordering::Acquire));
    type_line("exit");

    assert!(
        spin_until(|| !sched::is_alive(shell)),
        "the shell did not exit when told to"
    );
}

#[test_case]
fn input_is_not_silently_dropped() {
    assert_eq!(
        input::dropped(),
        0,
        "the input buffer overflowed during the test run"
    );
}
