//! Preemptive thread scheduling.
//!
//! The distinction these tests exist to draw is preemptive versus cooperative.
//! A cooperative scheduler passes every test that involves yielding, so the
//! cases below deliberately *never* yield: the spawning thread spins on an
//! atomic and nothing but a timer interrupt can hand the CPU to anyone else.
//! If preemption regresses to cooperative, they hang rather than quietly
//! passing.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::hint::black_box;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::{arch::x86_64::halt_loop, sched, testing, BOOTLOADER_CONFIG};

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

/// Comfortably more than a few 10 ms time slices, but bounded so a broken
/// scheduler fails with a message instead of hanging until the host times out.
const SPIN_BUDGET: u64 = 2_000_000_000;

/// Spin until `condition` holds. Never yields -- that is the whole point.
fn spin_until(condition: impl Fn() -> bool) -> bool {
    for _ in 0..SPIN_BUDGET {
        if condition() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn bump() {
    COUNTER.fetch_add(1, Ordering::Relaxed);
}

#[test_case]
fn the_scheduler_adopted_the_boot_thread() {
    assert!(sched::is_initialised(), "scheduler was never initialised");
    assert_eq!(
        sched::current_name(),
        Some("boot"),
        "tests should be running on the boot thread"
    );
    // Boot and idle.
    assert!(
        sched::live_thread_count() >= 2,
        "expected at least a boot thread and an idle thread"
    );
}

#[test_case]
fn a_spawned_thread_runs_without_the_spawner_ever_yielding() {
    let before = COUNTER.load(Ordering::Relaxed);
    sched::spawn("bump", bump).expect("spawn failed");

    assert!(
        spin_until(|| COUNTER.load(Ordering::Relaxed) > before),
        "the spawned thread never ran. This thread never yields, so the only \
         way it could have run is the timer preempting us -- preemption is not \
         happening"
    );
}

#[test_case]
fn every_spawned_thread_gets_the_cpu() {
    let before = COUNTER.load(Ordering::Relaxed);
    for _ in 0..4 {
        sched::spawn("bump", bump).expect("spawn failed");
    }

    assert!(
        spin_until(|| COUNTER.load(Ordering::Relaxed) >= before + 4),
        "only {} of 4 spawned threads ran; the round-robin is not reaching all \
         of the ready queue",
        COUNTER.load(Ordering::Relaxed) - before
    );
}

static STOP_SPINNER: AtomicBool = AtomicBool::new(false);
static SPINNER_ITERATIONS: AtomicU64 = AtomicU64::new(0);

fn spinner() {
    while !STOP_SPINNER.load(Ordering::Relaxed) {
        SPINNER_ITERATIONS.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

#[test_case]
fn a_cpu_bound_thread_does_not_starve_the_others() {
    STOP_SPINNER.store(false, Ordering::Relaxed);
    SPINNER_ITERATIONS.store(0, Ordering::Relaxed);

    sched::spawn("spinner", spinner).expect("spawn failed");
    assert!(
        spin_until(|| SPINNER_ITERATIONS.load(Ordering::Relaxed) > 0),
        "the spinner never started"
    );

    // A thread that never blocks and never yields is now competing for the CPU.
    // A newly spawned thread still has to get a slice.
    let before = COUNTER.load(Ordering::Relaxed);
    sched::spawn("bump", bump).expect("spawn failed");

    let ran = spin_until(|| COUNTER.load(Ordering::Relaxed) > before);
    STOP_SPINNER.store(true, Ordering::Relaxed);

    assert!(
        ran,
        "a CPU-bound thread starved a newly spawned one -- the timer is not \
         taking the CPU away from a thread that will not give it up"
    );
}

#[test_case]
fn yielding_hands_over_promptly() {
    let before = COUNTER.load(Ordering::Relaxed);
    sched::spawn("bump", bump).expect("spawn failed");

    // Far more yields than a round-robin needs to come back around.
    for _ in 0..200 {
        if COUNTER.load(Ordering::Relaxed) > before {
            return;
        }
        sched::yield_now();
    }

    panic!("200 yields did not give the spawned thread a chance to run");
}

static STACK_A: AtomicU64 = AtomicU64::new(0);
static STACK_B: AtomicU64 = AtomicU64::new(0);

fn record_stack_a() {
    let local = 0u64;
    STACK_A.store(black_box(&local) as *const u64 as u64, Ordering::Relaxed);
}

fn record_stack_b() {
    let local = 0u64;
    STACK_B.store(black_box(&local) as *const u64 as u64, Ordering::Relaxed);
}

#[test_case]
fn threads_run_on_separate_stacks() {
    STACK_A.store(0, Ordering::Relaxed);
    STACK_B.store(0, Ordering::Relaxed);

    sched::spawn("stack-a", record_stack_a).expect("spawn failed");
    sched::spawn("stack-b", record_stack_b).expect("spawn failed");

    assert!(
        spin_until(|| STACK_A.load(Ordering::Relaxed) != 0
            && STACK_B.load(Ordering::Relaxed) != 0),
        "the stack-probing threads did not both run"
    );

    let a = STACK_A.load(Ordering::Relaxed);
    let b = STACK_B.load(Ordering::Relaxed);
    let gap = a.abs_diff(b);

    // Sharing a stack would put both locals within a few bytes of each other,
    // and the two threads would be quietly corrupting one another.
    assert!(
        gap >= 4096,
        "two threads put their locals {gap} bytes apart ({a:#x} and {b:#x}); \
         they are sharing a stack"
    );
}

#[test_case]
fn finished_threads_are_reaped() {
    // Let anything left over from earlier cases drain first, so the baseline is
    // not moving underneath us.
    for _ in 0..50 {
        sched::yield_now();
    }
    let baseline = sched::live_thread_count();

    let before = COUNTER.load(Ordering::Relaxed);
    for _ in 0..4 {
        sched::spawn("short-lived", bump).expect("spawn failed");
    }
    assert!(
        spin_until(|| COUNTER.load(Ordering::Relaxed) >= before + 4),
        "the short-lived threads did not all run"
    );

    assert!(
        spin_until(|| sched::live_thread_count() <= baseline),
        "thread count stayed at {} against a baseline of {baseline}; finished \
         threads are not being reaped and their stacks are leaking",
        sched::live_thread_count()
    );
}
