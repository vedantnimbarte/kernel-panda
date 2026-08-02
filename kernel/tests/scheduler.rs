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

// --- sleeping ---------------------------------------------------------------

static SLEEPER_WOKE_AT: AtomicU64 = AtomicU64::new(0);
static SLEEP_TICKS: AtomicU64 = AtomicU64::new(0);

fn sleep_then_record() {
    sched::sleep_ticks(SLEEP_TICKS.load(Ordering::Acquire));
    SLEEPER_WOKE_AT.store(panda_kernel::time::ticks(), Ordering::Release);
}

#[test_case]
fn a_sleeping_thread_wakes_no_earlier_than_its_deadline() {
    const NAP: u64 = 10;
    SLEEP_TICKS.store(NAP, Ordering::Release);
    SLEEPER_WOKE_AT.store(0, Ordering::Release);

    let started = panda_kernel::time::ticks();
    let thread = sched::spawn("napper", sleep_then_record).expect("spawn failed");

    assert!(
        spin_until(|| SLEEPER_WOKE_AT.load(Ordering::Acquire) != 0),
        "the sleeping thread never woke; a deadline that is never checked is a \
         thread that is gone for good"
    );
    assert!(
        spin_until(|| !sched::is_alive(thread)),
        "the sleeper never finished"
    );

    let woke = SLEEPER_WOKE_AT.load(Ordering::Acquire);
    assert!(
        woke >= started + NAP,
        "a thread asked to sleep {NAP} ticks woke after {} -- a sleep is a floor",
        woke.saturating_sub(started)
    );
}

#[test_case]
fn a_sleeping_thread_is_not_on_the_ready_queue() {
    // The distinction is sleeping versus spinning. A thread that yielded in a
    // loop would report Ready every time it is looked at.
    SLEEP_TICKS.store(60, Ordering::Release);
    SLEEPER_WOKE_AT.store(0, Ordering::Release);

    let thread = sched::spawn("long-napper", sleep_then_record).expect("spawn failed");
    assert!(
        spin_until(|| sched::is_blocked(thread)),
        "a thread in the middle of a sleep never appeared blocked, so it is \
         burning CPU rather than waiting"
    );

    assert!(
        spin_until(|| SLEEPER_WOKE_AT.load(Ordering::Acquire) != 0),
        "the long sleeper never woke"
    );
}

// --- joining ----------------------------------------------------------------

static JOIN_FLAG: AtomicU64 = AtomicU64::new(0);

fn slow_worker() {
    sched::sleep_ticks(5);
    JOIN_FLAG.store(1, Ordering::Release);
}

#[test_case]
fn join_returns_only_after_the_thread_has_finished() {
    JOIN_FLAG.store(0, Ordering::Release);
    let worker = sched::spawn("joinee", slow_worker).expect("spawn failed");

    sched::join(worker);

    assert_eq!(
        JOIN_FLAG.load(Ordering::Acquire),
        1,
        "join returned before the thread it was waiting for had done its work"
    );
}

#[test_case]
fn joining_a_thread_that_has_already_finished_returns() {
    JOIN_FLAG.store(0, Ordering::Release);
    let worker = sched::spawn("quick-joinee", bump).expect("spawn failed");
    assert!(
        spin_until(|| !sched::is_alive(worker)),
        "the worker never finished"
    );

    // Reaped, so there is nothing left to register with. Parking here would be
    // a hang with no possible wake-up.
    sched::join(worker);
}

#[test_case]
fn joining_yourself_does_not_park_forever() {
    let me = sched::current_id().expect("no current thread");
    sched::join(me);
}

// --- priority ---------------------------------------------------------------

static HIGH_RUNS: AtomicU64 = AtomicU64::new(0);
static LOW_RUNS: AtomicU64 = AtomicU64::new(0);
static PRIORITY_STOP: AtomicBool = AtomicBool::new(false);

fn high_priority_loop() {
    while !PRIORITY_STOP.load(Ordering::Acquire) {
        HIGH_RUNS.fetch_add(1, Ordering::Relaxed);
        sched::yield_now();
    }
}

fn low_priority_loop() {
    while !PRIORITY_STOP.load(Ordering::Acquire) {
        LOW_RUNS.fetch_add(1, Ordering::Relaxed);
        sched::yield_now();
    }
}

#[test_case]
fn a_high_priority_thread_runs_more_often_than_a_low_one() {
    // Enough of each to keep every core busy. With four cores and one thread of
    // each priority, both simply get a core and priority never comes into it --
    // the queues have to be contended for the choice to mean anything.
    const EACH: usize = 6;

    HIGH_RUNS.store(0, Ordering::Relaxed);
    LOW_RUNS.store(0, Ordering::Relaxed);
    PRIORITY_STOP.store(false, Ordering::Release);

    let mut threads = [sched::ThreadId(0); EACH * 2];
    for slot in threads.iter_mut().take(EACH) {
        *slot = sched::spawn_with_priority("high", high_priority_loop, sched::Priority::High)
            .expect("spawn failed");
    }
    for slot in threads.iter_mut().skip(EACH) {
        *slot = sched::spawn_with_priority("low", low_priority_loop, sched::Priority::Low)
            .expect("spawn failed");
    }

    assert_eq!(sched::priority_of(threads[0]), Some(sched::Priority::High));
    assert_eq!(
        sched::priority_of(threads[EACH]),
        Some(sched::Priority::Low)
    );

    sched::sleep_ticks(20);
    PRIORITY_STOP.store(true, Ordering::Release);

    let high_runs = HIGH_RUNS.load(Ordering::Relaxed);
    let low_runs = LOW_RUNS.load(Ordering::Relaxed);

    for thread in threads {
        sched::join(thread);
    }

    assert!(
        high_runs > low_runs,
        "the high-priority threads ran {high_runs} times against the low ones' \
         {low_runs}; priority is not being honoured"
    );
    assert!(
        low_runs > 0,
        "the low-priority threads never ran at all in {high_runs} switches -- \
         strict priority starves, and the guard against it is not working"
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
