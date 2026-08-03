//! Multiprocessing.
//!
//! The suite as a whole runs on four cores, so every other test file is already
//! an SMP test in the weak sense that it did not break. These cases check the
//! things that only mean anything with more than one processor: that the others
//! actually started, that work reaches them, and that the shared structures
//! survive being hammered from several at once.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::memory::frame;
use panda_kernel::sync::Mutex;
use panda_kernel::{allocator, arch::x86_64::halt_loop, sched, smp, testing, time, BOOTLOADER_CONFIG};

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

#[test_case]
fn every_processor_the_firmware_reported_came_up() {
    let reported = smp::processor_count();
    let online = smp::online_count();

    assert!(reported >= 1, "ACPI reported no processors at all");
    assert_eq!(
        online, reported,
        "{online} of {reported} processors started; an application processor \
         did not make it through the trampoline"
    );
}

#[test_case]
fn the_timer_tick_does_not_take_the_scheduler_lock() {
    // Not a direct observation -- there is no way to ask a spinlock how often it
    // was taken. What can be checked is the consequence: with the decrement
    // outside the lock, a core can take thousands of ticks' worth of scheduler
    // work while the boot thread holds nothing, and the clock keeps moving.
    // Before, every core queued on one lock a hundred times a second.
    let start = time::ticks();
    assert!(
        spin_until(|| time::ticks() >= start + 5),
        "the clock stopped while several cores were running"
    );

    for cpu in 0..smp::online_count() {
        assert!(
            time::cpu_ticks(cpu) > 0,
            "processor {cpu} has taken no timer interrupts at all"
        );
    }
}

#[test_case]
fn this_processor_has_a_sane_index() {
    let index = smp::cpu_index();
    assert!(
        index < smp::MAX_CPUS,
        "cpu index {index} is outside the per-CPU arrays"
    );
    assert!(
        index < smp::online_count(),
        "cpu index {index} exceeds the number of processors online"
    );
}

static CPU_MASK: AtomicU64 = AtomicU64::new(0);

fn record_processor() {
    // Long enough to be preempted several times, so this thread has a real
    // chance of being resumed somewhere other than where it started.
    for _ in 0..2_000_000 {
        CPU_MASK.fetch_or(1 << smp::cpu_index(), Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

#[test_case]
fn work_reaches_more_than_one_processor() {
    if smp::online_count() < 2 {
        return;
    }

    CPU_MASK.store(0, Ordering::Relaxed);
    for _ in 0..8 {
        sched::spawn("cpu-probe", record_processor).expect("spawn failed");
    }

    assert!(
        spin_until(|| CPU_MASK.load(Ordering::Relaxed).count_ones() >= 2),
        "every thread ran on one processor; the ready queue is not being drained \
         by the others, so the extra cores are idle by accident"
    );
}

static CONTENDED: Mutex<u64> = Mutex::new(0);
static GRABS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static LOCK_STOP: AtomicBool = AtomicBool::new(false);
static LOCK_WORKERS_DONE: AtomicUsize = AtomicUsize::new(0);

fn hammer_the_lock() {
    while !LOCK_STOP.load(Ordering::Acquire) {
        {
            let mut held = CONTENDED.lock();
            *held += 1;
            // Long enough that the other cores are genuinely queued behind this
            // one rather than arriving after it has finished.
            for _ in 0..400 {
                core::hint::spin_loop();
            }
        }
        let cpu = smp::cpu_index();
        if let Some(counter) = GRABS.get(cpu) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
    LOCK_WORKERS_DONE.fetch_add(1, Ordering::AcqRel);
}

#[test_case]
fn a_contended_lock_is_shared_out_evenly() {
    if smp::online_count() < 2 {
        return;
    }

    // A test-and-set spinlock has no queue: every waiter races for the same
    // word on release and the core whose cache already holds the line tends to
    // win again. Under sustained contention that leaves a processor waiting for
    // reasons nothing in the code explains. A ticket lock serves arrivals in
    // order, so every core that keeps asking keeps getting it.
    const WORKERS: usize = 8;

    LOCK_STOP.store(false, Ordering::Release);
    LOCK_WORKERS_DONE.store(0, Ordering::Release);
    for counter in &GRABS {
        counter.store(0, Ordering::Relaxed);
    }

    for _ in 0..WORKERS {
        sched::spawn("lock-hammer", hammer_the_lock).expect("spawn failed");
    }

    sched::sleep_ticks(25);
    LOCK_STOP.store(true, Ordering::Release);
    assert!(
        spin_until(|| LOCK_WORKERS_DONE.load(Ordering::Acquire) >= WORKERS),
        "the lock hammering threads did not all finish"
    );

    let online = smp::online_count().min(GRABS.len());
    let per_cpu: Vec<u64> = (0..online)
        .map(|cpu| GRABS[cpu].load(Ordering::Relaxed))
        .collect();
    let total: u64 = per_cpu.iter().sum();
    assert!(total > 0, "nobody took the lock at all");

    let quietest = per_cpu.iter().copied().min().unwrap_or(0);
    let busiest = per_cpu.iter().copied().max().unwrap_or(0);

    // Deliberately loose. Threads are not pinned and the scheduler moves them,
    // so exact shares are not the claim -- the claim is that no processor is
    // shut out while the others keep going, which is what an unfair lock does.
    assert!(
        quietest * 8 >= busiest,
        "lock acquisitions across {online} processors were {per_cpu:?}; the \
         quietest core got {quietest} against the busiest core's {busiest}, so \
         the lock is not handing out turns in order"
    );
}

static STEAL_DONE: AtomicUsize = AtomicUsize::new(0);
static STEAL_CPUS: AtomicU64 = AtomicU64::new(0);

fn short_burst() {
    for _ in 0..200_000 {
        STEAL_CPUS.fetch_or(1 << smp::cpu_index(), Ordering::Relaxed);
        core::hint::spin_loop();
    }
    STEAL_DONE.fetch_add(1, Ordering::AcqRel);
}

#[test_case]
fn an_idle_processor_steals_from_a_busy_one() {
    if smp::online_count() < 2 {
        return;
    }

    // Every one of these is filed on the queue of the core that spawns them --
    // this one. Per-CPU queues without stealing would leave the other cores
    // running their idle threads next to the whole backlog, and the batch would
    // take as long as running it all here.
    const BATCH: usize = 12;
    STEAL_DONE.store(0, Ordering::Release);
    STEAL_CPUS.store(0, Ordering::Release);

    for _ in 0..BATCH {
        sched::spawn("steal-me", short_burst).expect("spawn failed");
    }

    assert!(
        spin_until(|| STEAL_DONE.load(Ordering::Acquire) >= BATCH),
        "only {} of {BATCH} threads finished",
        STEAL_DONE.load(Ordering::Acquire)
    );

    let cpus = STEAL_CPUS.load(Ordering::Acquire).count_ones();
    assert!(
        cpus >= 2,
        "a batch of {BATCH} threads spawned on one core ran on {cpus} core(s); \
         nothing is stealing, so the other processors sat idle next to the queue"
    );
}

static WORKERS_DONE: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Allocate and free hard, from several processors at once.
fn hammer_the_heap() {
    for round in 0..2_000u64 {
        let mut held: Vec<Box<u64>> = Vec::new();
        for value in 0..8u64 {
            held.push(Box::new(round * 8 + value));
        }
        for (index, item) in held.iter().enumerate() {
            if **item != round * 8 + index as u64 {
                ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(held);

        if round % 128 == 0 {
            sched::yield_now();
        }
    }
    WORKERS_DONE.fetch_add(1, Ordering::AcqRel);
}

#[test_case]
fn the_heap_survives_concurrent_use() {
    // The allocator's lock masks interrupts, which stops a CPU deadlocking
    // against its own timer handler. It does not stop two processors colliding;
    // only the spin does. This is what checks the spin is really there.
    const WORKERS: usize = 6;

    WORKERS_DONE.store(0, Ordering::Release);
    ALLOCATION_FAILURES.store(0, Ordering::Release);

    let before = allocator::stats().allocations;

    for _ in 0..WORKERS {
        sched::spawn("heap-hammer", hammer_the_heap).expect("spawn failed");
    }

    assert!(
        spin_until(|| WORKERS_DONE.load(Ordering::Acquire) >= WORKERS),
        "only {} of {WORKERS} workers finished; the allocator is deadlocked or \
         handing out bad memory",
        WORKERS_DONE.load(Ordering::Acquire)
    );

    assert_eq!(
        ALLOCATION_FAILURES.load(Ordering::Acquire),
        0,
        "an allocation came back holding someone else's data"
    );

    assert!(
        spin_until(|| allocator::stats().allocations <= before),
        "live allocations did not return to their starting count; concurrent \
         frees are being lost"
    );
}

static MAPPERS_DONE: AtomicUsize = AtomicUsize::new(0);

/// Map and unmap graphics buffers, which goes through the page tables and, on
/// the kernel's own space, triggers a TLB shootdown across every other CPU.
fn hammer_the_page_tables() {
    let me = sched::current_id().expect("no current thread");
    for _ in 0..16 {
        if let Ok(buffer) = panda_kernel::gbm::create(me, 32, 32) {
            if let Ok(address) = panda_kernel::gbm::map(me, buffer) {
                // Touch it, so a translation is genuinely cached before the
                // unmap that follows has to shoot it down.
                panda_kernel::arch::x86_64::with_user_access(|| {
                    // SAFETY: just mapped present and writable.
                    unsafe { (address as *mut u64).write_volatile(0xA5A5_A5A5) };
                });
            }
            let _ = panda_kernel::gbm::destroy(me, buffer);
        }
        sched::yield_now();
    }
    MAPPERS_DONE.fetch_add(1, Ordering::AcqRel);
}

#[test_case]
fn page_tables_survive_concurrent_mapping() {
    // Four processors mapping and unmapping in the *shared* kernel address
    // space at once, each unmap broadcasting a shootdown to the other three.
    // What is being checked is that they all get through it: a lock taken in the
    // wrong order, or a shootdown waiting on a CPU that cannot answer, shows up
    // here as workers that never finish.
    const WORKERS: usize = 4;

    MAPPERS_DONE.store(0, Ordering::Release);
    let before = frame::with(|allocator| allocator.free_frames());

    for _ in 0..WORKERS {
        sched::spawn("map-hammer", hammer_the_page_tables).expect("spawn failed");
    }

    assert!(
        spin_until(|| MAPPERS_DONE.load(Ordering::Acquire) >= WORKERS),
        "only {} of {WORKERS} mapping workers finished",
        MAPPERS_DONE.load(Ordering::Acquire)
    );

    // Buffer frames must come back. Page-table frames for freshly touched
    // addresses do not -- that is the intermediate-table leak recorded in the
    // README -- so this allows a small slack rather than demanding an exact
    // balance and quietly testing the wrong thing.
    let after = frame::with(|allocator| allocator.free_frames());
    let leaked = before.saturating_sub(after);
    assert!(
        leaked < 64,
        "{leaked} frames lost across {WORKERS} workers; buffer memory is not \
         being returned under concurrent use"
    );
}
