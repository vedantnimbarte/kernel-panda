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
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::memory::frame;
use panda_kernel::{allocator, arch::x86_64::halt_loop, sched, smp, testing, BOOTLOADER_CONFIG};

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
                // SAFETY: just mapped present and writable.
                unsafe { (address as *mut u64).write_volatile(0xA5A5_A5A5) };
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
