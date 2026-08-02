//! The kernel heap.
//!
//! The cases that matter here are the reuse ones. A heap that can allocate,
//! and can free, and still dies after a few thousand cycles is the normal
//! failure mode, and only a test that churns harder than the heap is large will
//! catch it.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::allocator;
use panda_kernel::memory::heap::HEAP_SIZE;
use panda_kernel::{arch::x86_64::halt_loop, testing, BOOTLOADER_CONFIG};

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

#[test_case]
fn a_box_holds_its_value() {
    let value = Box::new(41);
    let other = Box::new(13);
    assert_eq!(*value, 41);
    assert_eq!(*other, 13);
}

#[test_case]
fn a_vec_survives_reallocation() {
    // Starts at capacity zero and grows repeatedly, so this exercises the
    // allocate-copy-free path rather than a single allocation.
    const N: u64 = 1000;
    let collected: Vec<u64> = (0..N).collect();
    assert_eq!(collected.iter().sum::<u64>(), (N - 1) * N / 2);
    assert_eq!(collected.len(), N as usize);
}

#[test_case]
fn strings_allocate_and_grow() {
    let mut text = String::new();
    for n in 0..64 {
        write!(text, "{n},").expect("writing to a String cannot fail");
    }
    assert!(text.starts_with("0,1,2,"));
    assert!(text.ends_with("63,"));
}

#[test_case]
fn many_short_lived_boxes_reuse_memory() {
    // Deliberately more total bytes than the heap holds. Without reuse this runs
    // out and the allocation returns null, which aborts.
    let iterations = (HEAP_SIZE / 16) * 2;
    for i in 0..iterations {
        let boxed = Box::new(i);
        assert_eq!(*boxed, i);
    }
}

#[test_case]
fn a_long_lived_allocation_survives_churn_around_it() {
    // The classic way to break a naive free list: something pinned in the middle
    // of the heap while everything around it is recycled.
    let pinned = Box::new(0xABCD_u64);

    for i in 0..20_000u64 {
        let transient = Box::new(i);
        assert_eq!(*transient, i);
    }

    assert_eq!(*pinned, 0xABCD, "a live allocation was corrupted by churn");
}

#[test_case]
fn freeing_everything_coalesces_the_heap_again() {
    {
        let mut blocks: Vec<Box<[u64; 8]>> = Vec::new();
        for n in 0..64u64 {
            blocks.push(Box::new([n; 8]));
        }
        // Free in an order that is not the order of allocation, so merging has to
        // happen from both directions.
        while let Some(block) = blocks.pop() {
            drop(block);
        }
    }

    let stats = allocator::stats();
    assert_eq!(
        stats.allocations, 0,
        "{} allocations still live after everything was dropped",
        stats.allocations
    );
    assert_eq!(stats.allocated, 0, "byte accounting drifted");

    assert_eq!(
        allocator::free_region_count(),
        1,
        "the heap did not merge back into a single block -- coalescing is broken"
    );
    assert_eq!(
        allocator::largest_free_region(),
        HEAP_SIZE,
        "the single free block is not the whole heap"
    );
}

#[test_case]
fn usage_statistics_track_reality() {
    let baseline = allocator::stats();

    let held = Box::new([0u8; 512]);
    let during = allocator::stats();

    assert!(
        during.allocated >= baseline.allocated + 512,
        "allocating 512 bytes did not show up in the accounting"
    );
    assert_eq!(during.allocations, baseline.allocations + 1);
    assert!(during.peak >= during.allocated);

    drop(held);

    let after = allocator::stats();
    assert_eq!(after.allocated, baseline.allocated);
    assert_eq!(after.allocations, baseline.allocations);
    assert!(
        after.peak >= during.allocated,
        "the high-water mark must not go down"
    );
}
