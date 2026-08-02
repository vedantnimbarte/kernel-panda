//! Per-process resource limits.
//!
//! Every case here is a denial of service that Ring 3 could mount in a handful
//! of instructions before the limits existed: loop on a create call until the
//! kernel heap or physical memory runs out, and take the whole system down.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc::{self, Rights};
use panda_kernel::memory::frame;
use panda_kernel::sched::ThreadId;
use panda_kernel::syscall::Error;
use panda_kernel::{arch::x86_64::halt_loop, gbm, sched, testing, BOOTLOADER_CONFIG};

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

fn me() -> ThreadId {
    sched::current_id().expect("no current thread")
}

#[test_case]
fn endpoint_creation_is_capped() {
    let mut created = Vec::new();
    let mut refused = None;

    // One more than the limit, so the last attempt must be the one that fails.
    for _ in 0..=ipc::MAX_ENDPOINTS_PER_THREAD {
        match ipc::create(me(), 4) {
            Ok(endpoint) => created.push(endpoint),
            Err(error) => {
                refused = Some(error);
                break;
            }
        }
    }

    assert_eq!(
        refused,
        Some(Error::QuotaExceeded),
        "a thread created {} endpoints without being refused; a loop on create \
         would exhaust the kernel heap",
        created.len()
    );
    assert!(created.len() <= ipc::MAX_ENDPOINTS_PER_THREAD);
}

#[test_case]
fn buffer_count_is_capped() {
    let mut created = Vec::new();
    let mut refused = None;

    for _ in 0..=gbm::MAX_BUFFERS_PER_THREAD {
        match gbm::create(me(), 16, 16) {
            Ok(buffer) => created.push(buffer),
            Err(error) => {
                refused = Some(error);
                break;
            }
        }
    }

    let outcome = refused;
    for buffer in created {
        let _ = gbm::destroy(me(), buffer);
    }

    assert_eq!(
        outcome,
        Some(Error::QuotaExceeded),
        "a thread allocated past its buffer limit"
    );
}

#[test_case]
fn total_buffer_bytes_are_capped() {
    // A per-allocation ceiling alone is not a quota -- a process just asks
    // repeatedly. This checks the running total is what is enforced.
    let mut created = Vec::new();
    let mut refused = None;

    // Sized so the byte limit bites well before the count limit, whatever the
    // display's pixel depth: at three bytes per pixel these are 12 MiB apiece,
    // so six exceed the 64 MiB allowance while the count cap is sixteen.
    for _ in 0..gbm::MAX_BUFFERS_PER_THREAD {
        match gbm::create(me(), 2048, 2048) {
            Ok(buffer) => created.push(buffer),
            Err(error) => {
                refused = Some(error);
                break;
            }
        }
    }

    let outcome = refused;
    let allocated = created.len();
    for buffer in created {
        let _ = gbm::destroy(me(), buffer);
    }

    assert_eq!(
        outcome,
        Some(Error::QuotaExceeded),
        "{allocated} multi-megabyte buffers were handed out without hitting the \
         byte limit"
    );
}

#[test_case]
fn a_refused_allocation_takes_no_frames() {
    // The quota is checked before any frame is taken. Allocating first and
    // refusing afterwards would let a process drive the allocator up and down
    // at will even though every request is denied.
    let mut created = Vec::new();
    while let Ok(buffer) = gbm::create(me(), 1024, 1024) {
        created.push(buffer);
    }

    let before = frame::with(|allocator| allocator.free_frames());
    for _ in 0..8 {
        assert_eq!(
            gbm::create(me(), 1024, 1024),
            Err(Error::QuotaExceeded),
            "the quota stopped being enforced"
        );
    }
    let after = frame::with(|allocator| allocator.free_frames());

    for buffer in created {
        let _ = gbm::destroy(me(), buffer);
    }

    assert_eq!(
        before, after,
        "refused allocations still consumed physical frames"
    );
}

#[test_case]
fn quota_is_distinct_from_out_of_memory() {
    // A caller that cannot tell "the machine is full" from "you have had your
    // share" cannot decide whether retrying later is worth anything.
    assert_ne!(Error::QuotaExceeded, Error::OutOfMemory);
    assert_ne!(
        Error::QuotaExceeded as i64,
        Error::OutOfMemory as i64,
        "the two conditions report the same code to user space"
    );
}

#[test_case]
fn capabilities_per_thread_are_capped() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    let target = sched::spawn("cap-target", || {}).expect("spawn failed");

    // Re-granting the same endpoint must not consume a new slot each time, or
    // the cap would be trivially reachable by a cooperating pair.
    for _ in 0..(ipc::MAX_CAPABILITIES_PER_THREAD + 8) {
        ipc::grant(me(), target, endpoint, Rights::SEND).expect("re-grant failed");
    }

    assert!(
        ipc::rights_of(target, endpoint).contains(Rights::SEND),
        "the repeated grants lost the capability"
    );
}
