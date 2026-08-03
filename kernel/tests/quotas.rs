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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc::{self, Rights};
use panda_kernel::memory::frame;
use panda_kernel::sched::ThreadId;
use panda_kernel::syscall::Error;
use panda_kernel::{arch::x86_64::halt_loop, gbm, quota, sched, testing, BOOTLOADER_CONFIG};

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

const SPIN_BUDGET: u64 = 2_000_000_000;

/// Bounded, so a broken limit fails with a message rather than hanging until
/// the host gives up.
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

// --- per-process policy ------------------------------------------------------

static RESTRICTED_RELEASE: AtomicBool = AtomicBool::new(false);
static RESTRICTED_CREATED: AtomicUsize = AtomicUsize::new(0);
static RESTRICTED_REFUSED: AtomicBool = AtomicBool::new(false);

/// Creates endpoints until it is refused, then reports how many it managed.
fn restricted_worker() {
    let mut created = 0;
    loop {
        match ipc::create(me(), 4) {
            Ok(_) => {
                created += 1;
                RESTRICTED_CREATED.store(created, Ordering::Release);
                if created > 64 {
                    // Never refused: something is wrong, and looping forever
                    // would be a hang rather than a failure.
                    break;
                }
            }
            Err(_) => {
                RESTRICTED_REFUSED.store(true, Ordering::Release);
                break;
            }
        }
    }

    while !RESTRICTED_RELEASE.load(Ordering::Acquire) {
        sched::yield_now();
    }
}

#[test_case]
fn a_thread_gets_the_default_quota_unless_told_otherwise() {
    let fresh = quota::of(me());
    assert_eq!(
        fresh,
        quota::Quota::DEFAULT,
        "a thread nobody restricted does not have the default quota"
    );
}

#[test_case]
fn a_spawner_can_hand_a_child_less_than_it_has() {
    RESTRICTED_RELEASE.store(false, Ordering::Release);
    RESTRICTED_CREATED.store(0, Ordering::Release);
    RESTRICTED_REFUSED.store(false, Ordering::Release);

    let narrow = quota::Quota {
        endpoints: 3,
        ..quota::Quota::DEFAULT
    };

    let child = sched::spawn("restricted", restricted_worker).expect("spawn failed");
    let granted = quota::grant(me(), child, narrow);
    assert_eq!(granted.endpoints, 3, "the grant was not applied as asked");

    assert!(
        spin_until(|| RESTRICTED_REFUSED.load(Ordering::Acquire)),
        "the restricted thread was never refused; it created {} endpoints \
         against a limit of 3",
        RESTRICTED_CREATED.load(Ordering::Acquire)
    );
    assert_eq!(
        RESTRICTED_CREATED.load(Ordering::Acquire),
        3,
        "the restricted thread's limit was not the one it was given"
    );

    RESTRICTED_RELEASE.store(true, Ordering::Release);
    sched::join(child);
}

#[test_case]
fn a_thread_cannot_hand_a_child_more_than_it_has() {
    // The rule the capability system already uses, applied to resources:
    // authority narrows and never widens. Without it, a process at its limit
    // spawns a helper, grants it a larger quota, and asks the helper for
    // memory -- and the limit means nothing.
    let narrow = quota::Quota {
        buffers: 2,
        buffer_bytes: 1024,
        ..quota::Quota::NOTHING
    };

    let parent = sched::spawn("narrow-parent", || {}).expect("spawn failed");
    quota::grant(me(), parent, narrow);

    let child = sched::spawn("greedy-child", || {}).expect("spawn failed");
    let granted = quota::grant(parent, child, quota::Quota::DEFAULT);

    assert_eq!(
        granted.buffers, 2,
        "a thread limited to 2 buffers gave its child more"
    );
    assert_eq!(
        granted.buffer_bytes, 1024,
        "a thread limited to 1 KiB gave its child more"
    );
    assert_eq!(
        granted.endpoints, 0,
        "a thread with no endpoint allowance gave its child one"
    );

    sched::join(parent);
    sched::join(child);
}

#[test_case]
fn a_quota_is_forgotten_when_its_thread_exits() {
    let before = quota::assigned_count();

    let child = sched::spawn("short-lived-quota", || {}).expect("spawn failed");
    quota::grant(
        me(),
        child,
        quota::Quota {
            buffers: 1,
            ..quota::Quota::DEFAULT
        },
    );
    sched::join(child);

    assert!(
        spin_until(|| quota::assigned_count() <= before),
        "the quota table kept an entry for a thread that has exited; it grows \
         for the life of the system"
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

static CAP_TARGET_RELEASE: AtomicBool = AtomicBool::new(false);

/// Stays alive until the test is finished with it.
///
/// A thread that simply returned would be reaped -- on another core, quite
/// possibly before the grant loop is even over -- and `release_thread` takes its
/// capabilities with it. The assertion would then be reading an empty table and
/// blaming the grants for it.
fn cap_target() {
    while !CAP_TARGET_RELEASE.load(Ordering::Acquire) {
        sched::yield_now();
    }
}

#[test_case]
fn capabilities_per_thread_are_capped() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    CAP_TARGET_RELEASE.store(false, Ordering::Release);
    let target = sched::spawn("cap-target", cap_target).expect("spawn failed");

    // Re-granting the same endpoint must not consume a new slot each time, or
    // the cap would be trivially reachable by a cooperating pair.
    for _ in 0..(ipc::MAX_CAPABILITIES_PER_THREAD + 8) {
        ipc::grant(me(), target, endpoint, Rights::SEND).expect("re-grant failed");
    }

    let held = ipc::rights_of(target, endpoint);
    CAP_TARGET_RELEASE.store(true, Ordering::Release);
    sched::join(target);

    assert!(
        held.contains(Rights::SEND),
        "the repeated grants lost the capability"
    );
}
