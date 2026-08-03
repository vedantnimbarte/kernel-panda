//! Generic buffer management.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::console::framebuffer;
use panda_kernel::gbm::{self, BufferId};
use panda_kernel::memory::frame;
use panda_kernel::sched::ThreadId;
use panda_kernel::syscall::Error;
use panda_kernel::arch::x86_64::with_user_access;
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

fn me() -> ThreadId {
    sched::current_id().expect("no current thread")
}

#[test_case]
fn a_created_buffer_reports_its_geometry() {
    let buffer = gbm::create(me(), 64, 32).expect("create failed");
    let info = gbm::info(me(), buffer).expect("info failed");

    let depth = gbm::bytes_per_pixel();
    assert_eq!(info.width, 64);
    assert_eq!(info.height, 32);
    assert_eq!(info.bytes_per_pixel, depth);
    assert_eq!(info.stride, 64 * depth);
    assert_eq!(info.size, u64::from(64 * 32 * depth));

    gbm::destroy(me(), buffer).expect("destroy failed");
}

#[test_case]
fn a_mapped_buffer_is_readable_and_writable() {
    let buffer = gbm::create(me(), 64, 32).expect("create failed");
    let address = gbm::map(me(), buffer).expect("map failed");

    // Buffers are user-accessible pages, so Ring 0 needs SMAP relaxed to touch
    // one even from a kernel thread that owns it.
    with_user_access(|| {
        // SAFETY: `map` returned a range of `size` bytes mapped present and
        // writable, owned by this buffer alone.
        unsafe {
            let pixels = address as *mut u32;
            for index in 0..(64 * 32) {
                pixels.add(index).write_volatile(0xDEAD_0000 | index as u32);
            }
            for index in 0..(64 * 32) {
                assert_eq!(
                    pixels.add(index).read_volatile(),
                    0xDEAD_0000 | index as u32,
                    "buffer memory did not read back"
                );
            }
        }
    });

    gbm::destroy(me(), buffer).expect("destroy failed");
}

#[test_case]
fn mapping_twice_returns_the_same_address() {
    let buffer = gbm::create(me(), 16, 16).expect("create failed");
    let first = gbm::map(me(), buffer).expect("map failed");
    let second = gbm::map(me(), buffer).expect("second map failed");

    assert_eq!(
        first, second,
        "mapping the same buffer twice consumed the address space twice"
    );

    gbm::destroy(me(), buffer).expect("destroy failed");
}

#[test_case]
fn an_absurd_allocation_is_refused() {
    assert_eq!(
        gbm::create(me(), 100_000, 100_000),
        Err(Error::InvalidArgument),
        "a buffer far larger than physical memory was accepted"
    );
}

#[test_case]
fn destroying_returns_the_frames() {
    // Warm the region first. Mapping into a range nothing has used yet also
    // builds the page tables that describe it, and destroying the buffer now
    // reclaims those too -- so a cold measurement would see *more* frames come
    // back than went out, which is not what this case is about.
    let warmup = gbm::create(me(), 256, 256).expect("warm-up create failed");
    gbm::destroy(me(), warmup).expect("warm-up destroy failed");

    let before = frame::with(|allocator| allocator.free_frames());

    let buffer = gbm::create(me(), 256, 256).expect("create failed");
    let during = frame::with(|allocator| allocator.free_frames());
    assert!(
        during < before,
        "allocating a 256 KiB buffer consumed no physical frames"
    );

    gbm::destroy(me(), buffer).expect("destroy failed");
    assert_eq!(
        frame::with(|allocator| allocator.free_frames()),
        before,
        "destroying a buffer did not return its frames"
    );
}

// --- access control ---------------------------------------------------------

static TARGET_BUFFER: AtomicU64 = AtomicU64::new(0);
static OUTSIDER_RESULT: AtomicU64 = AtomicU64::new(0);
static OUTSIDER_RAN: AtomicBool = AtomicBool::new(false);

fn outsider() {
    let buffer = BufferId(TARGET_BUFFER.load(Ordering::Acquire));
    OUTSIDER_RESULT.store(
        match gbm::map(me(), buffer) {
            Err(Error::NoCapability) => 1,
            Err(_) => 2,
            Ok(_) => 3,
        },
        Ordering::Release,
    );
    OUTSIDER_RAN.store(true, Ordering::Release);
}

#[test_case]
fn a_buffer_cannot_be_mapped_without_access() {
    let buffer = gbm::create(me(), 32, 32).expect("create failed");
    TARGET_BUFFER.store(buffer.0, Ordering::Release);
    OUTSIDER_RAN.store(false, Ordering::Release);

    sched::spawn("outsider", outsider).expect("spawn failed");
    assert!(
        spin_until(|| OUTSIDER_RAN.load(Ordering::Acquire)),
        "the outsider thread never ran"
    );

    assert_eq!(
        OUTSIDER_RESULT.load(Ordering::Acquire),
        1,
        "a thread with no claim on the buffer was able to map it; a handle must \
         not be authority on its own"
    );

    gbm::destroy(me(), buffer).expect("destroy failed");
}

static SHARED_BUFFER: AtomicU64 = AtomicU64::new(0);
static INSIDER_OK: AtomicBool = AtomicBool::new(false);
static INSIDER_RAN: AtomicBool = AtomicBool::new(false);
static INSIDER_RELEASE: AtomicBool = AtomicBool::new(false);

fn insider() {
    let buffer = BufferId(SHARED_BUFFER.load(Ordering::Acquire));
    INSIDER_OK.store(gbm::map(me(), buffer).is_ok(), Ordering::Release);
    INSIDER_RAN.store(true, Ordering::Release);

    // Held open until the test is done looking. Exiting here would correctly
    // withdraw this thread from the buffer's share list, and the assertions
    // below would then be racing the teardown rather than testing the share.
    while !INSIDER_RELEASE.load(Ordering::Acquire) {
        sched::yield_now();
    }
}

#[test_case]
fn sharing_a_buffer_grants_access() {
    let buffer = gbm::create(me(), 32, 32).expect("create failed");
    SHARED_BUFFER.store(buffer.0, Ordering::Release);
    INSIDER_RAN.store(false, Ordering::Release);
    INSIDER_RELEASE.store(false, Ordering::Release);

    // `without_interrupts` masks this processor and no other, so it does not
    // make the spawn and the grant atomic with respect to the thread itself --
    // another core can pick it up the moment it is queued. Keeping the thread
    // alive is what makes the observation stable.
    let id = panda_kernel::sync::without_interrupts(|| {
        let id = sched::spawn("insider", insider).expect("spawn failed");
        gbm::share(me(), id, buffer).expect("share failed");
        id
    });

    assert!(gbm::may_access(id, buffer), "the share did not take effect");

    assert!(
        spin_until(|| INSIDER_RAN.load(Ordering::Acquire)),
        "the insider thread never ran"
    );
    assert!(
        INSIDER_OK.load(Ordering::Acquire),
        "a thread the buffer was shared with could not map it"
    );

    INSIDER_RELEASE.store(true, Ordering::Release);
    sched::join(id);
}

#[test_case]
fn sharing_requires_ownership() {
    let buffer = gbm::create(me(), 16, 16).expect("create failed");
    // Thread id 1 is the idle thread, which owns nothing.
    assert_eq!(
        gbm::share(ThreadId(1), ThreadId(1), buffer),
        Err(Error::NoCapability),
        "a non-owner was able to share a buffer with itself"
    );
    gbm::destroy(me(), buffer).expect("destroy failed");
}

// --- scanout ----------------------------------------------------------------

#[test_case]
fn the_scanout_buffer_needs_a_display_server_capability() {
    // Reaching the screen is authority. Any process being able to ask for the
    // framebuffer and receive it would mean reading everything displayed and
    // drawing over it at will.
    assert!(
        !gbm::is_display_server(ThreadId(1)),
        "the idle thread was somehow designated a display server"
    );
    assert_eq!(
        gbm::scanout(ThreadId(1)),
        Err(Error::NoCapability),
        "a thread with no display capability was handed the framebuffer"
    );
}

#[test_case]
fn the_scanout_buffer_matches_the_display() {
    gbm::allow_display_server(me());
    let scanout = gbm::scanout(me()).expect("no scanout buffer");
    let info = gbm::info(me(), scanout).expect("info failed");
    let display = framebuffer::info().expect("no framebuffer");

    assert_eq!(info.width, display.width as u32);
    assert_eq!(info.height, display.height as u32);
    assert_eq!(
        info.size,
        display.byte_len as u64,
        "the scanout buffer does not span the whole framebuffer"
    );
}

#[test_case]
fn the_scanout_buffer_is_a_singleton() {
    gbm::allow_display_server(me());
    let first = gbm::scanout(me()).expect("no scanout buffer");
    let second = gbm::scanout(me()).expect("no scanout buffer");
    assert_eq!(
        first, second,
        "two independent handles to the one screen were handed out"
    );
}

#[test_case]
fn the_scanout_buffer_cannot_be_destroyed() {
    gbm::allow_display_server(me());
    let scanout = gbm::scanout(me()).expect("no scanout buffer");
    assert_eq!(
        gbm::destroy(me(), scanout),
        Err(Error::InvalidArgument),
        "the display's own memory was released to the frame allocator"
    );
}
