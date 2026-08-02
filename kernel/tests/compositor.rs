//! The input daemon and the Sovereign compositor.
//!
//! The compositor runs entirely in Ring 3. It reaches the screen only through a
//! shared buffer handle, and learns what to draw only through IPC. These cases
//! check the pixels that actually landed in the display's memory, which is the
//! only evidence that the whole chain -- buffer allocation, sharing, mapping in a
//! second process, and blitting -- worked.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::console::{framebuffer, input};
use panda_kernel::ipc::{self, EndpointId, Rights};
use panda_kernel::sched::ThreadId;
use panda_kernel::{arch::x86_64::halt_loop, gbm, sched, sync, testing, userspace, BOOTLOADER_CONFIG};

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

/// Read a pixel straight out of the display's memory.
fn pixel_at(x: usize, y: usize) -> (u8, u8, u8) {
    let info = framebuffer::info().expect("no framebuffer");
    let base = framebuffer::buffer_address().expect("no framebuffer");
    let offset = (y * info.stride + x) * info.bytes_per_pixel;

    // SAFETY: the framebuffer is mapped for the life of the kernel and `offset`
    // is inside it by construction -- callers stay well within width and height.
    unsafe {
        let pixel = (base + offset as u64) as *const u8;
        (
            pixel.read_volatile(),
            pixel.add(1).read_volatile(),
            pixel.add(2).read_volatile(),
        )
    }
}

static COMPOSITOR_ENDPOINT: AtomicU64 = AtomicU64::new(0);
static COMPOSITOR_TID: AtomicU64 = AtomicU64::new(0);
static CLIENT_PARAMS: sync::Mutex<[u64; 8]> = sync::Mutex::new([0; 8]);

fn compositor_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_program(owner, userspace::compositor_program())
        .expect("failed to map the compositor");
    let endpoint = COMPOSITOR_ENDPOINT.load(Ordering::Acquire);
    // SAFETY: load_program mapped the entry user-executable and the stack
    // user-writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, endpoint) }
}

fn client_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_program(owner, userspace::client_program())
        .expect("failed to map the client");

    let params = *CLIENT_PARAMS.lock();
    // SAFETY: `image.data` is the writable data page just mapped for this
    // program, and the program is not running yet.
    unsafe { userspace::write_parameters(image.data, &params) };

    // SAFETY: as in `compositor_thread`.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, 0) }
}

fn input_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_program(owner, userspace::input_program())
        .expect("failed to map the input daemon");
    let endpoint = COMPOSITOR_ENDPOINT.load(Ordering::Acquire);
    // SAFETY: as above.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, endpoint) }
}

/// Bring up the compositor and wait until it is parked waiting for work, which
/// means it has already mapped the scanout buffer.
fn start_compositor() -> (EndpointId, ThreadId) {
    let endpoint = ipc::create(me(), 16).expect("create failed");
    COMPOSITOR_ENDPOINT.store(endpoint.0, Ordering::Release);

    let compositor = sync::without_interrupts(|| {
        let id = sched::spawn("compositor", compositor_thread).expect("spawn failed");
        ipc::grant(me(), id, endpoint, Rights::RECEIVE).expect("grant failed");
        gbm::allow_display_server(id);
        id
    });
    COMPOSITOR_TID.store(compositor.0 as u64, Ordering::Release);

    assert!(
        spin_until(|| sched::is_blocked(compositor) || !sched::is_alive(compositor)),
        "the compositor never settled"
    );
    assert!(sched::is_alive(compositor), "the compositor died at start-up");

    (endpoint, compositor)
}

/// Run one client: fill a buffer with `colour` and ask for it at (x, y).
fn present(endpoint: EndpointId, compositor: ThreadId, colour: u64, x: u64, y: u64) {
    let depth = gbm::bytes_per_pixel() as u64;
    *CLIENT_PARAMS.lock() = [
        colour,
        x,
        y,
        endpoint.0,
        40, // width
        30, // height
        compositor.0 as u64,
        depth,
    ];

    let client = sync::without_interrupts(|| {
        let id = sched::spawn("client", client_thread).expect("spawn failed");
        ipc::grant(me(), id, endpoint, Rights::SEND).expect("grant failed");
        id
    });

    assert!(
        spin_until(|| !sched::is_alive(client)),
        "the client never finished"
    );
}

#[test_case]
fn a_client_buffer_reaches_the_screen() {
    let (endpoint, compositor) = start_compositor();

    // 0x0000FF: blue is the low byte, which lands in byte 0 of a BGR pixel.
    present(endpoint, compositor, 0x0000FF, 100, 300);

    assert!(
        spin_until(|| pixel_at(110, 310) == (0xFF, 0x00, 0x00)),
        "nothing blue appeared where the client asked for it; got {:?}",
        pixel_at(110, 310)
    );
}

#[test_case]
fn several_clients_composite_side_by_side() {
    let (endpoint, compositor) = start_compositor();

    present(endpoint, compositor, 0x0000FF, 200, 400);
    present(endpoint, compositor, 0x00FF00, 300, 400);
    present(endpoint, compositor, 0xFF0000, 400, 400);

    assert!(
        spin_until(|| pixel_at(410, 410) == (0x00, 0x00, 0xFF)),
        "the last client never appeared"
    );

    // All three must still be on screen: a compositor that only tracked one
    // surface would have overwritten the earlier ones.
    assert_eq!(pixel_at(210, 410), (0xFF, 0x00, 0x00), "the blue surface is gone");
    assert_eq!(pixel_at(310, 410), (0x00, 0xFF, 0x00), "the green surface is gone");
    assert_eq!(pixel_at(410, 410), (0x00, 0x00, 0xFF), "the red surface is gone");
}

#[test_case]
fn a_surface_lands_where_it_was_asked_to() {
    let (endpoint, compositor) = start_compositor();
    present(endpoint, compositor, 0x00FF00, 600, 500);

    assert!(
        spin_until(|| pixel_at(610, 510) == (0x00, 0xFF, 0x00)),
        "the surface did not appear at its requested position"
    );

    // Just outside the 40x30 surface, nothing should have been touched.
    assert_ne!(
        pixel_at(650, 510),
        (0x00, 0xFF, 0x00),
        "the blit ran past the right edge of the surface"
    );
    assert_ne!(
        pixel_at(610, 545),
        (0x00, 0xFF, 0x00),
        "the blit ran past the bottom edge of the surface"
    );
}

#[test_case]
fn the_input_daemon_forwards_and_sanitises() {
    let endpoint = ipc::create(me(), 16).expect("create failed");
    COMPOSITOR_ENDPOINT.store(endpoint.0, Ordering::Release);

    let daemon = sync::without_interrupts(|| {
        let id = sched::spawn("input", input_thread).expect("spawn failed");
        ipc::grant(me(), id, endpoint, Rights::SEND).expect("grant failed");
        id
    });

    assert!(
        spin_until(|| sched::is_blocked(daemon)),
        "the input daemon never parked waiting for a key"
    );

    // A printable character must arrive; a bell must not. Dropping control
    // codes is the sanitising the PRD asks the input daemon to do.
    input::inject(b'k');
    input::inject(0x07);
    input::inject(b'j');

    assert!(
        spin_until(|| ipc::queued(endpoint) >= 2),
        "the input daemon forwarded nothing"
    );

    let first = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(first.tag, 1, "not a key event");
    assert_eq!(first.words[0], b'k' as u64);
    assert_eq!(
        first.sender,
        daemon.0 as u64,
        "the key event did not come from the daemon"
    );

    let second = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(
        second.words[0],
        b'j' as u64,
        "the bell was forwarded instead of being dropped"
    );

    // Escape shuts it down.
    input::inject(0x1b);
    assert!(
        spin_until(|| !sched::is_alive(daemon)),
        "the input daemon did not exit on escape"
    );
}
