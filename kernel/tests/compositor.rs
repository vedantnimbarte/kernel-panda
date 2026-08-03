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
use panda_kernel::{
    arch::x86_64::halt_loop, gbm, sched, smp, sync, testing, userspace, BOOTLOADER_CONFIG,
};

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

/// Write a pixel straight into the display's memory.
///
/// Used to plant a sentinel somewhere the compositor should not touch, so that
/// "only the damaged region was redrawn" is something the test can observe
/// rather than infer.
fn write_pixel(x: usize, y: usize, colour: (u8, u8, u8)) {
    let info = framebuffer::info().expect("no framebuffer");
    let base = framebuffer::buffer_address().expect("no framebuffer");
    let offset = (y * info.stride + x) * info.bytes_per_pixel;

    // SAFETY: as in `pixel_at`; the framebuffer is mapped for the life of the
    // kernel and callers stay inside its dimensions.
    unsafe {
        let pixel = (base + offset as u64) as *mut u8;
        pixel.write_volatile(colour.0);
        pixel.add(1).write_volatile(colour.1);
        pixel.add(2).write_volatile(colour.2);
    }
}

static COMPOSITOR_ENDPOINT: AtomicU64 = AtomicU64::new(0);
static COMPOSITOR_TID: AtomicU64 = AtomicU64::new(0);
static CLIENT_PARAMS: sync::Mutex<[u64; 10]> = sync::Mutex::new([0; 10]);

fn compositor_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::COMPOSITOR_ELF)
        .expect("failed to map the compositor");
    let endpoint = COMPOSITOR_ENDPOINT.load(Ordering::Acquire);
    // SAFETY: load_program mapped the entry user-executable and the stack
    // user-writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, endpoint) }
}

fn client_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::CLIENT_ELF)
        .expect("failed to map the client");

    let params = *CLIENT_PARAMS.lock();
    // SAFETY: `image.data` is the writable data page just mapped for this
    // program, and the program is not running yet.
    unsafe { userspace::write_parameters(image.data, &params) };

    // SAFETY: as in `compositor_thread`.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

fn input_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::INPUT_ELF)
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
    present_at_depth(endpoint, compositor, colour, x, y, 0);
}

/// As `present`, but at a chosen depth.
fn present_at_depth(
    endpoint: EndpointId,
    compositor: ThreadId,
    colour: u64,
    x: u64,
    y: u64,
    z: u64,
) {
    present_full(endpoint, compositor, colour, x, y, z, 0);
}

/// As `present_at_depth`, and if `move_to_x` is non-zero the client presents the
/// same buffer again there.
fn present_full(
    endpoint: EndpointId,
    compositor: ThreadId,
    colour: u64,
    x: u64,
    y: u64,
    z: u64,
    move_to_x: u64,
) {
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
        z,
        move_to_x,
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
fn a_surface_that_moves_far_does_not_repaint_everything_between() {
    let (endpoint, compositor) = start_compositor();

    // A moving surface is the case where damage genuinely spans two distant
    // regions: the hole it left and the place it went. Accumulating that into
    // one bounding box means recomposing the whole span between them, which
    // for a surface crossing the screen is the screen.
    let from_x = 100;
    let to_x = 700;

    // A sentinel written straight into the screen, midway between the two
    // positions and nowhere near either surface. It survives a region list and
    // is cleared by a bounding box.
    let sentinel = (0x5A, 0x6B, 0x7C);
    write_pixel(400, 710, sentinel);
    assert_eq!(pixel_at(400, 710), sentinel, "the sentinel did not take");

    present_full(endpoint, compositor, 0x0000FF, from_x, 700, 0, to_x);

    assert!(
        spin_until(|| pixel_at(to_x as usize + 10, 710) == (0xFF, 0x00, 0x00)),
        "the surface never arrived at its second position"
    );
    assert!(
        spin_until(|| pixel_at(from_x as usize + 10, 710) != (0xFF, 0x00, 0x00)),
        "the surface is still drawn where it used to be"
    );

    assert_eq!(
        pixel_at(400, 710),
        sentinel,
        "a pixel midway between a surface's old and new positions was \
         repainted; damage is one bounding box rather than a region list"
    );
}

static TEAR_STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static TEAR_SAMPLES: AtomicU64 = AtomicU64::new(0);
static TEAR_SEEN_CLEARED: AtomicU64 = AtomicU64::new(0);
static TEAR_X: AtomicU64 = AtomicU64::new(0);
static TEAR_Y: AtomicU64 = AtomicU64::new(0);

/// Watches one pixel from another core for the intermediate state.
///
/// Composition clears a region to black before drawing into it. In the back
/// buffer nobody can see that; done straight into the scanout it is a black
/// flash the display can latch. So "did anyone ever observe black here" is the
/// question, and it is answerable only from a processor that is not the one
/// compositing.
fn tear_watcher() {
    let x = TEAR_X.load(Ordering::Acquire) as usize;
    let y = TEAR_Y.load(Ordering::Acquire) as usize;

    while !TEAR_STOP.load(Ordering::Acquire) {
        let pixel = pixel_at(x, y);
        TEAR_SAMPLES.fetch_add(1, Ordering::Relaxed);
        if pixel == (0x00, 0x00, 0x00) {
            TEAR_SEEN_CLEARED.fetch_add(1, Ordering::Relaxed);
        }
        core::hint::spin_loop();
    }
}

#[test_case]
fn the_display_never_shows_a_half_composed_frame() {
    if smp::online_count() < 2 {
        panda_kernel::serial_println!("  (skipped: needs a second processor to watch from)");
        return;
    }

    let (endpoint, compositor) = start_compositor();

    // Establish a surface, then watch one of its pixels while it is repeatedly
    // recomposed underneath a second surface.
    //
    // Well down the screen and off to the right, because the kernel's own
    // framebuffer console draws test names from the top left and blanks the
    // glyph cells it writes. A watcher sitting in that region catches the
    // console clearing a character cell and reports it as a torn frame -- which
    // it did, once in twenty-three thousand samples, until this moved.
    let x = 820u64;
    let y = 600u64;
    present_at_depth(endpoint, compositor, 0x0000FF, x, y, 1);
    assert!(
        spin_until(|| pixel_at(x as usize + 10, y as usize + 10) == (0xFF, 0x00, 0x00)),
        "the watched surface never appeared"
    );

    TEAR_X.store(x + 10, Ordering::Release);
    TEAR_Y.store(y + 10, Ordering::Release);
    TEAR_STOP.store(false, Ordering::Release);
    TEAR_SAMPLES.store(0, Ordering::Relaxed);
    TEAR_SEEN_CLEARED.store(0, Ordering::Relaxed);

    let watcher = sched::spawn_with_priority(
        "tear-watcher",
        tear_watcher,
        sched::Priority::High,
    )
    .expect("spawn failed");

    // Recompose that exact area several times over, alternating between two
    // colours chosen so that *no* partial pixel write between them can read as
    // black: 0x0000FF is (FF,00,00) and 0x00FFFF is (FF,FF,00), so only the
    // middle byte changes and every intermediate is one of the two.
    //
    // That matters, because the final copy to the scanout is a memcpy and a
    // three-byte pixel is not written atomically. Alternating blue and green
    // -- (FF,00,00) and (00,FF,00) -- lets a reader catch the first byte updated
    // and the second not, which reads as black and looks exactly like the
    // cleared state this is hunting for. Double buffering does not make the
    // flush atomic and was never going to; conflating the two would have this
    // case failing for a reason it does not name.
    // Driven by how much the watcher has actually seen, not by a fixed number
    // of rounds. A busy host gives the watcher less CPU, and a round count tuned
    // on an idle one then fails for want of samples rather than for anything
    // about the compositor -- which is exactly how this first went wrong.
    const WANTED_SAMPLES: u64 = 4_000;
    const MAX_ROUNDS: u64 = 60;

    let mut round = 0;
    while round < MAX_ROUNDS && TEAR_SAMPLES.load(Ordering::Relaxed) < WANTED_SAMPLES {
        let colour = if round % 2 == 0 { 0x00FFFF } else { 0x0000FF };
        present_at_depth(endpoint, compositor, colour, x, y, 2);
        round += 1;
    }

    TEAR_STOP.store(true, Ordering::Release);
    sched::join(watcher);

    let samples = TEAR_SAMPLES.load(Ordering::Relaxed);
    let cleared = TEAR_SEEN_CLEARED.load(Ordering::Relaxed);
    panda_kernel::serial_println!("  ({samples} samples, {cleared} saw the cleared state)");

    assert!(
        samples > 500,
        "only {samples} samples taken over {round} rounds; the watcher barely \
         ran, so seeing nothing proves nothing"
    );
    assert_eq!(
        cleared, 0,
        "a processor watching the screen saw it cleared to black {cleared} \
         times out of {samples} while a surface was being recomposed; \
         composition is reaching the display before it is finished"
    );
}

#[test_case]
fn the_compositor_composes_off_screen() {
    // Composition happens in a buffer the compositor owns and reaches the
    // display in one copy per frame. Drawing surfaces straight into the scanout
    // lets the display controller read the screen halfway through a frame,
    // which with overlapping surfaces is a visible flicker of whatever was
    // underneath.
    //
    // Tearing is not something this can catch from inside the machine. What it
    // can check is that the back buffer exists and is the size of the screen --
    // without which the property is not merely untested but absent.
    let (_, compositor) = start_compositor();

    let screen = framebuffer::info().expect("no framebuffer");
    let owned = gbm::buffers_owned_by(compositor);

    assert!(
        owned.iter().any(|(_, info)| {
            info.width as usize == screen.width && info.height as usize == screen.height
        }),
        "the compositor owns no buffer the size of the screen, so it is drawing \
         straight into the scanout; it has {owned:?}"
    );
}

#[test_case]
fn depth_decides_what_is_on_top_not_arrival_order() {
    let (endpoint, compositor) = start_compositor();

    // The nearer surface arrives *first*. A compositor that simply blits each
    // message as it comes would leave the second one on top, which is the
    // behaviour this replaced.
    present_at_depth(endpoint, compositor, 0x0000FF, 100, 600, 10);
    assert!(
        spin_until(|| pixel_at(110, 610) == (0xFF, 0x00, 0x00)),
        "the near surface never appeared"
    );

    present_at_depth(endpoint, compositor, 0x00FF00, 100, 600, 1);

    // Give the compositor a moment to have got it wrong, so this fails on a
    // real ordering bug rather than on a race with the second client.
    for _ in 0..200 {
        sched::yield_now();
    }

    assert_eq!(
        pixel_at(110, 610),
        (0xFF, 0x00, 0x00),
        "a surface at depth 1 covered one at depth 10; composition is following \
         arrival order rather than z"
    );
}

#[test_case]
fn a_nearer_surface_covers_a_further_one() {
    let (endpoint, compositor) = start_compositor();

    // The other direction, so the case above cannot pass by ignoring the
    // second surface entirely.
    present_at_depth(endpoint, compositor, 0x0000FF, 200, 600, 1);
    assert!(
        spin_until(|| pixel_at(210, 610) == (0xFF, 0x00, 0x00)),
        "the far surface never appeared"
    );

    present_at_depth(endpoint, compositor, 0x00FF00, 200, 600, 5);
    assert!(
        spin_until(|| pixel_at(210, 610) == (0x00, 0xFF, 0x00)),
        "a surface at depth 5 did not cover one at depth 1"
    );
}

#[test_case]
fn only_the_damaged_region_is_written() {
    let (endpoint, compositor) = start_compositor();

    present(endpoint, compositor, 0x0000FF, 300, 600);
    assert!(
        spin_until(|| pixel_at(310, 610) == (0xFF, 0x00, 0x00)),
        "the first surface never appeared"
    );

    // A sentinel written straight into the screen, far from anything the next
    // client will touch. Only the damaged region should be recomposed, so this
    // must survive -- a compositor redrawing the whole screen every frame would
    // erase it.
    let sentinel = (0x11, 0x22, 0x33);
    write_pixel(700, 700, sentinel);
    assert_eq!(pixel_at(700, 700), sentinel, "the sentinel did not take");

    present(endpoint, compositor, 0x00FF00, 300, 650);
    assert!(
        spin_until(|| pixel_at(310, 660) == (0x00, 0xFF, 0x00)),
        "the second surface never appeared"
    );

    assert_eq!(
        pixel_at(700, 700),
        sentinel,
        "a pixel far outside the damaged region was rewritten; the whole screen \
         is being recomposed on every frame"
    );
}

#[test_case]
fn a_surface_that_moves_does_not_leave_a_hole() {
    let (endpoint, compositor) = start_compositor();

    // The same client buffer twice would be ideal, but each client allocates
    // its own. Two surfaces at the same depth, the second overlapping the
    // first, is the same test of whether the damaged region is cleared before
    // recomposition: without the clear, the first surface's pixels stay.
    present_at_depth(endpoint, compositor, 0x0000FF, 400, 600, 3);
    assert!(
        spin_until(|| pixel_at(410, 610) == (0xFF, 0x00, 0x00)),
        "the first surface never appeared"
    );

    present_at_depth(endpoint, compositor, 0x00FF00, 420, 600, 4);
    assert!(
        spin_until(|| pixel_at(430, 610) == (0x00, 0xFF, 0x00)),
        "the second surface never appeared"
    );

    // The part of the first surface the second does not cover must still be
    // there: clearing the damage rectangle must be followed by recomposing
    // every surface that intersects it, not just the newest.
    assert_eq!(
        pixel_at(405, 610),
        (0xFF, 0x00, 0x00),
        "clearing the damaged region wiped a surface that was not replaced"
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
