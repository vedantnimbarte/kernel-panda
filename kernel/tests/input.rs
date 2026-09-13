//! The PS/2 driver, in Ring 3.
//!
//! Bytes go in through the keyboard controller itself -- its "write output
//! buffer" commands raise the real interrupt line -- so what these cases see
//! has come through the I/O APIC, the kernel's notification, the grant checks on
//! every port access, and the driver's decoding.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc::{self, EndpointId, Message, Rights};
use panda_kernel::sched::ThreadId;
use panda_kernel::{
    arch::x86_64::halt_loop, device, sched, sync, syscall, testing, userspace, BOOTLOADER_CONFIG,
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

const TAG_SHUTDOWN: u64 = 0;
const TAG_KEY: u64 = 1;
const TAG_POINTER: u64 = 3;
const SHIFT: u64 = 1;

fn spin_until(condition: impl Fn() -> bool) -> bool {
    (0..2_000_000_000u64).any(|_| {
        let done = condition();
        core::hint::spin_loop();
        done
    })
}

fn me() -> ThreadId {
    sched::current_id().expect("no current thread")
}

static CONSUMER: AtomicU64 = AtomicU64::new(0);

fn input_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::INPUT_ELF)
        .expect("failed to map the input daemon");
    // SAFETY: load_elf mapped the entry user-executable and the stack
    // user-writable.
    unsafe {
        userspace::enter_ring3(image.entry, image.stack_top, CONSUMER.load(Ordering::Acquire))
    }
}

fn device_probe_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_probe(owner, userspace::probe::DEVICE, CONSUMER.load(Ordering::Acquire))
        .expect("failed to load the probe");
    // SAFETY: load_probe mapped the entry user-executable, the stack
    // user-writable, and filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

/// A driver with the controller granted, parked waiting for its first
/// interrupt, and an endpoint this thread reads its events from.
fn start_daemon() -> (EndpointId, ThreadId) {
    let consumer = ipc::create(me(), 32).expect("create failed");
    CONSUMER.store(consumer.0, Ordering::Release);

    let daemon = sync::without_interrupts(|| {
        let id = sched::spawn("input", input_thread).expect("spawn failed");
        ipc::grant(me(), id, consumer, Rights::SEND).expect("grant failed");
        device::grant_ps2_controller(id);
        id
    });
    assert!(
        spin_until(|| sched::is_blocked(daemon) || !sched::is_alive(daemon)),
        "the input daemon never settled"
    );
    assert!(
        sched::is_alive(daemon),
        "the input daemon died starting up; the controller or its grants are missing"
    );
    (consumer, daemon)
}

fn keyboard(byte: u8) {
    assert!(
        testing::inject_ps2(false, byte),
        "keyboard byte {byte:#04x} was never read; the interrupt did not reach the driver"
    );
}

fn mouse(byte: u8) {
    assert!(
        testing::inject_ps2(true, byte),
        "mouse byte {byte:#04x} was never read; the interrupt did not reach the driver"
    );
}

fn next(consumer: EndpointId) -> Message {
    assert!(
        spin_until(|| ipc::queued(consumer) > 0),
        "the driver sent nothing"
    );
    ipc::receive(me(), consumer).expect("receive failed")
}

/// Escape ends the session: a shutdown goes out, and the driver exits.
fn stop(consumer: EndpointId, daemon: ThreadId) {
    keyboard(0x01);
    assert_eq!(next(consumer).tag, TAG_SHUTDOWN, "escape did not send a shutdown");
    assert!(
        spin_until(|| !sched::is_alive(daemon)),
        "the input daemon did not exit on escape"
    );
}

#[test_case]
fn a_process_without_grants_cannot_reach_the_controller() {
    let consumer = ipc::create(me(), 4).expect("create failed");
    CONSUMER.store(consumer.0, Ordering::Release);

    sync::without_interrupts(|| {
        let id = sched::spawn("device-probe", device_probe_thread).expect("spawn failed");
        ipc::grant(me(), id, consumer, Rights::SEND).expect("grant failed");
    });

    let report = next(consumer);
    let refused = syscall::Error::NoCapability as i64 as u64;
    assert_eq!(report.words[0], refused, "an ungranted process read a port");
    assert_eq!(report.words[1], refused, "an ungranted process wrote a port");
    assert_eq!(
        report.words[2], refused,
        "an ungranted process bound an interrupt line"
    );
}

#[test_case]
fn keys_arrive_decoded_from_the_controller() {
    let (consumer, daemon) = start_daemon();

    keyboard(0x1E);
    let press = next(consumer);
    assert_eq!(press.tag, TAG_KEY, "not a key event");
    assert_eq!(press.words, [b'a' as u64, 0x1E, 1, 0], "the A key pressed");
    assert_eq!(press.sender, daemon.0 as u64, "the event did not come from the driver");

    keyboard(0x9E);
    assert_eq!(next(consumer).words, [0, 0x1E, 0, 0], "the A key released");

    // Shift held changes the character and is reported as a modifier.
    keyboard(0x2A);
    assert_eq!(next(consumer).words, [0, 0x2A, 1, SHIFT], "shift pressed");
    keyboard(0x1E);
    assert_eq!(next(consumer).words, [b'A' as u64, 0x1E, 1, SHIFT], "shifted A");
    keyboard(0xAA);
    assert_eq!(next(consumer).words, [0, 0x2A, 0, 0], "shift released");

    // An E0-prefixed key comes out as one event with its own code, and a key
    // with no character carries none.
    keyboard(0xE0);
    keyboard(0x48);
    assert_eq!(next(consumer).words, [0, 0x148, 1, 0], "the up arrow");
    keyboard(0x3B);
    assert_eq!(next(consumer).words, [0, 0x3B, 1, 0], "F1 was passed off as text");

    stop(consumer, daemon);
}

#[test_case]
fn mouse_packets_become_pointer_events() {
    let (consumer, daemon) = start_daemon();

    // Left button, right 5, and a PS/2 dy of -3 -- which is down the screen.
    mouse(0x29);
    mouse(0x05);
    mouse(0xFD);
    let packet = next(consumer);
    assert_eq!(packet.tag, TAG_POINTER, "not a pointer event");
    assert_eq!(packet.words, [5, 3, 1, 0], "the packet decoded wrongly");

    // A stray byte without the sync bit is dropped, and the packet after it
    // still decodes.
    mouse(0x00);
    mouse(0x18);
    mouse(0xFE);
    mouse(0x00);
    assert_eq!(
        next(consumer).words,
        [(-2i64) as u64, 0, 0, 0],
        "a lost byte put the packets out of step"
    );

    stop(consumer, daemon);
}

#[test_case]
fn a_process_exiting_while_another_loads_does_not_disturb_either() {
    // One process's exit overlapping the next one's start, again and again. The
    // exit used to free the page tables its own processor was still translating
    // through, and the loading process -- handed the same frame -- cleared it
    // underneath: a reset, with nothing on the console.
    let probe_endpoint = ipc::create(me(), 4).expect("create failed");
    let daemon_endpoint = ipc::create(me(), 32).expect("create failed");

    for _ in 0..15 {
        CONSUMER.store(probe_endpoint.0, Ordering::Release);
        sync::without_interrupts(|| {
            let id = sched::spawn("device-probe", device_probe_thread).expect("spawn failed");
            ipc::grant(me(), id, probe_endpoint, Rights::SEND).expect("grant failed");
        });
        // The probe reports and exits; the driver starts before it has gone.
        next(probe_endpoint);

        CONSUMER.store(daemon_endpoint.0, Ordering::Release);
        let daemon = sync::without_interrupts(|| {
            let id = sched::spawn("input", input_thread).expect("spawn failed");
            ipc::grant(me(), id, daemon_endpoint, Rights::SEND).expect("grant failed");
            device::grant_ps2_controller(id);
            id
        });
        assert!(
            spin_until(|| sched::is_blocked(daemon) || !sched::is_alive(daemon)),
            "the input daemon never settled"
        );
        assert!(sched::is_alive(daemon), "the input daemon died starting up");

        keyboard(0x1E);
        assert_eq!(next(daemon_endpoint).words[1], 0x1E, "the driver decoded the wrong key");
        stop(daemon_endpoint, daemon);
    }
}
