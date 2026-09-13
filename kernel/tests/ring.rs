//! Rings: two Ring 3 processes sharing a message queue.
//!
//! The claims under test are the ones the design rests on: messages arrive
//! whole and in order, a busy channel needs almost no system calls, a sleeping
//! side is always woken, and each side is confined to the pages it owns.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc::{self, EndpointId, Message, Rights};
use panda_kernel::sched::{self, ThreadId};
use panda_kernel::{
    arch::x86_64::halt_loop, ring, serial_println, sync, syscall, testing, userspace, BOOTLOADER_CONFIG,
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

fn me() -> ThreadId {
    sched::current_id().expect("no thread")
}

fn spin_until(condition: impl Fn() -> bool) -> bool {
    (0..4_000_000_000u64).any(|_| {
        let done = condition();
        core::hint::spin_loop();
        done
    })
}

static PROBE: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

fn probe_thread() {
    // Read before anything else: `spawn_probe` moves on to the next probe once
    // this one has claimed its address space, and that happens inside
    // `load_elf`.
    let [mode, ring, count, report, pace] = [0, 1, 2, 3, 4].map(|index| PROBE[index].load(Ordering::Acquire));
    let owner = me();
    let image = userspace::load_elf(owner, userspace::PROBE_ELF).expect("failed to load the probe");
    // Probe parameters: mode, pace, endpoint, count, report.
    // SAFETY: the parameter page just mapped for a program not yet running.
    unsafe { userspace::write_parameters(image.data, &[mode, pace, ring, count, report]) };
    // SAFETY: load_elf mapped the entry executable and the stack writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

/// Start a probe holding `rights` on the ring and `SEND` on `report`.
fn spawn_probe(mode: u64, ring: EndpointId, count: u64, report: EndpointId, rights: Rights) -> ThreadId {
    spawn_paced_probe(mode, ring, count, report, rights, false)
}

/// As `spawn_probe`, and if `paced` the probe dawdles after every message.
fn spawn_paced_probe(
    mode: u64,
    ring: EndpointId,
    count: u64,
    report: EndpointId,
    rights: Rights,
    paced: bool,
) -> ThreadId {
    for (slot, value) in [mode, ring.0, count, report.0, paced as u64].into_iter().enumerate() {
        PROBE[slot].store(value, Ordering::Release);
    }
    let id = sync::without_interrupts(|| {
        let id = sched::spawn("ring-probe", probe_thread).expect("spawn failed");
        if !rights.is_empty() {
            ipc::grant(me(), id, ring, rights).expect("grant failed");
        }
        ipc::grant(me(), id, report, Rights::SEND).expect("grant failed");
        id
    });
    // The probe reads its parameters first thing; the next spawn must not
    // overwrite them before it has.
    assert!(spin_until(|| !sched::is_alive(id) || userspace::slot_of(id).is_some()));
    id
}

fn report_from(report: EndpointId) -> Message {
    assert!(spin_until(|| ipc::queued(report) > 0), "a probe never reported");
    ipc::receive(me(), report).expect("receive failed")
}

/// Push `count` messages through a ring of `slots`, and return the system calls
/// that took. `pace` slows the sender (`Some(true)`) or the receiver
/// (`Some(false)`) so the other side sleeps.
fn exchange(slots: u32, count: u64, pace: Option<bool>) -> u64 {
    let ring = ring::create(me(), slots).expect("could not create a ring");
    let report = ipc::create(me(), 4).expect("create failed");

    let before = syscall::syscall_count();
    let receiver = spawn_paced_probe(userspace::probe::RING_RECEIVE, ring, count, report, Rights::RECEIVE, pace == Some(false));
    let sender = spawn_paced_probe(userspace::probe::RING_SEND, ring, count, report, Rights::SEND, pace == Some(true));

    let first = report_from(report);
    let second = report_from(report);
    assert!(spin_until(|| !sched::is_alive(sender) && !sched::is_alive(receiver)));
    let calls = syscall::syscall_count() - before;

    for result in [first, second] {
        assert_ne!(result.words[0], u64::MAX, "a probe could not map its side");
        assert_eq!(result.words[0], count, "a side handled {} of {count} messages", result.words[0]);
        assert_eq!(result.words[1], 0, "{} messages arrived wrong or out of order", result.words[1]);
    }
    calls
}

#[test_case]
fn a_busy_ring_needs_almost_no_system_calls() {
    const MESSAGES: u64 = 50_000;
    let calls = exchange(256, MESSAGES, None);
    serial_println!("  ({MESSAGES} messages, {calls} system calls)");
    // An endpoint would need two per message. Mapping, reporting, exiting and
    // the occasional sleep are all a ring should cost.
    assert!(
        calls < MESSAGES / 10,
        "{calls} system calls for {MESSAGES} messages; the ring is not avoiding the kernel"
    );
}

#[test_case]
fn a_sleeping_side_is_always_woken() {
    // A side that keeps up spins rather than sleeps, so each side in turn is
    // made to wait on a slow partner: first the receiver on a dawdling sender,
    // then the sender on a dawdling receiver, filling two slots at once. A
    // single lost wake parks one side forever, and this never finishes.
    const MESSAGES: u64 = 1_000;
    for (pace, sleeper) in [(true, "receiver"), (false, "sender")] {
        let calls = exchange(2, MESSAGES, Some(pace));
        serial_println!("  (the {sleeper} waited: {MESSAGES} messages, {calls} system calls)");
        // Each wait is a system call on one side and a wake on the other. Far
        // fewer means the side never slept, and nothing was tested.
        assert!(
            calls > MESSAGES,
            "only {calls} system calls; the {sleeper} did not sleep, so the wake path went unexercised"
        );
    }
}

#[test_case]
fn a_receiver_cannot_write_a_message() {
    let ring = ring::create(me(), 16).expect("could not create a ring");
    let report = ipc::create(me(), 4).expect("create failed");
    let probe = spawn_probe(userspace::probe::RING_FORGE_MESSAGE, ring, 0, report, Rights::RECEIVE);
    assert!(spin_until(|| !sched::is_alive(probe)), "the probe never finished");
    assert_eq!(ipc::queued(report), 0, "a receiver wrote into the slots and lived");
}

#[test_case]
fn a_sender_cannot_move_the_receivers_position() {
    let ring = ring::create(me(), 16).expect("could not create a ring");
    let report = ipc::create(me(), 4).expect("create failed");
    let probe = spawn_probe(userspace::probe::RING_MOVE_HEAD, ring, 0, report, Rights::SEND);
    assert!(spin_until(|| !sched::is_alive(probe)), "the probe never finished");
    assert_eq!(ipc::queued(report), 0, "a sender wrote the receiver's head and lived");
}

#[test_case]
fn a_ring_has_one_sender_and_no_uninvited_ones() {
    let ring = ring::create(me(), 16).expect("could not create a ring");
    let report = ipc::create(me(), 4).expect("create failed");

    // This thread takes the sending side first.
    ring::map(me(), ring, ring::Side::Sender).expect("the owner could not map its ring");

    // A second sender, properly granted, is still refused: two writers on one
    // unlocked counter would corrupt it.
    spawn_probe(userspace::probe::RING_SEND, ring, 1, report, Rights::SEND);
    let refused = report_from(report);
    assert_eq!(refused.words[0], u64::MAX, "a second sender mapped the ring");
    assert_eq!(refused.words[1], syscall::Error::AlreadyExists as i64 as u64);

    // And a thread holding nothing gets nothing.
    spawn_probe(userspace::probe::RING_RECEIVE, ring, 1, report, Rights::NONE);
    let uninvited = report_from(report);
    assert_eq!(uninvited.words[0], u64::MAX, "a thread with no rights mapped the ring");
    assert_eq!(uninvited.words[1], syscall::Error::NoCapability as i64 as u64);
}
