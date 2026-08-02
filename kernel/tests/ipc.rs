//! Capability-mediated IPC.
//!
//! Two properties carry the weight here: that naming an endpoint is not
//! permission to use it, and that authority can only ever narrow as it is passed
//! along. Both are the kind of thing that works in the happy path of a demo and
//! is wide open the moment anyone probes it.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc::{self, EndpointId, Message, Rights};
use panda_kernel::sched::ThreadId;
use panda_kernel::syscall::Error;
use panda_kernel::{arch::x86_64::halt_loop, sched, sync, testing, userspace, BOOTLOADER_CONFIG};

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
fn creating_an_endpoint_grants_the_owner_everything() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    let rights = ipc::rights_of(me(), endpoint);

    assert!(rights.contains(Rights::SEND));
    assert!(rights.contains(Rights::RECEIVE));
    assert!(rights.contains(Rights::GRANT));
}

#[test_case]
fn a_round_trip_preserves_the_payload() {
    let endpoint = ipc::create(me(), 4).expect("create failed");

    ipc::send(
        me(),
        endpoint,
        Message {
            tag: 0xABCD,
            words: [1, 2, 3, 4],
            sender: 0,
        },
    )
    .expect("send failed");

    let message = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(message.tag, 0xABCD);
    assert_eq!(message.words, [1, 2, 3, 4]);
}

#[test_case]
fn the_kernel_stamps_the_real_sender() {
    let endpoint = ipc::create(me(), 4).expect("create failed");

    ipc::send(
        me(),
        endpoint,
        Message {
            tag: 1,
            words: [0; 4],
            // A lie. The kernel must overwrite it, or a receiver cannot use the
            // field for authentication.
            sender: 0xDEAD_BEEF,
        },
    )
    .expect("send failed");

    let message = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(
        message.sender,
        me().0 as u64,
        "the sender field was not overwritten by the kernel"
    );
}

#[test_case]
fn messages_come_back_in_order() {
    let endpoint = ipc::create(me(), 8).expect("create failed");

    for n in 0..5u64 {
        ipc::send(
            me(),
            endpoint,
            Message {
                tag: n,
                words: [n; 4],
                sender: 0,
            },
        )
        .expect("send failed");
    }

    for n in 0..5u64 {
        let message = ipc::receive(me(), endpoint).expect("receive failed");
        assert_eq!(message.tag, n, "messages were reordered");
    }
}

#[test_case]
fn a_full_queue_is_refused_rather_than_growing() {
    let endpoint = ipc::create(me(), 2).expect("create failed");

    for _ in 0..2 {
        ipc::send(me(), endpoint, Message::default()).expect("send failed");
    }

    assert_eq!(
        ipc::send(me(), endpoint, Message::default()),
        Err(Error::QueueFull),
        "an endpoint accepted more than its capacity, so a sender can make the \
         kernel allocate without limit"
    );
}

// --- capability enforcement -------------------------------------------------

static SHARED_ENDPOINT: AtomicU64 = AtomicU64::new(0);
static UNAUTHORISED_RESULT: AtomicU64 = AtomicU64::new(0);
static UNAUTHORISED_RAN: AtomicBool = AtomicBool::new(false);

/// Holds no capability at all, and tries to send anyway.
fn unauthorised_sender() {
    let endpoint = EndpointId(SHARED_ENDPOINT.load(Ordering::Acquire));
    let result = ipc::send(me(), endpoint, Message::default());
    UNAUTHORISED_RESULT.store(
        match result {
            Err(Error::NoCapability) => 1,
            Err(_) => 2,
            Ok(()) => 3,
        },
        Ordering::Release,
    );
    UNAUTHORISED_RAN.store(true, Ordering::Release);
}

#[test_case]
fn sending_without_a_capability_is_refused() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    SHARED_ENDPOINT.store(endpoint.0, Ordering::Release);
    UNAUTHORISED_RAN.store(false, Ordering::Release);

    sched::spawn("no-caps", unauthorised_sender).expect("spawn failed");
    assert!(
        spin_until(|| UNAUTHORISED_RAN.load(Ordering::Acquire)),
        "the unauthorised sender never ran"
    );

    assert_eq!(
        UNAUTHORISED_RESULT.load(Ordering::Acquire),
        1,
        "a thread holding no capability was able to send; knowing an endpoint id \
         must not be authority to use it"
    );
    assert_eq!(
        ipc::queued(endpoint),
        0,
        "the refused message was queued anyway"
    );
}

static GRANT_ENDPOINT: AtomicU64 = AtomicU64::new(0);
static GRANT_OUTCOME: AtomicU64 = AtomicU64::new(0);
static GRANT_RAN: AtomicBool = AtomicBool::new(false);

/// Holds SEND only, and tries to pass RECEIVE to itself.
fn escalation_attempt() {
    let endpoint = EndpointId(GRANT_ENDPOINT.load(Ordering::Acquire));
    let result = ipc::grant(me(), me(), endpoint, Rights::RECEIVE);
    GRANT_OUTCOME.store(
        match result {
            Err(Error::NoCapability) => 1,
            Err(_) => 2,
            Ok(()) => 3,
        },
        Ordering::Release,
    );
    GRANT_RAN.store(true, Ordering::Release);
}

#[test_case]
fn a_thread_cannot_grant_rights_it_does_not_hold() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    GRANT_ENDPOINT.store(endpoint.0, Ordering::Release);
    GRANT_RAN.store(false, Ordering::Release);

    let thread = sync::without_interrupts(|| {
        let id = sched::spawn("escalate", escalation_attempt).expect("spawn failed");
        // SEND only: no GRANT, and no RECEIVE.
        ipc::grant(me(), id, endpoint, Rights::SEND).expect("grant failed");
        id
    });

    assert!(
        spin_until(|| GRANT_RAN.load(Ordering::Acquire)),
        "the escalating thread never ran"
    );
    assert_eq!(
        GRANT_OUTCOME.load(Ordering::Acquire),
        1,
        "a thread without GRANT was able to hand itself new rights"
    );
    assert!(
        !ipc::rights_of(thread, endpoint).contains(Rights::RECEIVE),
        "the escalation actually took effect"
    );
}

#[test_case]
fn granting_cannot_widen_authority() {
    let endpoint = ipc::create(me(), 4).expect("create failed");

    // The owner holds everything, so grant a deliberately narrow subset.
    let target = sched::spawn("narrow", || {}).expect("spawn failed");
    ipc::grant(me(), target, endpoint, Rights::SEND).expect("grant failed");

    let rights = ipc::rights_of(target, endpoint);
    assert!(rights.contains(Rights::SEND));
    assert!(
        !rights.contains(Rights::RECEIVE),
        "a grant of SEND alone also conveyed RECEIVE"
    );
    assert!(
        !rights.contains(Rights::GRANT),
        "a grant of SEND alone also conveyed GRANT"
    );
}

#[test_case]
fn unknown_right_bits_are_discarded() {
    // A user-supplied integer must never turn into authority that does not
    // exist.
    let rights = Rights::from_bits_truncate(u64::MAX);
    assert_eq!(
        rights.bits(),
        Rights::SEND
            .union(Rights::RECEIVE)
            .union(Rights::GRANT)
            .bits(),
        "bits outside the defined rights survived truncation"
    );
}

// --- blocking ---------------------------------------------------------------

static BLOCK_ENDPOINT: AtomicU64 = AtomicU64::new(0);
static RECEIVER_ID: AtomicUsize = AtomicUsize::new(0);
static RECEIVER_WAS_BLOCKED: AtomicBool = AtomicBool::new(false);

/// Waits for the receiver to actually park before sending, and records that it
/// saw it happen.
fn observing_sender() {
    let receiver = ThreadId(RECEIVER_ID.load(Ordering::Acquire));

    for _ in 0..SPIN_BUDGET {
        if sched::is_blocked(receiver) {
            RECEIVER_WAS_BLOCKED.store(true, Ordering::Release);
            break;
        }
        core::hint::spin_loop();
    }

    let endpoint = EndpointId(BLOCK_ENDPOINT.load(Ordering::Acquire));
    ipc::send(
        me(),
        endpoint,
        Message {
            tag: 0x77,
            words: [7, 0, 0, 0],
            sender: 0,
        },
    )
    .expect("send failed");
}

#[test_case]
fn receive_parks_the_thread_until_a_message_arrives() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    BLOCK_ENDPOINT.store(endpoint.0, Ordering::Release);
    RECEIVER_ID.store(me().0, Ordering::Release);
    RECEIVER_WAS_BLOCKED.store(false, Ordering::Release);

    sync::without_interrupts(|| {
        let id = sched::spawn("observing-sender", observing_sender).expect("spawn failed");
        ipc::grant(me(), id, endpoint, Rights::SEND).expect("grant failed");
    });

    // Nothing is queued, so this must park rather than spin.
    let message = ipc::receive(me(), endpoint).expect("receive failed");

    assert_eq!(message.tag, 0x77);
    assert_eq!(message.words[0], 7);
    assert!(
        RECEIVER_WAS_BLOCKED.load(Ordering::Acquire),
        "the sender never observed the receiver in a blocked state, so receive \
         was busy-waiting rather than sleeping"
    );
}

#[test_case]
fn try_receive_does_not_block_on_an_empty_endpoint() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    assert_eq!(
        ipc::try_receive(me(), endpoint),
        Ok(None),
        "try_receive should report emptiness rather than wait"
    );
}

// --- end to end through Ring 3 ----------------------------------------------

static USER_ENDPOINT: AtomicU64 = AtomicU64::new(0);

fn ring3_sender() {
    let slot = sched::current_id().map_or(0, |id| id.0 as u64);
    let image = userspace::load_program(slot, userspace::ipc_program())
        .expect("failed to map user image");
    let endpoint = USER_ENDPOINT.load(Ordering::Acquire);
    // SAFETY: load_program mapped the entry user-executable and the stack
    // user-writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, endpoint) }
}

#[test_case]
fn a_ring3_process_can_send_through_a_granted_capability() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    USER_ENDPOINT.store(endpoint.0, Ordering::Release);

    let user = sync::without_interrupts(|| {
        let id = sched::spawn("user-ipc", ring3_sender).expect("spawn failed");
        ipc::grant(me(), id, endpoint, Rights::SEND).expect("grant failed");
        id
    });

    assert!(
        spin_until(|| ipc::queued(endpoint) > 0),
        "no message arrived from the Ring 3 process"
    );

    let message = ipc::receive(me(), endpoint).expect("receive failed");
    assert_eq!(message.tag, 0xCAFE, "wrong tag from user space");
    assert_eq!(message.words[0], 0xBEEF, "wrong payload from user space");
    assert_eq!(
        message.sender,
        user.0 as u64,
        "the sender field was not replaced with the real Ring 3 sender -- the \
         user program wrote 999 into it"
    );
}
