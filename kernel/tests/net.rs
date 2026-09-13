//! The network card, below any protocol stack.
//!
//! The harness attaches a virtio-net card to QEMU's user-mode network, whose
//! gateway at 10.0.2.2 answers ARP. These cases put frames on the wire from
//! Ring 0 and check what comes back -- and that it comes back by interrupt.
//! Then the Ring 3 stack is started on top.
//!
//! Cases run in name order, and that order matters here: the card cases bind
//! arrivals to themselves, so they are named to run before the stack starts
//! and binds them to it.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc;
use panda_kernel::net;
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

const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

fn spin_until(condition: impl Fn() -> bool) -> bool {
    (0..2_000_000_000u64).any(|_| {
        let done = condition();
        core::hint::spin_loop();
        done
    })
}

/// A broadcast "who has 10.0.2.2?" from this card.
fn arp_request(mac: [u8; 6]) -> [u8; 42] {
    let mut frame = [0u8; 42];
    frame[0..6].fill(0xFF);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1u16.to_be_bytes()); // request
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&GUEST_IP);
    frame[38..42].copy_from_slice(&GATEWAY_IP);
    frame
}

#[test_case]
fn card_was_found_with_qemus_mac() {
    // QEMU's default for the first card. A different value means the
    // configuration was read from the wrong offset -- with MSI-X on, it moves.
    assert_eq!(
        net::mac(),
        Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
        "no card, or its MAC was read from the wrong place"
    );
}

#[test_case]
fn card_gets_the_gateways_arp_answer_by_interrupt() {
    let mac = net::mac().expect("no card");
    let me = sched::current_id().expect("no thread");
    let endpoint = ipc::create(me, 8).expect("create failed");
    net::bind(endpoint);

    // Anything already waiting is somebody else's.
    let mut frame = [0u8; net::MAX_FRAME];
    while let Ok(Some(_)) = net::receive(&mut frame) {}
    while ipc::try_receive(me, endpoint).ok().flatten().is_some() {}

    net::send(&arp_request(mac)).expect("send failed");

    assert!(
        spin_until(|| ipc::queued(endpoint) > 0),
        "nothing was announced; the receive interrupt is not arriving"
    );
    let notification = ipc::receive(me, endpoint).expect("receive failed");
    assert_eq!(notification.sender, ipc::KERNEL_SENDER, "not from the kernel");

    // The reply is among whatever arrived.
    let mut replied = false;
    for _ in 0..16 {
        let Ok(Some(length)) = net::receive(&mut frame) else {
            break;
        };
        let is_arp_reply = length >= 42
            && frame[12..14] == 0x0806u16.to_be_bytes()
            && frame[20..22] == 2u16.to_be_bytes();
        if is_arp_reply {
            assert_eq!(frame[28..32], GATEWAY_IP, "the reply is for another address");
            assert_eq!(frame[32..38], mac, "the reply was not addressed to this card");
            replied = true;
            break;
        }
    }
    assert!(replied, "frames arrived but none was the gateway's ARP reply");
}

// ---------------------------------------------------------------------------
// The Ring 3 stack on top
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU64, Ordering};
use panda_kernel::ipc::{EndpointId, Message, Rights};
use panda_kernel::sched::ThreadId;
use panda_kernel::{sync, syscall, userspace};

const TAG_PING: u64 = 1;
const TAG_PONG: u64 = 2;

const fn packed(address: [u8; 4]) -> u64 {
    u32::from_be_bytes(address) as u64
}

fn me() -> ThreadId {
    sched::current_id().expect("no thread")
}

static CONTROL: AtomicU64 = AtomicU64::new(0);
static STACK: AtomicU64 = AtomicU64::new(u64::MAX);
static PROBE: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

fn stack_thread() {
    let owner = me();
    let image = userspace::load_elf(owner, userspace::NET_ELF).expect("failed to load the stack");
    let parameters = [
        CONTROL.load(Ordering::Acquire),
        packed(GUEST_IP),
        packed(GATEWAY_IP),
        packed([255, 255, 255, 0]),
    ];
    // SAFETY: the parameter page just mapped for a program not yet running.
    unsafe { userspace::write_parameters(image.data, &parameters) };
    // SAFETY: load_elf mapped the entry executable and the stack writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

/// The network daemon, running once for the whole test kernel: it is the only
/// thread allowed the card, and later cases reuse it.
fn stack() -> (EndpointId, ThreadId) {
    if let Some(id) = Some(STACK.load(Ordering::Acquire)).filter(|id| *id != u64::MAX) {
        return (EndpointId(CONTROL.load(Ordering::Acquire)), ThreadId(id as usize));
    }

    let control = ipc::create(me(), 32).expect("create failed");
    CONTROL.store(control.0, Ordering::Release);
    let daemon = sync::without_interrupts(|| {
        let id = sched::spawn("net", stack_thread).expect("spawn failed");
        ipc::grant(me(), id, control, Rights::SEND.union(Rights::RECEIVE)).expect("grant failed");
        net::allow_stack(id);
        id
    });
    assert!(
        spin_until(|| sched::is_blocked(daemon) || !sched::is_alive(daemon)),
        "the network daemon never settled"
    );
    assert!(sched::is_alive(daemon), "the network daemon died starting up");
    STACK.store(daemon.0 as u64, Ordering::Release);
    (control, daemon)
}

fn probe_thread() {
    let owner = me();
    let image = userspace::load_elf(owner, userspace::PROBE_ELF).expect("failed to load the probe");
    let [mode, first, second] = [0, 1, 2].map(|index| PROBE[index].load(Ordering::Acquire));
    let (daemon, report) = (STACK.load(Ordering::Acquire), second);
    // Probe parameters: mode, address, endpoint, daemon, report.
    // SAFETY: the parameter page just mapped for a program not yet running.
    unsafe { userspace::write_parameters(image.data, &[mode, 0, first, daemon, report]) };
    // SAFETY: as in `stack_thread`.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

#[test_case]
fn stack_pings_the_gateway() {
    let (control, daemon) = stack();
    let reply = ipc::create(me(), 4).expect("create failed");
    ipc::grant(me(), daemon, reply, Rights::SEND).expect("grant failed");

    let request = Message {
        tag: TAG_PING,
        words: [packed(GATEWAY_IP), reply.0, 0xC0FFEE, 0],
        sender: 0,
        sender_user: 0,
    };
    ipc::send(me(), control, request).expect("send failed");

    assert!(
        spin_until(|| ipc::queued(reply) > 0),
        "no echo reply came back from the gateway"
    );
    let pong = ipc::receive(me(), reply).expect("receive failed");
    assert_eq!(pong.tag, TAG_PONG, "not a pong");
    assert_eq!(pong.words[0], 0xC0FFEE, "the pong carries the wrong token");
    assert_eq!(pong.words[1], packed(GATEWAY_IP), "the pong is from the wrong address");
    assert_eq!(pong.sender, daemon.0 as u64, "the pong did not come from the daemon");
}

#[test_case]
fn stack_serves_a_process_fetching_a_file_over_udp() {
    let (control, _) = stack();
    let report = ipc::create(me(), 4).expect("create failed");

    PROBE[0].store(userspace::probe::TFTP, Ordering::Release);
    PROBE[1].store(control.0, Ordering::Release);
    PROBE[2].store(report.0, Ordering::Release);
    sync::without_interrupts(|| {
        let id = sched::spawn("tftp-probe", probe_thread).expect("spawn failed");
        ipc::grant(me(), id, control, Rights::SEND).expect("grant failed");
        ipc::grant(me(), id, report, Rights::SEND).expect("grant failed");
    });

    assert!(spin_until(|| ipc::queued(report) > 0), "the probe reported nothing");
    let result = ipc::receive(me(), report).expect("receive failed");

    // Must match what xtask writes into the TFTP directory.
    const EXPECTED: &[u8] = b"hello from the host, over TFTP\n";
    assert_eq!(
        result.words[0],
        EXPECTED.len() as u64,
        "the probe got {} bytes (failed at step {} if zero)",
        result.words[0],
        result.words[1]
    );
    let mut first = [0u8; 24];
    for (index, byte) in first.iter_mut().enumerate() {
        *byte = (result.words[1 + index / 8] >> (8 * (index % 8))) as u8;
    }
    assert_eq!(&first, &EXPECTED[..24], "the file's contents came back wrong");
}

#[test_case]
fn stack_is_the_only_process_that_can_send_frames() {
    stack();
    let report = ipc::create(me(), 4).expect("create failed");
    PROBE[0].store(userspace::probe::DEVICE, Ordering::Release);
    PROBE[1].store(report.0, Ordering::Release);
    PROBE[2].store(0, Ordering::Release);
    sync::without_interrupts(|| {
        let id = sched::spawn("device-probe", probe_thread).expect("spawn failed");
        ipc::grant(me(), id, report, Rights::SEND).expect("grant failed");
    });

    assert!(spin_until(|| ipc::queued(report) > 0), "the probe reported nothing");
    let result = ipc::receive(me(), report).expect("receive failed");
    assert_eq!(
        result.words[3],
        syscall::Error::NoCapability as i64 as u64,
        "a process other than the stack put a frame on the wire"
    );
}
