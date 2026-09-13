//! The network card, below any protocol stack.
//!
//! The harness attaches a virtio-net card to QEMU's user-mode network, whose
//! gateway at 10.0.2.2 answers ARP. These cases put frames on the wire from
//! Ring 0 and check what comes back -- and that it comes back by interrupt.

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
fn the_card_was_found_with_qemus_mac() {
    // QEMU's default for the first card. A different value means the
    // configuration was read from the wrong offset -- with MSI-X on, it moves.
    assert_eq!(
        net::mac(),
        Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
        "no card, or its MAC was read from the wrong place"
    );
}

#[test_case]
fn the_gateway_answers_arp_and_the_answer_arrives_by_interrupt() {
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
