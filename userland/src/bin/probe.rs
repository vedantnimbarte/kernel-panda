//! Test programs, selected by the argument the kernel passes in.
//!
//! One binary rather than four, because each costs an entry in the kernel image
//! and these differ by a handful of instructions. The kernel picks a mode; the
//! program does exactly that and exits.

#![no_std]
#![no_main]

use panda_user as user;

user::entry!(main);

/// Modes. Must match `kernel/src/userspace.rs`.
pub const MODE_DEMO: u64 = 0;
pub const MODE_TRESPASS: u64 = 1;
pub const MODE_IPC: u64 = 2;
pub const MODE_PEEK: u64 = 3;
pub const MODE_FILES: u64 = 4;
pub const MODE_DEVICE: u64 = 5;
pub const MODE_TFTP: u64 = 6;
pub const MODE_RING_SEND: u64 = 7;
pub const MODE_RING_RECEIVE: u64 = 8;
pub const MODE_RING_FORGE_MESSAGE: u64 = 9;
pub const MODE_RING_MOVE_HEAD: u64 = 10;
pub const MODE_WHOAMI: u64 = 11;
pub const MODE_PERMISSIONS: u64 = 12;
pub const MODE_LOGIN: u64 = 13;
pub const MODE_TCP: u64 = 14;
pub const MODE_RESOLVE: u64 = 15;

/// Parameters for the modes that need more than a mode number.
#[repr(C)]
struct Parameters {
    mode: u64,
    /// Address to read, for TRESPASS and PEEK.
    address: u64,
    /// Endpoint to send on, for IPC. The network daemon's, for TFTP.
    endpoint: u64,
    /// For TFTP: the daemon's thread id, and where to send the result.
    daemon: u64,
    report: u64,
}

extern "C" fn main(parameters: u64) {
    // SAFETY: the kernel fills this page in before entry.
    let parameters = unsafe { &*(parameters as *const Parameters) };

    match parameters.mode {
        MODE_DEMO => {
            user::write("  [ring 3] hello from user space\n");
            user::yield_now();
            user::write("  [ring 3] still running after a yield\n");
        }

        // Both of these must fault. Reaching the write means the boundary they
        // are testing did not hold, so they say so loudly rather than exiting
        // quietly and letting a test pass for the wrong reason.
        MODE_TRESPASS => {
            // SAFETY: deliberately not safe. The address is kernel memory and
            // this must fault; the kernel kills the thread before the read
            // completes.
            let value = unsafe { core::ptr::read_volatile(parameters.address as *const u64) };
            user::write("  [ring 3] READ KERNEL MEMORY -- boundary broken: ");
            user::write_number(value);
            user::write("\n");
        }
        MODE_PEEK => {
            // SAFETY: as above, for an address belonging to another process.
            let value = unsafe { core::ptr::read_volatile(parameters.address as *const u64) };
            user::write("  [ring 3] READ ANOTHER ADDRESS SPACE -- isolation broken: ");
            user::write_number(value);
            user::write("\n");
        }

        // The whole file surface from Ring 3, exercised in one pass. Exits with
        // a code naming the step that failed, so a kernel-side test can say
        // which call broke rather than only that something did.
        MODE_FILES => {
            const PATH: &str = "/ring3-probe";
            const PAYLOAD: &[u8] = b"written from user space";

            if user::file_create(PATH) < 0 {
                user::exit(1);
            }
            if user::file_write(PATH, PAYLOAD) < 0 {
                user::exit(2);
            }

            let mut buffer = [0u8; 64];
            let read = user::file_read(PATH, &mut buffer);
            if read != PAYLOAD.len() as i64 {
                user::exit(3);
            }
            if &buffer[..PAYLOAD.len()] != PAYLOAD {
                user::exit(4);
            }

            let mut size = 0u64;
            if user::file_stat(PATH, &mut size) != 0 || size != PAYLOAD.len() as u64 {
                user::exit(5);
            }

            if user::dir_create("/ring3-dir") < 0 {
                user::exit(6);
            }
            let mut listing = [0u8; 256];
            if user::dir_list("/", &mut listing) <= 0 {
                user::exit(7);
            }

            if user::file_remove(PATH) < 0 {
                user::exit(8);
            }
            // Gone means gone: reading it again has to fail.
            if user::file_read(PATH, &mut buffer) >= 0 {
                user::exit(9);
            }

            user::write("  [ring 3] files: created, wrote, read back, removed\n");
            user::exit(0);
        }

        // Reach for the keyboard controller without having been given it. Every
        // call must be refused; the results go back over IPC so the kernel can
        // see each one rather than only that the program ended.
        MODE_DEVICE => {
            let read = user::port_read(0x60);
            let written = user::port_write(0x60, 0xF4);
            let bound = user::irq_bind(1, parameters.endpoint);
            let sent = user::net_send(&[0u8; 60]);
            let report = user::Message {
                tag: 0xDE,
                words: [read as u64, written as u64, bound as u64, sent as u64],
                sender: 0,
                sender_user: 0,
            };
            user::ipc_send(parameters.endpoint, &report);
        }

        // Fetch a file from QEMU's TFTP server through the network daemon, and
        // report its length and first 24 bytes. Everything is fallible, and a
        // failure is reported as a length of zero with the step that failed.
        MODE_TFTP => {
            let failed = |step: u64| -> ! {
                let report = user::Message { tag: 0x7F7F, words: [0, step, 0, 0], sender: 0, sender_user: 0 };
                user::ipc_send(parameters.report, &report);
                user::exit(1)
            };

            let reply = user::ipc_create(8);
            if reply < 0 || user::ipc_grant(reply as u64, parameters.daemon, 1) < 0 {
                failed(1);
            }
            let reply = reply as u64;

            let receive = user::buffer_create(1024, 1);
            let transmit = user::buffer_create(256, 1);
            if receive < 0 || transmit < 0 {
                failed(2);
            }
            let (receive, transmit) = (receive as u64, transmit as u64);
            if user::buffer_share(receive, parameters.daemon) < 0
                || user::buffer_share(transmit, parameters.daemon) < 0
            {
                failed(3);
            }
            let (receive_base, transmit_base) = (user::buffer_map(receive), user::buffer_map(transmit));
            if receive_base < 0 || transmit_base < 0 {
                failed(4);
            }

            const LOCAL_PORT: u64 = 1069;
            let server = user::net::address(10, 0, 2, 2);
            let send = |tag: u64, words: [u64; 4]| {
                user::ipc_send(parameters.endpoint, &user::Message { tag, words, sender: 0, sender_user: 0 });
            };
            send(user::net::TAG_UDP_BIND, [LOCAL_PORT, reply, receive, 0]);

            // A read request: opcode 1, file name, transfer mode.
            let request = b"\x00\x01hello.txt\x00octet\x00";
            // SAFETY: the transmit buffer is this process's, mapped, and far
            // larger than the request.
            unsafe {
                core::ptr::copy_nonoverlapping(request.as_ptr(), transmit_base as *mut u8, request.len())
            };
            send(
                user::net::TAG_UDP_SEND,
                [transmit, request.len() as u64, server, LOCAL_PORT << 16 | 69],
            );

            let mut message = user::Message::default();
            if user::ipc_receive(reply, &mut message) < 0 || message.tag != user::net::TAG_DATAGRAM {
                failed(5);
            }
            let length = message.words[0] as usize;
            // SAFETY: the receive buffer is mapped, and the daemon wrote
            // `length` bytes of it, never more than its size.
            let datagram = unsafe { core::slice::from_raw_parts(receive_base as *const u8, length) };
            // DATA, block 1.
            if length < 4 || datagram[..4] != [0, 3, 0, 1] {
                failed(6);
            }

            // Acknowledged, so the server does not send it again. The server
            // answers from a port of its own, which is where the ack goes.
            let ack = [0u8, 4, 0, 1];
            // SAFETY: as for the request.
            unsafe { core::ptr::copy_nonoverlapping(ack.as_ptr(), transmit_base as *mut u8, 4) };
            send(
                user::net::TAG_UDP_SEND,
                [transmit, 4, message.words[1], LOCAL_PORT << 16 | message.words[2]],
            );

            let data = &datagram[4..];
            let mut words = [data.len() as u64, 0, 0, 0];
            for (index, byte) in data.iter().take(24).enumerate() {
                words[1 + index / 8] |= (*byte as u64) << (8 * (index % 8));
            }
            user::ipc_send(parameters.report, &user::Message { tag: 0x7F7F, words, sender: 0, sender_user: 0 });
        }

        // One TCP conversation through the network daemon. `address` is a port:
        // with bit 63 set, listen on it; otherwise connect to it on the host,
        // 10.0.2.2. Either way, answer the first line that arrives with
        // "hello from panda", then close once the other side has. Reports the
        // bytes received, their FNV-1a hash, and why the connection ended --
        // or u64::MAX, the reason, and the step, if it never opened.
        MODE_TCP => {
            use user::net;
            let report = |words: [u64; 4]| {
                user::ipc_send(parameters.report, &user::Message { tag: 0x7C7C, words, sender: 0, sender_user: 0 });
                user::exit(0)
            };
            let send = |tag: u64, words: [u64; 4]| {
                user::ipc_send(parameters.endpoint, &user::Message { tag, words, sender: 0, sender_user: 0 });
            };

            let reply = user::ipc_create(8);
            if reply < 0 || user::ipc_grant(reply as u64, parameters.daemon, 1) < 0 {
                report([u64::MAX, 0, 1, 0]);
            }
            let reply = reply as u64;
            let (receive, transmit) = (user::buffer_create(1024, 1), user::buffer_create(256, 1));
            if receive < 0 || transmit < 0 {
                report([u64::MAX, 0, 2, 0]);
            }
            let (receive, transmit) = (receive as u64, transmit as u64);
            if user::buffer_share(receive, parameters.daemon) < 0 || user::buffer_share(transmit, parameters.daemon) < 0 {
                report([u64::MAX, 0, 3, 0]);
            }
            let (receive_base, transmit_base) = (user::buffer_map(receive), user::buffer_map(transmit));
            if receive_base < 0 || transmit_base < 0 {
                report([u64::MAX, 0, 4, 0]);
            }

            let port = parameters.address as u16;
            if parameters.address >> 63 != 0 {
                send(net::TAG_TCP_LISTEN, [port as u64, reply, receive, 0]);
            } else {
                send(net::TAG_TCP_CONNECT, [net::address(10, 0, 2, 2), port as u64, reply, receive]);
            }

            let mut message = user::Message::default();
            if user::ipc_receive(reply, &mut message) < 0 {
                report([u64::MAX, 0, 5, 0]);
            }
            if message.tag != net::TAG_TCP_OPEN {
                report([u64::MAX, message.words[1], 6, 0]);
            }
            let connection = message.words[0];

            let mut received = [0u8; 256];
            let mut total = 0usize;
            let mut answered = false;
            let reason = loop {
                if user::ipc_receive(reply, &mut message) < 0 {
                    report([u64::MAX, 0, 7, 0]);
                }
                match message.tag {
                    net::TAG_TCP_DATA => {
                        let length = message.words[1] as usize;
                        // SAFETY: the daemon wrote `length` bytes at the start of
                        // the mapped receive buffer, never more than its size.
                        let data = unsafe { core::slice::from_raw_parts(receive_base as *const u8, length) };
                        let take = length.min(received.len() - total);
                        received[total..total + take].copy_from_slice(&data[..take]);
                        total += take;
                        send(net::TAG_TCP_CONSUMED, [connection, 0, 0, 0]);

                        if !answered && received[..total].contains(&b'\n') {
                            answered = true;
                            let line = b"hello from panda\n";
                            // SAFETY: this process's mapped buffer, far larger
                            // than the line, which stays put until acknowledged.
                            unsafe { core::ptr::copy_nonoverlapping(line.as_ptr(), transmit_base as *mut u8, line.len()) };
                            send(net::TAG_TCP_SEND, [connection, transmit, line.len() as u64, 0]);
                        }
                    }
                    net::TAG_TCP_SENT if message.words[1] == 0 => report([u64::MAX, 0, 8, 0]),
                    net::TAG_TCP_SENT => {}
                    net::TAG_TCP_CLOSED if message.words[1] == net::CLOSED_PEER_FINISHED => {
                        send(net::TAG_TCP_CLOSE, [connection, 0, 0, 0]);
                    }
                    net::TAG_TCP_CLOSED => break message.words[1],
                    _ => {}
                }
            };

            let hash = received[..total]
                .iter()
                .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| (hash ^ *byte as u64).wrapping_mul(0x0100_0000_01b3));
            report([total as u64, hash, reason, 0]);
        }

        // Look up two names through the network daemon: one the test's DNS
        // server knows, one it does not. Reports each address and status -- or
        // u64::MAX and the step that failed.
        MODE_RESOLVE => {
            use user::net;
            let report = |words: [u64; 4]| {
                user::ipc_send(parameters.report, &user::Message { tag: 0xD45, words, sender: 0, sender_user: 0 });
                user::exit(0)
            };
            let reply = user::ipc_create(4);
            if reply < 0 || user::ipc_grant(reply as u64, parameters.daemon, 1) < 0 {
                report([u64::MAX, 1, 0, 0]);
            }
            let reply = reply as u64;
            let buffer = user::buffer_create(256, 1);
            if buffer < 0 || user::buffer_share(buffer as u64, parameters.daemon) < 0 {
                report([u64::MAX, 2, 0, 0]);
            }
            let base = user::buffer_map(buffer as u64);
            if base < 0 {
                report([u64::MAX, 3, 0, 0]);
            }

            let mut words = [0u64; 4];
            for (index, name) in [&b"panda.test"[..], &b"nowhere.test"[..]].into_iter().enumerate() {
                // SAFETY: this process's mapped buffer, far larger than the name.
                unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), base as *mut u8, name.len()) };
                let request = [buffer as u64, name.len() as u64, reply, index as u64];
                let message = user::Message { tag: net::TAG_RESOLVE, words: request, sender: 0, sender_user: 0 };
                user::ipc_send(parameters.endpoint, &message);

                let mut answer = user::Message::default();
                if user::ipc_receive(reply, &mut answer) < 0 || answer.tag != net::TAG_RESOLVED {
                    report([u64::MAX, 4, 0, 0]);
                }
                words[2 * index] = answer.words[1];
                words[2 * index + 1] = answer.words[2];
            }
            report(words);
        }

        // The two ends of a ring. `endpoint` is the ring, `daemon` the message
        // count, and the result goes to `report`: messages handled, then
        // messages that arrived wrong -- or, if mapping was refused, u64::MAX and
        // the error. A non-zero `address` makes this side dawdle after each
        // message, far longer than the other side spins, so the other side has
        // to sleep and be woken.
        MODE_RING_SEND | MODE_RING_RECEIVE => {
            use user::ring::{Ring, Side};
            let report = |words: [u64; 4]| {
                user::ipc_send(parameters.report, &user::Message { tag: 0x2170, words, sender: 0, sender_user: 0 });
            };
            let side = if parameters.mode == MODE_RING_SEND { Side::Sender } else { Side::Receiver };
            let ring = match Ring::map(parameters.endpoint, side) {
                Ok(ring) => ring,
                Err(error) => {
                    report([u64::MAX, error as u64, 0, 0]);
                    user::exit(1);
                }
            };

            let (mut handled, mut wrong) = (0u64, 0u64);
            let mut slot = [0u8; user::ring::SLOT_BYTES];
            for sequence in 0..parameters.daemon {
                let check = sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                if side == Side::Sender {
                    slot[0..8].copy_from_slice(&sequence.to_le_bytes());
                    slot[8..16].copy_from_slice(&check.to_le_bytes());
                    if !ring.send(&slot) {
                        break;
                    }
                } else {
                    if !ring.receive(&mut slot) {
                        break;
                    }
                    let got = u64::from_le_bytes(slot[0..8].try_into().unwrap_or([0; 8]));
                    let got_check = u64::from_le_bytes(slot[8..16].try_into().unwrap_or([0; 8]));
                    if got != sequence || got_check != check {
                        wrong += 1;
                    }
                }
                handled += 1;
                if parameters.address != 0 {
                    for _ in 0..50_000 {
                        core::hint::spin_loop();
                    }
                }
            }
            report([handled, wrong, 0, 0]);
        }

        // A receiver writing a message, and a sender moving the receiver's
        // position. Both pages are read-only to them, so both must fault, and
        // the report after is only reached if they did not.
        MODE_RING_FORGE_MESSAGE | MODE_RING_MOVE_HEAD => {
            use user::ring::{Ring, Side};
            // Slots start at page 3, the receiver's head is at page 2.
            let (side, offset) = if parameters.mode == MODE_RING_FORGE_MESSAGE {
                (Side::Receiver, 3 * 4096)
            } else {
                (Side::Sender, 2 * 4096)
            };
            let Ok(ring) = Ring::map(parameters.endpoint, side) else {
                user::exit(1);
            };
            // SAFETY: deliberately not safe; the page is read-only and this must
            // fault before the report below.
            unsafe { core::ptr::write_volatile((ring.base() + offset) as *mut u32, 0xBAD) };
            user::ipc_send(parameters.report, &user::Message { tag: 0xBAD, words: [0; 4], sender: 0, sender_user: 0 });
        }

        // Log in as alice, whose password the test set: first wrongly, then
        // rightly. Reports the refusal, the user after it, the login, and the
        // user after that alongside an attempt to read the account database.
        MODE_LOGIN => {
            let wrong = user::login("alice", "not the password");
            let after_wrong = user::user_id();
            let right = user::login("alice", "correct horse battery staple");
            let mut buffer = [0u8; 64];
            let database = user::file_read("/users", &mut buffer);
            let words = [wrong as u64, after_wrong as u64, right as u64, (user::user_id() as u64) << 32 | database as u32 as u64];
            user::ipc_send(parameters.endpoint, &user::Message { tag: 0x0413, words, sender: 0, sender_user: 0 });
        }

        // Report the user this process runs as, to `endpoint`.
        MODE_WHOAMI => {
            let words = [user::user_id() as u64, 0, 0, 0];
            user::ipc_send(parameters.endpoint, &user::Message { tag: 0x0410, words, sender: 0, sender_user: 0 });
        }

        // File permissions as an unprivileged user, through the real system
        // calls. The system has made `/shared`, writable by anyone. Reports:
        // creating at the root, creating in `/shared`, the new file's owner and
        // mode, and changing the mode of `/shared`, which is not this user's.
        MODE_PERMISSIONS => {
            let at_root = user::file_create("/mine");
            let in_shared = user::file_create("/shared/mine");
            // Owner read and write only.
            let private = user::file_chmod("/shared/mine", 0b0011);
            let owner = user::file_owner("/shared/mine");
            let not_mine = user::file_chmod("/shared", 0b1111);
            let words = [at_root as u64, in_shared as u64 | (private as u64) << 32, owner as u64, not_mine as u64];
            user::ipc_send(parameters.endpoint, &user::Message { tag: 0x0412, words, sender: 0, sender_user: 0 });
        }

        MODE_IPC => {
            let message = user::Message {
                tag: 0xCAFE,
                words: [0xBEEF, 0, 0, 0],
                // Lies, so the kernel can be seen to overwrite them.
                sender: 999,
                sender_user: 999,
            };
            let result = user::ipc_send(parameters.endpoint, &message);
            user::exit(result as u64);
        }

        _ => {
            user::write("  [ring 3] unknown probe mode\n");
        }
    }
}
