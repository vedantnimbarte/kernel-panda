//! The network daemon: ARP, IPv4, ICMP, UDP and TCP, in Ring 3.
//!
//! The kernel hands this process Ethernet frames and nothing else, so every
//! byte that arrives from the network is parsed here, by a process with no
//! privilege. A malformed packet that trips a bug in this file kills this
//! file's process.
//!
//! No allocator, so every table is a fixed array and running out is a dropped
//! packet rather than a crash:
//!
//! * **ARP**: a small cache of address to MAC, answering requests for this
//!   machine's address. A frame for an address not yet resolved waits in one of
//!   a few slots while the request goes out.
//! * **IPv4**: one address, a gateway for everything off the local network, no
//!   fragments, no options.
//! * **ICMP**: echo requests are answered; echo replies are matched to pings a
//!   client asked for.
//! * **UDP**: a client binds a port to a buffer it shares, and sends by naming a
//!   buffer. Checksums are not sent -- IPv4 allows that -- and not checked.
//! * **TCP**: connections opened and accepted, one segment in flight each way.
//!   A client's send waits for its acknowledgement before the next, and the
//!   receive side takes one segment into the client's buffer and closes its
//!   window until the client has read it. Unacknowledged segments are resent on
//!   a timer, backing off, until a connection gives up.

#![no_std]
#![no_main]

use panda_user::{self as user, net};

user::entry!(main);

#[repr(C)]
struct Parameters {
    /// Commands arrive here, and so do the kernel's arrival notifications.
    control: u64,
    address: u64,
    gateway: u64,
    netmask: u64,
}

const MAX_FRAME: usize = 1514;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_UDP: u8 = 17;
const PROTOCOL_TCP: u8 = 6;
const BROADCAST: [u8; 6] = [0xFF; 6];

/// Identifier stamped on every echo request this daemon sends.
const PING_IDENTIFIER: u16 = 0x5044;

const ARP_ENTRIES: usize = 8;
const WAITING_FRAMES: usize = 2;
const PINGS: usize = 8;
const BINDINGS: usize = 8;
const MAPPINGS: usize = 8;
const CONNECTIONS: usize = 8;
const LISTENERS: usize = 4;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// The resend timer's period, and the first resend's wait in its ticks.
const TICK_MS: u64 = 200;
const FIRST_RTO_TICKS: u32 = 5;
const MAX_RTO_TICKS: u32 = 40;
const MAX_RETRIES: u32 = 6;

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
enum State {
    #[default]
    Free,
    SynSent,
    SynReceived,
    Established,
    /// Our FIN is out; theirs has not come.
    FinWait1,
    /// Our FIN is acknowledged; theirs has not come.
    FinWait2,
    /// Both FINs crossed; ours is not acknowledged yet.
    Closing,
    /// Their FIN came; ours has not gone.
    CloseWait,
    /// Their FIN came, and ours is out.
    LastAck,
}

#[derive(Clone, Copy, Default)]
struct Connection {
    state: State,
    /// The thread that opened or accepted it, and the only one that may use it.
    owner: u64,
    reply: u64,
    remote: u32,
    remote_port: u16,
    local_port: u16,
    /// The client's receive buffer, and how much of it holds data.
    base: u64,
    size: u64,
    filled: usize,
    /// Data is waiting in the buffer for the client, so the window is shut.
    delivered: bool,
    /// Oldest sequence number not acknowledged, and the next to send. Something
    /// is in flight whenever they differ.
    unacknowledged: u32,
    next_send: u32,
    next_receive: u32,
    /// What is in flight, to send again: its flags, and its data, which stays
    /// in the client's buffer.
    flight_flags: u8,
    flight_base: u64,
    flight_length: usize,
    close_requested: bool,
    waited: u32,
    timeout: u32,
    retries: u32,
}

#[derive(Clone, Copy, Default)]
struct Listener {
    port: u16,
    owner: u64,
    reply: u64,
    base: u64,
    size: u64,
}

#[derive(Clone, Copy)]
struct Waiting {
    frame: [u8; MAX_FRAME],
    length: usize,
    /// The address whose MAC the frame is waiting for. Zero for a free slot.
    next_hop: u32,
}

#[derive(Clone, Copy, Default)]
struct Ping {
    token: u64,
    reply: u64,
    address: u32,
    /// Echo sequence number, or zero for a free slot.
    sequence: u16,
}

#[derive(Clone, Copy, Default)]
struct Binding {
    port: u16,
    reply: u64,
    base: u64,
    size: u64,
}

struct Stack {
    mac: [u8; 6],
    address: u32,
    gateway: u32,
    netmask: u32,
    arp: [(u32, [u8; 6]); ARP_ENTRIES],
    arp_next: usize,
    waiting: [Waiting; WAITING_FRAMES],
    pings: [Ping; PINGS],
    next_sequence: u16,
    bindings: [Binding; BINDINGS],
    /// Buffers mapped into this process: handle, base, size.
    mappings: [(u64, u64, u64); MAPPINGS],
    next_identification: u16,
    control: u64,
    connections: [Connection; CONNECTIONS],
    listeners: [Listener; LISTENERS],
    timer_armed: bool,
    next_port: u16,
    next_sequence_start: u32,
}

extern "C" fn main(parameters: u64) {
    // SAFETY: the kernel fills this page in before entry.
    let parameters = unsafe { &*(parameters as *const Parameters) };

    let mut mac = [0u8; 6];
    if user::net_info(&mut mac) < 0 {
        fail("no network card, or this process may not use it");
    }
    if user::net_bind(parameters.control) < 0 {
        fail("could not bind arrivals to the control endpoint");
    }

    let mut stack = Stack {
        mac,
        address: parameters.address as u32,
        gateway: parameters.gateway as u32,
        netmask: parameters.netmask as u32,
        arp: [(0, [0; 6]); ARP_ENTRIES],
        arp_next: 0,
        waiting: [Waiting {
            frame: [0; MAX_FRAME],
            length: 0,
            next_hop: 0,
        }; WAITING_FRAMES],
        pings: [Ping::default(); PINGS],
        next_sequence: 1,
        bindings: [Binding::default(); BINDINGS],
        mappings: [(0, 0, 0); MAPPINGS],
        next_identification: 1,
        control: parameters.control,
        connections: [Connection::default(); CONNECTIONS],
        listeners: [Listener::default(); LISTENERS],
        timer_armed: false,
        next_port: 49152,
        // No entropy source, so initial sequence numbers are predictable from
        // the MAC; see the README.
        next_sequence_start: u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]),
    };

    // Anything that arrived before the bind was announced to nobody.
    stack.drain();

    loop {
        let mut message = user::Message::default();
        if user::ipc_receive(parameters.control, &mut message) < 0 {
            user::exit(1);
        }
        if message.sender == user::KERNEL_SENDER {
            if message.tag == user::TAG_NET_RECEIVED {
                stack.drain();
            } else if message.tag == user::TAG_TIMER {
                stack.tick();
            }
            continue;
        }
        stack.command(&message);
    }
}

fn fail(why: &str) -> ! {
    user::write("  [net] ");
    user::write(why);
    user::write("\n");
    user::exit(1)
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The Internet checksum: the ones' complement of the ones' complement sum of
/// the bytes taken as big-endian 16-bit words.
fn checksum(bytes: &[u8]) -> u16 {
    fold(add_words(0, bytes))
}

fn add_words(mut sum: u64, bytes: &[u8]) -> u64 {
    for pair in bytes.chunks(2) {
        let word = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], 0])
        };
        sum += word as u64;
    }
    sum
}

fn fold(mut sum: u64) -> u16 {
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A TCP checksum: over a pseudo-header of the addresses, protocol and length,
/// then the segment. Zero when checking a segment that carries a good one.
fn tcp_checksum(source: u32, destination: u32, segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&source.to_be_bytes());
    pseudo[4..8].copy_from_slice(&destination.to_be_bytes());
    pseudo[9] = PROTOCOL_TCP;
    pseudo[10..12].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    fold(add_words(add_words(0, &pseudo), segment))
}

impl Stack {
    // --- receiving -----------------------------------------------------------

    /// Take every frame the kernel has.
    fn drain(&mut self) {
        let mut frame = [0u8; MAX_FRAME];
        // Bounded, so a flood cannot keep this away from its commands forever.
        for _ in 0..64 {
            let length = user::net_receive(&mut frame);
            if length <= 0 {
                return;
            }
            self.frame(&frame[..length as usize]);
        }
    }

    fn frame(&mut self, frame: &[u8]) {
        if frame.len() < 14 {
            return;
        }
        match read_u16(frame, 12) {
            ETHERTYPE_ARP => self.arp(&frame[14..]),
            ETHERTYPE_IPV4 => self.ipv4(&frame[14..]),
            _ => {}
        }
    }

    fn arp(&mut self, packet: &[u8]) {
        // Ethernet and IPv4 only: hardware type 1, protocol 0x0800, 6 and 4.
        if packet.len() < 28 || read_u16(packet, 0) != 1 || read_u16(packet, 2) != ETHERTYPE_IPV4 {
            return;
        }
        if packet[4] != 6 || packet[5] != 4 {
            return;
        }

        let operation = read_u16(packet, 6);
        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&packet[8..14]);
        let sender = read_u32(packet, 14);
        let target = read_u32(packet, 24);

        // Learned only from traffic that concerns this machine, so a stranger
        // on the segment cannot fill the cache with addresses nobody asked for.
        if target != self.address {
            return;
        }
        self.learn(sender, sender_mac);

        if operation == 1 {
            let mut reply = [0u8; 42];
            reply[0..6].copy_from_slice(&sender_mac);
            reply[6..12].copy_from_slice(&self.mac);
            reply[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
            reply[14..22].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
            reply[22..28].copy_from_slice(&self.mac);
            reply[28..32].copy_from_slice(&self.address.to_be_bytes());
            reply[32..38].copy_from_slice(&sender_mac);
            reply[38..42].copy_from_slice(&sender.to_be_bytes());
            user::net_send(&reply);
        }
    }

    fn learn(&mut self, address: u32, mac: [u8; 6]) {
        match self.arp.iter_mut().find(|(known, _)| *known == address) {
            Some(entry) => entry.1 = mac,
            None => {
                self.arp[self.arp_next] = (address, mac);
                self.arp_next = (self.arp_next + 1) % ARP_ENTRIES;
            }
        }

        // Frames that were waiting for this address can go now.
        for slot in 0..WAITING_FRAMES {
            if self.waiting[slot].next_hop == address {
                let waiting = &mut self.waiting[slot];
                waiting.frame[0..6].copy_from_slice(&mac);
                user::net_send(&waiting.frame[..waiting.length]);
                waiting.next_hop = 0;
            }
        }
    }

    fn ipv4(&mut self, packet: &[u8]) {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return;
        }
        let header = (packet[0] & 0x0F) as usize * 4;
        let total = read_u16(packet, 2) as usize;
        if header < 20 || total < header || total > packet.len() {
            return;
        }
        if checksum(&packet[..header]) != 0 {
            return;
        }
        // Fragments are not reassembled: more-fragments set, or an offset.
        if read_u16(packet, 6) & 0x3FFF != 0 {
            return;
        }
        if read_u32(packet, 16) != self.address {
            return;
        }

        let source = read_u32(packet, 12);
        let payload = &packet[header..total];
        match packet[9] {
            PROTOCOL_ICMP => self.icmp(source, payload),
            PROTOCOL_UDP => self.udp(source, payload),
            PROTOCOL_TCP => self.tcp(source, payload),
            _ => {}
        }
    }

    fn icmp(&mut self, source: u32, message: &[u8]) {
        if message.len() < 8 || checksum(message) != 0 {
            return;
        }
        match message[0] {
            // Echo request: the same message back, as a reply.
            8 => {
                let mut reply = [0u8; MAX_FRAME - 34];
                let length = message.len().min(reply.len());
                reply[..length].copy_from_slice(&message[..length]);
                reply[0] = 0;
                reply[2..4].fill(0);
                let sum = checksum(&reply[..length]);
                reply[2..4].copy_from_slice(&sum.to_be_bytes());
                self.send_ipv4(source, PROTOCOL_ICMP, &reply[..length]);
            }
            // Echo reply to one of ours.
            0 if read_u16(message, 4) == PING_IDENTIFIER => {
                let sequence = read_u16(message, 6);
                if let Some(ping) = self
                    .pings
                    .iter_mut()
                    .find(|ping| ping.sequence == sequence && ping.address == source)
                {
                    let pong = user::Message {
                        tag: net::TAG_PONG,
                        words: [ping.token, source as u64, 0, 0],
                        sender: 0,
                        sender_user: 0,
                    };
                    user::ipc_send(ping.reply, &pong);
                    ping.sequence = 0;
                }
            }
            _ => {}
        }
    }

    fn udp(&mut self, source: u32, datagram: &[u8]) {
        if datagram.len() < 8 {
            return;
        }
        let source_port = read_u16(datagram, 0);
        let port = read_u16(datagram, 2);
        let length = (read_u16(datagram, 4) as usize).clamp(8, datagram.len());
        let payload = &datagram[8..length];

        let Some(binding) = self.bindings.iter().find(|binding| binding.port == port && binding.base != 0) else {
            return;
        };
        let take = payload.len().min(binding.size as usize);
        // SAFETY: the client's buffer, mapped into this process with at least
        // `size` bytes, and `take` never exceeds that.
        unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), binding.base as *mut u8, take) };

        let announcement = user::Message {
            tag: net::TAG_DATAGRAM,
            words: [take as u64, source as u64, source_port as u64, port as u64],
            sender: 0,
            sender_user: 0,
        };
        user::ipc_send(binding.reply, &announcement);
    }

    // --- sending -------------------------------------------------------------

    /// Wrap `payload` in IPv4 and Ethernet and send it, resolving the next hop
    /// first if need be.
    fn send_ipv4(&mut self, destination: u32, protocol: u8, payload: &[u8]) {
        let mut frame = [0u8; MAX_FRAME];
        let total = 20 + payload.len();
        if 14 + total > MAX_FRAME {
            return;
        }

        frame[6..12].copy_from_slice(&self.mac);
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&self.next_identification.to_be_bytes());
        self.next_identification = self.next_identification.wrapping_add(1);
        ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&self.address.to_be_bytes());
        ip[16..20].copy_from_slice(&destination.to_be_bytes());
        let sum = checksum(ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());

        frame[34..34 + payload.len()].copy_from_slice(payload);
        let length = 14 + total;

        let next_hop = if destination & self.netmask == self.address & self.netmask {
            destination
        } else {
            self.gateway
        };

        if let Some(&(_, mac)) = self.arp.iter().find(|(known, _)| *known == next_hop) {
            frame[0..6].copy_from_slice(&mac);
            user::net_send(&frame[..length]);
            return;
        }

        // Park it until the address resolves. With every slot taken the frame
        // is dropped; whoever sent it retries or gives up.
        if let Some(slot) = self.waiting.iter_mut().find(|slot| slot.next_hop == 0) {
            slot.frame[..length].copy_from_slice(&frame[..length]);
            slot.length = length;
            slot.next_hop = next_hop;
        }
        self.request_mac(next_hop);
    }

    fn request_mac(&self, address: u32) {
        let mut request = [0u8; 42];
        request[0..6].copy_from_slice(&BROADCAST);
        request[6..12].copy_from_slice(&self.mac);
        request[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        request[14..22].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        request[22..28].copy_from_slice(&self.mac);
        request[28..32].copy_from_slice(&self.address.to_be_bytes());
        request[38..42].copy_from_slice(&address.to_be_bytes());
        user::net_send(&request);
    }

    // --- commands ------------------------------------------------------------

    fn command(&mut self, message: &user::Message) {
        let [a, b, c, d] = message.words;
        match message.tag {
            net::TAG_PING => self.ping(a as u32, b, c),
            net::TAG_UDP_BIND => self.bind(a as u16, b, c),
            net::TAG_UDP_SEND => self.send_udp(a, b as usize, c as u32, (d >> 16) as u16, d as u16),
            net::TAG_TCP_CONNECT => self.connect(message.sender, a as u32, (b >> 16) as u16, b as u16, c, d),
            net::TAG_TCP_LISTEN => self.listen(message.sender, a as u16, b, c),
            _ => {}
        }

        // The rest name a connection, and only its owner may use it.
        let index = a as usize;
        if index >= CONNECTIONS
            || self.connections[index].state == State::Free
            || self.connections[index].owner != message.sender
        {
            return;
        }
        match message.tag {
            net::TAG_TCP_SEND => self.send_tcp(index, b, c as usize),
            net::TAG_TCP_CONSUMED => {
                let connection = &mut self.connections[index];
                connection.filled = 0;
                connection.delivered = false;
                // The window opens again: say so, or the peer never sends.
                self.send_ack(index);
            }
            net::TAG_TCP_CLOSE => self.close(index),
            _ => {}
        }
    }

    fn ping(&mut self, address: u32, reply: u64, token: u64) {
        let Some(slot) = self.pings.iter().position(|ping| ping.sequence == 0) else {
            return;
        };
        let sequence = self.next_sequence;
        // Zero marks a free slot, so it is never used as a sequence number.
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        self.pings[slot] = Ping {
            token,
            reply,
            address,
            sequence,
        };

        let mut echo = [0u8; 8 + 32];
        echo[0] = 8;
        echo[4..6].copy_from_slice(&PING_IDENTIFIER.to_be_bytes());
        echo[6..8].copy_from_slice(&sequence.to_be_bytes());
        for (index, byte) in echo[8..].iter_mut().enumerate() {
            *byte = b'a' + (index % 26) as u8;
        }
        let sum = checksum(&echo);
        echo[2..4].copy_from_slice(&sum.to_be_bytes());
        self.send_ipv4(address, PROTOCOL_ICMP, &echo);
    }

    /// A buffer the client shared, mapped into this process once.
    fn mapping(&mut self, buffer: u64) -> Option<(u64, u64)> {
        if let Some(&(_, base, size)) = self.mappings.iter().find(|(handle, _, _)| *handle == buffer) {
            return Some((base, size));
        }
        let base = user::buffer_map(buffer);
        if base < 0 {
            return None;
        }
        let mut info = user::BufferInfo::default();
        if user::buffer_info(buffer, &mut info) < 0 {
            return None;
        }
        let slot = self.mappings.iter().position(|(handle, _, _)| *handle == 0)?;
        self.mappings[slot] = (buffer, base as u64, info.size);
        Some((base as u64, info.size))
    }

    fn bind(&mut self, port: u16, reply: u64, buffer: u64) {
        let Some((base, size)) = self.mapping(buffer) else {
            return;
        };
        let slot = self
            .bindings
            .iter()
            .position(|binding| binding.port == port || binding.base == 0);
        if let Some(slot) = slot {
            self.bindings[slot] = Binding {
                port,
                reply,
                base,
                size,
            };
        }
    }

    fn send_udp(&mut self, buffer: u64, length: usize, destination: u32, local: u16, remote: u16) {
        let Some((base, size)) = self.mapping(buffer) else {
            return;
        };
        let mut datagram = [0u8; MAX_FRAME - 34];
        if length > size as usize || 8 + length > datagram.len() {
            return;
        }
        datagram[0..2].copy_from_slice(&local.to_be_bytes());
        datagram[2..4].copy_from_slice(&remote.to_be_bytes());
        datagram[4..6].copy_from_slice(&((8 + length) as u16).to_be_bytes());
        // SAFETY: the client's buffer, mapped with `size` bytes, and `length`
        // was checked against it.
        unsafe { core::ptr::copy_nonoverlapping(base as *const u8, datagram[8..].as_mut_ptr(), length) };
        self.send_ipv4(destination, PROTOCOL_UDP, &datagram[..8 + length]);
    }
}

// --- TCP ---------------------------------------------------------------------

impl Stack {
    fn tcp(&mut self, source: u32, segment: &[u8]) {
        if segment.len() < 20 || tcp_checksum(source, self.address, segment) != 0 {
            return;
        }
        let remote_port = read_u16(segment, 0);
        let local_port = read_u16(segment, 2);
        let sequence = read_u32(segment, 4);
        let acknowledgement = read_u32(segment, 8);
        let offset = (segment[12] >> 4) as usize * 4;
        let flags = segment[13];
        if offset < 20 || offset > segment.len() {
            return;
        }
        let payload = &segment[offset..];

        let found = self.connections.iter().position(|c| {
            c.state != State::Free && c.remote == source && c.remote_port == remote_port && c.local_port == local_port
        });
        let Some(index) = found else {
            if flags & RST != 0 {
                return;
            }
            if flags & SYN != 0 && flags & ACK == 0 && self.accept(source, remote_port, local_port, sequence) {
                return;
            }
            // Nothing here: refuse, in the form RFC 793 asks for.
            let length = payload.len() as u32 + (flags & (SYN | FIN) != 0) as u32;
            if flags & ACK != 0 {
                self.segment(source, local_port, remote_port, acknowledgement, 0, RST, 0, &[]);
            } else {
                let ack = sequence.wrapping_add(length);
                self.segment(source, local_port, remote_port, 0, ack, RST | ACK, 0, &[]);
            }
            return;
        };

        let connection = self.connections[index];
        if flags & RST != 0 {
            // Believed only at the expected place, so a blind guess cannot
            // tear a connection down.
            let expected = match connection.state {
                State::SynSent => flags & ACK != 0 && acknowledgement == connection.next_send,
                _ => sequence == connection.next_receive,
            };
            if expected {
                self.finish(index, net::CLOSED_RESET);
            }
            return;
        }

        match connection.state {
            State::SynSent => {
                if flags & (SYN | ACK) == SYN | ACK && acknowledgement == connection.next_send {
                    let connection = &mut self.connections[index];
                    connection.next_receive = sequence.wrapping_add(1);
                    connection.state = State::Established;
                    self.flight_landed(index);
                    self.send_ack(index);
                    self.announce_open(index);
                }
                return;
            }
            State::SynReceived => {
                if flags & ACK == 0 || acknowledgement != connection.next_send {
                    return;
                }
                self.connections[index].state = State::Established;
                self.flight_landed(index);
                self.announce_open(index);
            }
            _ => {
                let in_flight = connection.unacknowledged != connection.next_send;
                if flags & ACK != 0 && in_flight && acknowledgement == connection.next_send {
                    self.flight_landed(index);
                }
            }
        }

        let receiving = matches!(
            self.connections[index].state,
            State::Established | State::FinWait1 | State::FinWait2
        );
        let mut accepted = payload.is_empty();
        if !payload.is_empty() && receiving {
            let connection = &mut self.connections[index];
            let fits = connection.filled + payload.len() <= connection.size as usize;
            if sequence == connection.next_receive && !connection.delivered && fits {
                // SAFETY: the client's buffer, mapped with `size` bytes, and the
                // copy was just checked to fit.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        payload.as_ptr(),
                        (connection.base as usize + connection.filled) as *mut u8,
                        payload.len(),
                    )
                };
                connection.filled += payload.len();
                connection.next_receive = connection.next_receive.wrapping_add(payload.len() as u32);
                connection.delivered = true;
                accepted = true;
                let words = [index as u64, connection.filled as u64, 0, 0];
                self.tell(index, net::TAG_TCP_DATA, words);
            }
        }

        let connection = self.connections[index];
        let fin_in_order = flags & FIN != 0
            && accepted
            && sequence.wrapping_add(payload.len() as u32) == connection.next_receive;
        if fin_in_order && receiving {
            self.connections[index].next_receive = connection.next_receive.wrapping_add(1);
            self.send_ack(index);
            match connection.state {
                State::Established => {
                    self.connections[index].state = State::CloseWait;
                    self.tell(index, net::TAG_TCP_CLOSED, [index as u64, net::CLOSED_PEER_FINISHED, 0, 0]);
                }
                State::FinWait1 => self.connections[index].state = State::Closing,
                _ => self.finish(index, net::CLOSED_FINISHED),
            }
        } else if !payload.is_empty() || flags & FIN != 0 {
            // Taken or not, say where this side is, so the peer knows what to
            // send again. A repeated FIN whose acknowledgement was lost lands here.
            self.send_ack(index);
        }
    }

    /// A SYN for a port someone is listening on becomes a connection.
    fn accept(&mut self, source: u32, remote_port: u16, local_port: u16, sequence: u32) -> bool {
        let Some(listener) = self.listeners.iter().position(|l| l.port == local_port && l.base != 0) else {
            return false;
        };
        let Some(index) = self.connections.iter().position(|c| c.state == State::Free) else {
            return false;
        };
        let listening = core::mem::take(&mut self.listeners[listener]);
        let start = self.sequence_start();
        self.connections[index] = Connection {
            state: State::SynReceived,
            owner: listening.owner,
            reply: listening.reply,
            remote: source,
            remote_port,
            local_port,
            base: listening.base,
            size: listening.size,
            unacknowledged: start,
            next_send: start,
            next_receive: sequence.wrapping_add(1),
            ..Connection::default()
        };
        self.start_flight(index, SYN, 0, 0);
        true
    }

    fn sequence_start(&mut self) -> u32 {
        self.next_sequence_start = self.next_sequence_start.wrapping_add(0x0101_7F31);
        self.next_sequence_start
    }

    fn connect(&mut self, owner: u64, address: u32, local_port: u16, remote_port: u16, reply: u64, buffer: u64) {
        let Some((base, size)) = self.mapping(buffer) else {
            return;
        };
        let Some(index) = self.connections.iter().position(|c| c.state == State::Free) else {
            let words = [u64::MAX, net::CLOSED_NO_ROOM, 0, 0];
            user::ipc_send(reply, &user::Message { tag: net::TAG_TCP_CLOSED, words, sender: 0, sender_user: 0 });
            return;
        };
        let local_port = if local_port != 0 {
            local_port
        } else {
            self.next_port = self.next_port.checked_add(1).unwrap_or(49152);
            self.next_port
        };
        let start = self.sequence_start();
        self.connections[index] = Connection {
            state: State::SynSent,
            owner,
            reply,
            remote: address,
            remote_port,
            local_port,
            base,
            size,
            unacknowledged: start,
            next_send: start,
            ..Connection::default()
        };
        self.start_flight(index, SYN, 0, 0);
    }

    fn listen(&mut self, owner: u64, port: u16, reply: u64, buffer: u64) {
        let Some((base, size)) = self.mapping(buffer) else {
            return;
        };
        let slot = self.listeners.iter().position(|l| l.base == 0 || (l.port == port && l.owner == owner));
        if let Some(slot) = slot {
            self.listeners[slot] = Listener { port, owner, reply, base, size };
        }
    }

    fn send_tcp(&mut self, index: usize, buffer: u64, length: usize) {
        let connection = self.connections[index];
        let open = matches!(connection.state, State::Established | State::CloseWait);
        let idle = connection.unacknowledged == connection.next_send && !connection.close_requested;
        let mapped = self.mapping(buffer);
        match mapped {
            Some((base, size)) if open && idle && length > 0 && length <= net::TCP_MSS && length <= size as usize => {
                self.start_flight(index, PSH, base, length);
            }
            _ => self.tell(index, net::TAG_TCP_SENT, [index as u64, 0, 0, 0]),
        }
    }

    fn close(&mut self, index: usize) {
        let connection = self.connections[index];
        match connection.state {
            State::SynSent | State::SynReceived => {
                self.send_reset(index);
                self.finish(index, net::CLOSED_FINISHED);
            }
            State::Established | State::CloseWait if connection.unacknowledged == connection.next_send => {
                self.send_fin(index);
            }
            State::Established | State::CloseWait => self.connections[index].close_requested = true,
            _ => {}
        }
    }

    fn send_fin(&mut self, index: usize) {
        let connection = &mut self.connections[index];
        connection.state = match connection.state {
            State::CloseWait => State::LastAck,
            _ => State::FinWait1,
        };
        self.start_flight(index, FIN, 0, 0);
    }

    /// What was in flight has been acknowledged.
    fn flight_landed(&mut self, index: usize) {
        let connection = &mut self.connections[index];
        connection.unacknowledged = connection.next_send;
        let (flags, length) = (connection.flight_flags, connection.flight_length);
        connection.flight_flags = 0;
        connection.flight_length = 0;

        if flags & FIN != 0 {
            match connection.state {
                State::FinWait1 => connection.state = State::FinWait2,
                State::Closing | State::LastAck => self.finish(index, net::CLOSED_FINISHED),
                _ => {}
            }
            return;
        }
        if length > 0 {
            self.tell(index, net::TAG_TCP_SENT, [index as u64, length as u64, 0, 0]);
        }
        let connection = self.connections[index];
        if connection.close_requested && matches!(connection.state, State::Established | State::CloseWait) {
            self.connections[index].close_requested = false;
            self.send_fin(index);
        }
    }

    /// Put something in flight and send it. A SYN and a FIN each take a
    /// sequence number, as data takes one per byte.
    fn start_flight(&mut self, index: usize, flags: u8, base: u64, length: usize) {
        let connection = &mut self.connections[index];
        connection.unacknowledged = connection.next_send;
        connection.next_send = connection
            .next_send
            .wrapping_add(length as u32 + (flags & (SYN | FIN) != 0) as u32);
        connection.flight_flags = flags;
        connection.flight_base = base;
        connection.flight_length = length;
        connection.waited = 0;
        connection.timeout = FIRST_RTO_TICKS;
        connection.retries = 0;
        self.transmit(index);
        self.arm_timer();
    }

    fn transmit(&mut self, index: usize) {
        let connection = self.connections[index];
        let mut flags = connection.flight_flags;
        if connection.state != State::SynSent {
            flags |= ACK;
        }
        // SAFETY: a buffer mapped into this process with at least `length`
        // bytes; `send_tcp` checked the length against it.
        let data = unsafe { core::slice::from_raw_parts(connection.flight_base as *const u8, connection.flight_length) };
        let mut payload = [0u8; net::TCP_MSS];
        payload[..data.len()].copy_from_slice(data);
        self.connection_segment(index, connection.unacknowledged, flags, &payload[..data.len()]);
    }

    fn send_ack(&mut self, index: usize) {
        let sequence = self.connections[index].next_send;
        self.connection_segment(index, sequence, ACK, &[]);
    }

    fn send_reset(&mut self, index: usize) {
        let sequence = self.connections[index].next_send;
        self.connection_segment(index, sequence, RST, &[]);
    }

    fn connection_segment(&mut self, index: usize, sequence: u32, flags: u8, payload: &[u8]) {
        let c = self.connections[index];
        // Shut while the client has data to read, so nothing arrives that
        // there is no room for.
        let window = if c.delivered { 0 } else { (c.size as usize - c.filled).min(0xFFFF) as u16 };
        self.segment(c.remote, c.local_port, c.remote_port, sequence, c.next_receive, flags, window, payload);
    }

    #[allow(clippy::too_many_arguments)]
    fn segment(
        &mut self,
        destination: u32,
        local_port: u16,
        remote_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
    ) {
        let mut segment = [0u8; 24 + net::TCP_MSS];
        // A SYN carries one option: the largest segment this side takes.
        let header = if flags & SYN != 0 { 24 } else { 20 };
        segment[0..2].copy_from_slice(&local_port.to_be_bytes());
        segment[2..4].copy_from_slice(&remote_port.to_be_bytes());
        segment[4..8].copy_from_slice(&sequence.to_be_bytes());
        if flags & ACK != 0 {
            segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        }
        segment[12] = (header as u8 / 4) << 4;
        segment[13] = flags;
        segment[14..16].copy_from_slice(&window.to_be_bytes());
        if header == 24 {
            segment[20..24].copy_from_slice(&[2, 4, 0x05, 0xB4]);
        }
        segment[header..header + payload.len()].copy_from_slice(payload);
        let length = header + payload.len();
        let sum = tcp_checksum(self.address, destination, &segment[..length]);
        segment[16..18].copy_from_slice(&sum.to_be_bytes());
        self.send_ipv4(destination, PROTOCOL_TCP, &segment[..length]);
    }

    fn announce_open(&mut self, index: usize) {
        let c = self.connections[index];
        let words = [index as u64, c.remote as u64, c.remote_port as u64, c.local_port as u64];
        self.tell(index, net::TAG_TCP_OPEN, words);
    }

    fn tell(&self, index: usize, tag: u64, words: [u64; 4]) {
        let message = user::Message { tag, words, sender: 0, sender_user: 0 };
        user::ipc_send(self.connections[index].reply, &message);
    }

    /// The connection is over: tell its owner why and free the slot.
    fn finish(&mut self, index: usize, reason: u64) {
        self.tell(index, net::TAG_TCP_CLOSED, [index as u64, reason, 0, 0]);
        self.connections[index] = Connection::default();
    }

    fn arm_timer(&mut self) {
        let waiting = self.connections.iter().any(|c| c.state != State::Free && c.unacknowledged != c.next_send);
        if waiting && !self.timer_armed && user::timer_set(self.control, TICK_MS, 0) >= 0 {
            self.timer_armed = true;
        }
    }

    /// Resend what has waited too long, and give up on what has been resent
    /// too often.
    fn tick(&mut self) {
        self.timer_armed = false;
        for index in 0..CONNECTIONS {
            let connection = &mut self.connections[index];
            if connection.state == State::Free || connection.unacknowledged == connection.next_send {
                continue;
            }
            connection.waited += 1;
            if connection.waited < connection.timeout {
                continue;
            }
            connection.retries += 1;
            if connection.retries > MAX_RETRIES {
                self.send_reset(index);
                self.finish(index, net::CLOSED_TIMED_OUT);
                continue;
            }
            connection.waited = 0;
            connection.timeout = (connection.timeout * 2).min(MAX_RTO_TICKS);
            self.transmit(index);
        }
        self.arm_timer();
    }
}
