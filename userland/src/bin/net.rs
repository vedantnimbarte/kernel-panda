//! The network daemon: ARP, IPv4, ICMP and UDP, in Ring 3.
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
const BROADCAST: [u8; 6] = [0xFF; 6];

/// Identifier stamped on every echo request this daemon sends.
const PING_IDENTIFIER: u16 = 0x5044;

const ARP_ENTRIES: usize = 8;
const WAITING_FRAMES: usize = 2;
const PINGS: usize = 8;
const BINDINGS: usize = 8;
const MAPPINGS: usize = 8;

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
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], 0])
        };
        sum += word as u32;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
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
