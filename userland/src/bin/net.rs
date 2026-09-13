//! The network daemon: ARP, IPv4, ICMP, IPv6, NDP, UDP, TCP, DHCP and DNS, in
//! Ring 3.
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
//! * **IPv6**: a link-local address made from the MAC, and a global one made
//!   from the prefix a router advertises; neighbours found by NDP into the same
//!   cache as ARP's. No extension headers, no fragments, no duplicate address
//!   detection.
//! * **ICMP and ICMPv6**: echo requests are answered; echo replies are matched to
//!   pings a client asked for.
//! * **UDP**: a client binds a port to a buffer it shares, and sends by naming a
//!   buffer. Checksums are sent, and checked on IPv6, where they are mandatory.
//!
//! Above the network layer an address is 16 bytes, IPv4 ones held IPv4-mapped
//! (`::ffff:a.b.c.d`), so UDP, TCP and DNS have one code path for both.
//! * **TCP**: connections opened and accepted, one segment in flight each way.
//!   A client's send waits for its acknowledgement before the next, and the
//!   receive side takes one segment into the client's buffer and closes its
//!   window until the client has read it. Unacknowledged segments are resent on
//!   a timer, backing off, until a connection gives up.
//! * **DHCP**: started with no address, the daemon asks for one, and answers
//!   clients asking for the configuration once it has it. The lease is taken
//!   for as long as the daemon runs; it is never renewed.
//! * **DNS**: IPv4 addresses for names, from the server DHCP offered or one
//!   given at start-up, asked again twice before giving up.

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
    /// A DNS server to use instead of any DHCP offers, as `address << 16 |
    /// port`, or zero.
    dns: u64,
}

const MAX_FRAME: usize = 1514;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const PROTOCOL_ICMPV6: u8 = 58;
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
const RESOLVERS: usize = 4;
const CONFIG_WAITERS: usize = 4;

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
/// Lookups go out from a port chosen at random at start-up, plus their slot, so
/// an answer names its slot.
const DNS_PORT_RANGE: core::ops::Range<u16> = 49152..65535 - RESOLVERS as u16;
/// Timer ticks before a DHCP or DNS request is sent again, and DNS tries.
const REQUEST_TICKS: u32 = 10;
const DNS_TRIES: u32 = 3;
/// Router solicitations sent before giving up on being told a prefix.
const SOLICITATIONS: u32 = 3;
/// Largest TCP payload in one frame over IPv6, whose header is 20 bytes longer.
const TCP_MSS_V6: usize = net::TCP_MSS - 20;

/// An address of either family: see the module notes.
type Ip = [u8; 16];
const UNSPECIFIED: Ip = [0; 16];
const ALL_NODES: Ip = [0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const ALL_ROUTERS: Ip = [0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn mapped(v4: u32) -> Ip {
    let mut ip = UNSPECIFIED;
    ip[10..12].copy_from_slice(&[0xFF, 0xFF]);
    ip[12..].copy_from_slice(&v4.to_be_bytes());
    ip
}

fn as_v4(ip: &Ip) -> Option<u32> {
    (ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]).then(|| read_u32(ip, 12))
}

fn read_ip(bytes: &[u8], at: usize) -> Ip {
    bytes[at..at + 16].try_into().unwrap()
}

fn is_link_local(ip: &Ip) -> bool {
    ip[0] == 0xFE && ip[1] & 0xC0 == 0x80
}

/// The multicast group a neighbour solicitation for `ip` goes to.
fn solicited_node(ip: &Ip) -> Ip {
    let mut group = [0xFF, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0, 0, 0];
    group[13..].copy_from_slice(&ip[13..]);
    group
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Dhcp {
    /// Given an address, or has one.
    #[default]
    Done,
    Discovering,
    Requesting,
}

#[derive(Clone, Copy, Default)]
struct Resolve {
    /// Zero for a free slot.
    id: u16,
    /// 1 for A, 28 for AAAA.
    kind: u16,
    reply: u64,
    token: u64,
    base: u64,
    length: usize,
    waited: u32,
    tries: u32,
}

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
    remote: Ip,
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
    /// The address whose MAC the frame is waiting for. Unspecified for a free
    /// slot.
    next_hop: Ip,
}

#[derive(Clone, Copy, Default)]
struct Ping {
    token: u64,
    reply: u64,
    address: Ip,
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
    /// Neighbours of both families: ARP's and NDP's.
    arp: [(Ip, [u8; 6]); ARP_ENTRIES],
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
    dhcp: Dhcp,
    dhcp_waited: u32,
    transaction: u32,
    offered: u32,
    dhcp_server: u32,
    offered_dns: u32,
    config_waiters: [u64; CONFIG_WAITERS],
    dns_server: Ip,
    dns_port: u16,
    resolves: [Resolve; RESOLVERS],
    dns_local_port: u16,
    link_local: Ip,
    /// Unspecified until a router advertises a prefix.
    global6: Ip,
    router6: Ip,
    dns6: Ip,
    solicited: u32,
    solicit_waited: u32,
    config6_waiters: [u64; CONFIG_WAITERS],
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
        arp: [(UNSPECIFIED, [0; 6]); ARP_ENTRIES],
        arp_next: 0,
        waiting: [Waiting {
            frame: [0; MAX_FRAME],
            length: 0,
            next_hop: UNSPECIFIED,
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
        next_port: 49152 + (user::random_u64() % 8192) as u16,
        dhcp: Dhcp::Done,
        dhcp_waited: 0,
        transaction: user::random_u64() as u32,
        offered: 0,
        dhcp_server: 0,
        offered_dns: 0,
        config_waiters: [0; CONFIG_WAITERS],
        dns_server: mapped((parameters.dns >> 16) as u32),
        dns_port: parameters.dns as u16,
        resolves: [Resolve::default(); RESOLVERS],
        dns_local_port: DNS_PORT_RANGE.start + (user::random_u64() % DNS_PORT_RANGE.len() as u64) as u16,
        // fe80::, then the MAC stretched to 64 bits with its universal bit flipped.
        link_local: [
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, mac[0] ^ 2, mac[1], mac[2], 0xFF, 0xFE, mac[3], mac[4], mac[5],
        ],
        global6: UNSPECIFIED,
        router6: UNSPECIFIED,
        dns6: UNSPECIFIED,
        solicited: 1,
        solicit_waited: 0,
        config6_waiters: [0; CONFIG_WAITERS],
    };
    stack.solicit_router();
    stack.arm_timer();
    if stack.address == 0 {
        stack.dhcp = Dhcp::Discovering;
        stack.dhcp_send(DHCP_DISCOVER);
        stack.arm_timer();
    }

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

/// The checksum UDP, TCP and ICMPv6 carry: over a pseudo-header of the
/// addresses, protocol and length -- laid out per family -- then the bytes.
/// Zero when checking bytes that carry a good one.
fn transport_checksum(protocol: u8, source: &Ip, destination: &Ip, bytes: &[u8]) -> u16 {
    let pseudo = match (as_v4(source), as_v4(destination)) {
        (Some(from), Some(to)) => {
            let mut pseudo = [0u8; 12];
            pseudo[0..4].copy_from_slice(&from.to_be_bytes());
            pseudo[4..8].copy_from_slice(&to.to_be_bytes());
            pseudo[9] = protocol;
            pseudo[10..12].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
            add_words(0, &pseudo)
        }
        _ => {
            let mut pseudo = [0u8; 40];
            pseudo[0..16].copy_from_slice(source);
            pseudo[16..32].copy_from_slice(destination);
            pseudo[32..36].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
            pseudo[39] = protocol;
            add_words(0, &pseudo)
        }
    };
    fold(add_words(pseudo, bytes))
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
            ETHERTYPE_IPV6 => self.ipv6(&frame[14..]),
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
        self.learn(mapped(sender), sender_mac);

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

    fn learn(&mut self, address: Ip, mac: [u8; 6]) {
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
                waiting.next_hop = UNSPECIFIED;
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
        let destination = read_u32(packet, 16);
        if destination != self.address && destination != u32::MAX && self.address != 0 {
            return;
        }

        let source = read_u32(packet, 12);
        let payload = &packet[header..total];
        match packet[9] {
            PROTOCOL_ICMP => self.icmp(source, payload),
            PROTOCOL_UDP => self.udp(mapped(source), mapped(destination), payload),
            PROTOCOL_TCP => self.tcp(mapped(source), mapped(destination), payload),
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
                    .find(|ping| ping.sequence == sequence && ping.address == mapped(source))
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

    fn udp(&mut self, source: Ip, destination: Ip, datagram: &[u8]) {
        if datagram.len() < 8 {
            return;
        }
        let v4 = as_v4(&source).is_some();
        if !v4 && transport_checksum(PROTOCOL_UDP, &source, &destination, datagram) != 0 {
            return;
        }
        let source_port = read_u16(datagram, 0);
        let port = read_u16(datagram, 2);
        let length = (read_u16(datagram, 4) as usize).clamp(8, datagram.len());
        let payload = &datagram[8..length];

        if v4 && port == DHCP_CLIENT_PORT && self.dhcp != Dhcp::Done {
            self.dhcp_reply(payload);
            return;
        }
        if let Some(slot) = port.checked_sub(self.dns_local_port).map(usize::from).filter(|slot| *slot < RESOLVERS) {
            if self.resolves[slot].id != 0 && source == self.dns_server && source_port == self.dns_port {
                self.dns_reply(slot, payload);
            }
            return;
        }

        let Some(binding) = self.bindings.iter().find(|binding| binding.port == port && binding.base != 0) else {
            return;
        };
        // An IPv6 source goes ahead of the payload, since it will not fit a word.
        let skip = if v4 { 0 } else { 16 };
        if (binding.size as usize) < skip {
            return;
        }
        let take = payload.len().min(binding.size as usize - skip);
        // SAFETY: the client's buffer, mapped into this process with at least
        // `size` bytes, and `skip + take` never exceeds that.
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), binding.base as *mut u8, skip);
            core::ptr::copy_nonoverlapping(payload.as_ptr(), (binding.base as usize + skip) as *mut u8, take);
        }

        let from = as_v4(&source).map_or(net::IPV6, u64::from);
        let announcement = user::Message {
            tag: net::TAG_DATAGRAM,
            words: [take as u64, from, source_port as u64, port as u64],
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

        if destination == u32::MAX {
            frame[0..6].copy_from_slice(&BROADCAST);
            user::net_send(&frame[..length]);
            return;
        }
        let next_hop = mapped(if destination & self.netmask == self.address & self.netmask {
            destination
        } else {
            self.gateway
        });

        if let Some(&(_, mac)) = self.arp.iter().find(|(known, _)| *known == next_hop) {
            frame[0..6].copy_from_slice(&mac);
            user::net_send(&frame[..length]);
            return;
        }

        self.park(&frame[..length], next_hop);
        if let Some(address) = as_v4(&next_hop) {
            self.request_mac(address);
        }
    }

    /// Hold a frame until its next hop's MAC is known. With every slot taken
    /// the frame is dropped; whoever sent it retries or gives up.
    fn park(&mut self, frame: &[u8], next_hop: Ip) {
        if let Some(slot) = self.waiting.iter_mut().find(|slot| slot.next_hop == UNSPECIFIED) {
            slot.frame[..frame.len()].copy_from_slice(frame);
            slot.length = frame.len();
            slot.next_hop = next_hop;
        }
    }

    /// Send `payload` to either family.
    fn send_ip(&mut self, destination: &Ip, protocol: u8, payload: &[u8]) {
        match as_v4(destination) {
            Some(address) => self.send_ipv4(address, protocol, payload),
            None => self.send_ipv6(destination, protocol, payload),
        }
    }

    /// The address this machine sends to `destination` from.
    fn source_for(&self, destination: &Ip) -> Ip {
        if as_v4(destination).is_some() {
            mapped(self.address)
        } else if is_link_local(destination) || destination[0] == 0xFF || self.global6 == UNSPECIFIED {
            self.link_local
        } else {
            self.global6
        }
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
            net::TAG_PING => self.ping(a, b, c, d),
            net::TAG_UDP_BIND => self.bind(a as u16, b, c),
            net::TAG_UDP_SEND => self.send_udp(a, b as usize, c, (d >> 16) as u16, d as u16),
            net::TAG_TCP_CONNECT => self.connect(message.sender, a, (b >> 16) as u16, b as u16, c, d),
            net::TAG_TCP_LISTEN => self.listen(message.sender, a as u16, b, c),
            net::TAG_NET_CONFIG => self.config(a),
            net::TAG_RESOLVE => self.resolve(a, b as usize, c, d, 1),
            net::TAG_RESOLVE6 => self.resolve(a, b as usize, c, d, 28),
            net::TAG_NET_CONFIG6 => self.config6(a),
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

    /// The address a client named: a word for IPv4, or `IPV6` and the 16 bytes
    /// at the start of `buffer`.
    fn named_address(&mut self, word: u64, buffer: u64) -> Option<Ip> {
        if word != net::IPV6 {
            return Some(mapped(word as u32));
        }
        let (base, size) = self.mapping(buffer)?;
        // SAFETY: a mapped buffer of `size` bytes, checked to hold 16.
        (size >= 16).then(|| unsafe { core::ptr::read_unaligned(base as *const Ip) })
    }

    fn ping(&mut self, word: u64, reply: u64, token: u64, buffer: u64) {
        let Some(address) = self.named_address(word, buffer) else {
            return;
        };
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
        echo[4..6].copy_from_slice(&PING_IDENTIFIER.to_be_bytes());
        echo[6..8].copy_from_slice(&sequence.to_be_bytes());
        for (index, byte) in echo[8..].iter_mut().enumerate() {
            *byte = b'a' + (index % 26) as u8;
        }
        match as_v4(&address) {
            Some(v4) => {
                echo[0] = 8;
                let sum = checksum(&echo);
                echo[2..4].copy_from_slice(&sum.to_be_bytes());
                self.send_ipv4(v4, PROTOCOL_ICMP, &echo);
            }
            None => {
                echo[0] = 128;
                self.send_icmpv6(&address, &mut echo);
            }
        }
    }

    /// A buffer the client shared, mapped into this process once. With the
    /// table full, one that nothing refers to any more is given up for it:
    /// clients come and go, and each brings buffers of its own.
    fn mapping(&mut self, buffer: u64) -> Option<(u64, u64)> {
        if let Some(&(_, base, size)) = self.mappings.iter().find(|(handle, _, _)| *handle == buffer) {
            return Some((base, size));
        }
        let slot = match self.mappings.iter().position(|(handle, _, _)| *handle == 0) {
            Some(slot) => slot,
            None => {
                let slot = self.mappings.iter().position(|&(_, base, _)| !self.refers_to(base))?;
                user::buffer_unmap(self.mappings[slot].0);
                self.mappings[slot] = (0, 0, 0);
                slot
            }
        };
        let base = user::buffer_map(buffer);
        if base < 0 {
            return None;
        }
        let mut info = user::BufferInfo::default();
        if user::buffer_info(buffer, &mut info) < 0 {
            user::buffer_unmap(buffer);
            return None;
        }
        self.mappings[slot] = (buffer, base as u64, info.size);
        Some((base as u64, info.size))
    }

    /// Whether anything still in use reads or writes the buffer mapped at `base`.
    fn refers_to(&self, base: u64) -> bool {
        self.bindings.iter().any(|b| b.base == base)
            || self.listeners.iter().any(|l| l.base == base)
            || self.connections.iter().any(|c| c.state != State::Free && (c.base == base || c.flight_base == base))
            || self.resolves.iter().any(|r| r.id != 0 && r.base == base)
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

    fn send_udp(&mut self, buffer: u64, length: usize, word: u64, local: u16, remote: u16) {
        let (Some((base, size)), Some(destination)) = (self.mapping(buffer), self.named_address(word, buffer)) else {
            return;
        };
        // For IPv6 the payload follows the address.
        let skip = if word == net::IPV6 { 16 } else { 0 };
        let room = if skip == 0 { MAX_FRAME - 34 } else { MAX_FRAME - 54 };
        let mut datagram = [0u8; MAX_FRAME - 34];
        if skip + length > size as usize || 8 + length > room {
            return;
        }
        datagram[0..2].copy_from_slice(&local.to_be_bytes());
        datagram[2..4].copy_from_slice(&remote.to_be_bytes());
        datagram[4..6].copy_from_slice(&((8 + length) as u16).to_be_bytes());
        // SAFETY: the client's buffer, mapped with `size` bytes, and
        // `skip + length` was checked against it.
        unsafe { core::ptr::copy_nonoverlapping((base as usize + skip) as *const u8, datagram[8..].as_mut_ptr(), length) };
        self.send_udp_datagram(&destination, &mut datagram[..8 + length]);
    }

    /// Checksum a UDP datagram and send it. Zero means "no checksum", so a
    /// checksum that works out to zero is sent as all ones.
    fn send_udp_datagram(&mut self, destination: &Ip, datagram: &mut [u8]) {
        datagram[6..8].fill(0);
        let source = self.source_for(destination);
        let sum = match transport_checksum(PROTOCOL_UDP, &source, destination, datagram) {
            0 => 0xFFFF,
            sum => sum,
        };
        datagram[6..8].copy_from_slice(&sum.to_be_bytes());
        self.send_ip(destination, PROTOCOL_UDP, datagram);
    }
}

// --- TCP ---------------------------------------------------------------------

impl Stack {
    fn tcp(&mut self, source: Ip, destination: Ip, segment: &[u8]) {
        if segment.len() < 20 || transport_checksum(PROTOCOL_TCP, &source, &destination, segment) != 0 {
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
                self.segment(&source, local_port, remote_port, acknowledgement, 0, RST, 0, &[]);
            } else {
                let ack = sequence.wrapping_add(length);
                self.segment(&source, local_port, remote_port, 0, ack, RST | ACK, 0, &[]);
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
    fn accept(&mut self, source: Ip, remote_port: u16, local_port: u16, sequence: u32) -> bool {
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

    /// Random, so that nobody off the path can guess where a connection's
    /// sequence numbers are and write into it.
    fn sequence_start(&mut self) -> u32 {
        user::random_u64() as u32
    }

    fn connect(&mut self, owner: u64, word: u64, local_port: u16, remote_port: u16, reply: u64, buffer: u64) {
        let (Some((base, size)), Some(address)) = (self.mapping(buffer), self.named_address(word, buffer)) else {
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
            Some((base, size)) if open && idle && length > 0 && length <= Self::mss(&connection.remote) && length <= size as usize => {
                self.start_flight(index, PSH, base, length);
            }
            _ => self.tell(index, net::TAG_TCP_SENT, [index as u64, 0, 0, 0]),
        }
    }

    fn mss(remote: &Ip) -> usize {
        if as_v4(remote).is_some() { net::TCP_MSS } else { TCP_MSS_V6 }
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
        self.segment(&c.remote, c.local_port, c.remote_port, sequence, c.next_receive, flags, window, payload);
    }

    #[allow(clippy::too_many_arguments)]
    fn segment(
        &mut self,
        destination: &Ip,
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
            segment[20..22].copy_from_slice(&[2, 4]);
            segment[22..24].copy_from_slice(&(Self::mss(destination) as u16).to_be_bytes());
        }
        segment[header..header + payload.len()].copy_from_slice(payload);
        let length = header + payload.len();
        let source = self.source_for(destination);
        let sum = transport_checksum(PROTOCOL_TCP, &source, destination, &segment[..length]);
        segment[16..18].copy_from_slice(&sum.to_be_bytes());
        self.send_ip(destination, PROTOCOL_TCP, &segment[..length]);
    }

    fn announce_open(&mut self, index: usize) {
        let c = self.connections[index];
        if as_v4(&c.remote).is_none() && c.size >= 16 {
            // SAFETY: the client's mapped buffer, checked to hold 16 bytes. No
            // data has arrived to be overwritten: this is the first news of it.
            unsafe { core::ptr::write_unaligned(c.base as *mut Ip, c.remote) };
        }
        let remote = as_v4(&c.remote).map_or(net::IPV6, u64::from);
        let words = [index as u64, remote, c.remote_port as u64, c.local_port as u64];
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
        let waiting = self.connections.iter().any(|c| c.state != State::Free && c.unacknowledged != c.next_send)
            || self.dhcp != Dhcp::Done
            || self.resolves.iter().any(|r| r.id != 0)
            || (self.global6 == UNSPECIFIED && self.solicited < SOLICITATIONS);
        if waiting && !self.timer_armed && user::timer_set(self.control, TICK_MS, 0) >= 0 {
            self.timer_armed = true;
        }
    }

    /// Resend what has waited too long, and give up on what has been resent
    /// too often.
    fn tick(&mut self) {
        self.timer_armed = false;
        self.dhcp_tick();
        self.dns_tick();
        self.solicit_tick();
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

// --- DHCP and DNS ------------------------------------------------------------

impl Stack {
    /// A UDP datagram of this daemon's own, rather than a client's.
    fn send_datagram(&mut self, destination: &Ip, local: u16, remote: u16, payload: &[u8]) {
        let mut datagram = [0u8; 8 + 512];
        let length = 8 + payload.len();
        datagram[0..2].copy_from_slice(&local.to_be_bytes());
        datagram[2..4].copy_from_slice(&remote.to_be_bytes());
        datagram[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        datagram[8..length].copy_from_slice(payload);
        self.send_udp_datagram(destination, &mut datagram[..length]);
    }

    fn dhcp_send(&mut self, kind: u8) {
        let mut message = [0u8; 300];
        message[0..4].copy_from_slice(&[1, 1, 6, 0]);
        message[4..8].copy_from_slice(&self.transaction.to_be_bytes());
        // Answer by broadcast: this machine cannot receive unicast until it has
        // the address it is asking for.
        message[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        message[28..34].copy_from_slice(&self.mac);
        message[236..240].copy_from_slice(&DHCP_COOKIE);

        let mut options = [0u8; 32];
        let mut length = 0;
        let mut option = |bytes: &[u8]| {
            options[length..length + bytes.len()].copy_from_slice(bytes);
            length += bytes.len();
        };
        option(&[53, 1, kind]);
        if kind == DHCP_REQUEST {
            let [a, b, c, d] = self.offered.to_be_bytes();
            option(&[50, 4, a, b, c, d]);
            let [a, b, c, d] = self.dhcp_server.to_be_bytes();
            option(&[54, 4, a, b, c, d]);
        }
        // Asking for the netmask, the router and a DNS server.
        option(&[55, 3, 1, 3, 6, 255]);
        message[240..240 + length].copy_from_slice(&options[..length]);

        self.send_datagram(&mapped(u32::MAX), DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &message);
    }

    fn dhcp_reply(&mut self, message: &[u8]) {
        if message.len() < 240
            || message[0] != 2
            || read_u32(message, 4) != self.transaction
            || message[28..34] != self.mac
            || message[236..240] != DHCP_COOKIE
        {
            return;
        }

        let (mut kind, mut netmask, mut router, mut dns, mut server) = (0, 0, 0, 0, 0);
        let mut at = 240;
        while at + 1 < message.len() && message[at] != 255 {
            if message[at] == 0 {
                at += 1;
                continue;
            }
            let (code, length, value) = (message[at], message[at + 1] as usize, at + 2);
            if value + length > message.len() {
                return;
            }
            match code {
                53 if length == 1 => kind = message[value],
                1 if length == 4 => netmask = read_u32(message, value),
                3 if length >= 4 => router = read_u32(message, value),
                6 if length >= 4 => dns = read_u32(message, value),
                54 if length == 4 => server = read_u32(message, value),
                _ => {}
            }
            at = value + length;
        }

        match (self.dhcp, kind) {
            (Dhcp::Discovering, DHCP_OFFER) => {
                self.offered = read_u32(message, 16);
                self.dhcp_server = server;
                self.dhcp = Dhcp::Requesting;
                self.dhcp_waited = 0;
                self.dhcp_send(DHCP_REQUEST);
            }
            (Dhcp::Requesting, DHCP_ACK) => {
                self.address = self.offered;
                self.netmask = netmask;
                self.gateway = router;
                self.offered_dns = dns;
                if self.dns_port == 0 && dns != 0 {
                    self.dns_server = mapped(dns);
                    self.dns_port = 53;
                }
                self.dhcp = Dhcp::Done;
                for waiter in core::mem::take(&mut self.config_waiters) {
                    if waiter != 0 {
                        self.configured(waiter);
                    }
                }
            }
            (Dhcp::Requesting, DHCP_NAK) => {
                self.transaction = user::random_u64() as u32;
                self.dhcp = Dhcp::Discovering;
                self.dhcp_waited = 0;
                self.dhcp_send(DHCP_DISCOVER);
            }
            _ => {}
        }
    }

    fn dhcp_tick(&mut self) {
        if self.dhcp == Dhcp::Done {
            return;
        }
        self.dhcp_waited += 1;
        if self.dhcp_waited >= REQUEST_TICKS {
            self.dhcp_waited = 0;
            let kind = if self.dhcp == Dhcp::Discovering { DHCP_DISCOVER } else { DHCP_REQUEST };
            self.dhcp_send(kind);
        }
    }

    fn config(&mut self, reply: u64) {
        if self.dhcp == Dhcp::Done {
            self.configured(reply);
        } else if let Some(slot) = self.config_waiters.iter_mut().find(|waiter| **waiter == 0) {
            *slot = reply;
        }
    }

    fn configured(&self, reply: u64) {
        let words = [self.address as u64, self.gateway as u64, self.netmask as u64, self.offered_dns as u64];
        user::ipc_send(reply, &user::Message { tag: net::TAG_NET_CONFIGURED, words, sender: 0, sender_user: 0 });
    }

    fn resolve(&mut self, buffer: u64, length: usize, reply: u64, token: u64, kind: u16) {
        let answer = |status: u64| {
            let words = [token, 0, status, 0];
            user::ipc_send(reply, &user::Message { tag: net::TAG_RESOLVED, words, sender: 0, sender_user: 0 });
        };
        let Some((base, size)) = self.mapping(buffer) else {
            return;
        };
        // An IPv6 answer is written over the start of the buffer.
        if length == 0 || length > 253 || length > size as usize || (kind == 28 && size < 16) {
            return answer(net::RESOLVE_BAD_NAME);
        }
        if self.dns_port == 0 {
            return answer(net::RESOLVE_TIMED_OUT);
        }
        let Some(slot) = self.resolves.iter().position(|r| r.id == 0) else {
            return answer(net::RESOLVE_TIMED_OUT);
        };

        // Random, and never zero, which marks a free slot.
        let id = (user::random_u64() as u16).max(1);
        self.resolves[slot] = Resolve { id, kind, reply, token, base, length, waited: 0, tries: 1 };
        if !self.dns_query(slot) {
            self.resolves[slot] = Resolve::default();
            return answer(net::RESOLVE_BAD_NAME);
        }
        self.arm_timer();
    }

    /// Send the lookup in `slot`. `false` if its name is not a name.
    fn dns_query(&mut self, slot: usize) -> bool {
        let lookup = self.resolves[slot];
        // SAFETY: a buffer mapped into this process, and `resolve` checked the
        // length against its size.
        let name = unsafe { core::slice::from_raw_parts(lookup.base as *const u8, lookup.length) };

        let mut query = [0u8; 12 + 255 + 4];
        query[0..2].copy_from_slice(&lookup.id.to_be_bytes());
        // A standard query, recursion desired, one question.
        query[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        query[4..6].copy_from_slice(&1u16.to_be_bytes());
        let mut at = 12;
        for label in name.split(|byte| *byte == b'.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            query[at] = label.len() as u8;
            query[at + 1..at + 1 + label.len()].copy_from_slice(label);
            at += 1 + label.len();
        }
        // The root, the type, class IN.
        query[at] = 0;
        query[at + 1..at + 3].copy_from_slice(&lookup.kind.to_be_bytes());
        query[at + 3..at + 5].copy_from_slice(&[0, 1]);
        at += 5;

        let (server, port) = (self.dns_server, self.dns_port);
        self.send_datagram(&server, self.dns_local_port + slot as u16, port, &query[..at]);
        true
    }

    fn dns_reply(&mut self, slot: usize, message: &[u8]) {
        let lookup = self.resolves[slot];
        // An answer, to this question.
        if message.len() < 12 || read_u16(message, 0) != lookup.id || message[2] & 0x80 == 0 {
            return;
        }
        let code = (message[3] & 0x0F) as u64;
        let (questions, answers) = (read_u16(message, 4), read_u16(message, 6));

        let mut at = 12;
        let mut found = false;
        let mut address = 0;
        for _ in 0..questions {
            at = skip_name(message, at) + 4;
        }
        for _ in 0..answers {
            at = skip_name(message, at);
            if at + 10 > message.len() {
                break;
            }
            let length = read_u16(message, at + 8) as usize;
            let (kind, class) = (read_u16(message, at), read_u16(message, at + 2));
            let size = if lookup.kind == 1 { 4 } else { 16 };
            if kind == lookup.kind && class == 1 && length == size && at + 10 + size <= message.len() {
                found = true;
                if size == 4 {
                    address = read_u32(message, at + 10) as u64;
                } else {
                    address = net::IPV6;
                    // SAFETY: the lookup's mapped buffer, which `resolve` checked
                    // holds 16 bytes.
                    unsafe { core::ptr::copy_nonoverlapping(message[at + 10..].as_ptr(), lookup.base as *mut u8, 16) };
                }
                break;
            }
            at += 10 + length;
        }

        let (address, status) = match (found, code) {
            (true, 0) => (address, net::RESOLVE_FOUND),
            (_, 0) => (0, net::RESOLVE_NO_ADDRESS),
            (_, code) => (0, code),
        };
        self.resolves[slot] = Resolve::default();
        let words = [lookup.token, address, status, 0];
        user::ipc_send(lookup.reply, &user::Message { tag: net::TAG_RESOLVED, words, sender: 0, sender_user: 0 });
    }

    fn dns_tick(&mut self) {
        for slot in 0..RESOLVERS {
            let lookup = &mut self.resolves[slot];
            if lookup.id == 0 {
                continue;
            }
            lookup.waited += 1;
            if lookup.waited < REQUEST_TICKS {
                continue;
            }
            lookup.waited = 0;
            lookup.tries += 1;
            if lookup.tries > DNS_TRIES {
                let words = [lookup.token, 0, net::RESOLVE_TIMED_OUT, 0];
                let reply = lookup.reply;
                self.resolves[slot] = Resolve::default();
                user::ipc_send(reply, &user::Message { tag: net::TAG_RESOLVED, words, sender: 0, sender_user: 0 });
            } else {
                self.dns_query(slot);
            }
        }
    }
}

/// Past a name in a DNS message: labels ending in the root or in a pointer to
/// another name. Past the end of the message if it runs off it, which every
/// caller's bounds check then catches.
fn skip_name(message: &[u8], mut at: usize) -> usize {
    while at < message.len() {
        match message[at] {
            0 => return at + 1,
            length if length & 0xC0 == 0xC0 => return at + 2,
            length => at += 1 + length as usize,
        }
    }
    usize::MAX / 2
}

// --- IPv6 --------------------------------------------------------------------

impl Stack {
    fn ipv6(&mut self, packet: &[u8]) {
        if packet.len() < 40 || packet[0] >> 4 != 6 {
            return;
        }
        let length = read_u16(packet, 4) as usize;
        if 40 + length > packet.len() {
            return;
        }
        let (next_header, hop_limit) = (packet[6], packet[7]);
        let (source, destination) = (read_ip(packet, 8), read_ip(packet, 24));
        // The global address shares its last 24 bits with the link-local one, so
        // one solicited-node group covers both.
        let ours = destination == self.link_local
            || (destination == self.global6 && self.global6 != UNSPECIFIED)
            || destination == ALL_NODES
            || destination == solicited_node(&self.link_local);
        if !ours {
            return;
        }

        let payload = &packet[40..40 + length];
        match next_header {
            PROTOCOL_ICMPV6 => self.icmpv6(source, destination, hop_limit, payload),
            PROTOCOL_UDP => self.udp(source, destination, payload),
            PROTOCOL_TCP => self.tcp(source, destination, payload),
            // Extension headers are not followed.
            _ => {}
        }
    }

    fn icmpv6(&mut self, source: Ip, destination: Ip, hop_limit: u8, message: &[u8]) {
        if message.len() < 8 || transport_checksum(PROTOCOL_ICMPV6, &source, &destination, message) != 0 {
            return;
        }
        // Neighbour discovery must come from the link itself: a router would
        // have spent a hop, so anything less than 255 was forwarded.
        let from_link = hop_limit == 255;
        match message[0] {
            // Echo request.
            128 => {
                let mut reply = [0u8; MAX_FRAME - 54];
                let length = message.len().min(reply.len());
                reply[..length].copy_from_slice(&message[..length]);
                reply[0] = 129;
                self.send_icmpv6(&source, &mut reply[..length]);
            }
            // Echo reply to one of ours.
            129 if read_u16(message, 4) == PING_IDENTIFIER => {
                let sequence = read_u16(message, 6);
                if let Some(ping) = self.pings.iter_mut().find(|p| p.sequence == sequence && p.address == source) {
                    let pong = user::Message { tag: net::TAG_PONG, words: [ping.token, net::IPV6, 0, 0], sender: 0, sender_user: 0 };
                    user::ipc_send(ping.reply, &pong);
                    ping.sequence = 0;
                }
            }
            // Router advertisement.
            134 if from_link && is_link_local(&source) && message.len() >= 16 => {
                let (mut prefix, mut dns) = (None, UNSPECIFIED);
                for (kind, option) in options(&message[16..]) {
                    match kind {
                        1 if option.len() >= 8 => self.learn(source, option[2..8].try_into().unwrap()),
                        3 if option.len() >= 32 && option[2] == 64 => prefix = Some(read_ip(option, 16)),
                        25 if option.len() >= 24 => dns = read_ip(option, 8),
                        _ => {}
                    }
                }
                let Some(prefix) = prefix else {
                    return;
                };
                self.router6 = source;
                if self.global6 == UNSPECIFIED {
                    self.global6[..8].copy_from_slice(&prefix[..8]);
                    self.global6[8..].copy_from_slice(&self.link_local[8..]);
                }
                if dns != UNSPECIFIED {
                    self.dns6 = dns;
                    if self.dns_port == 0 {
                        self.dns_server = dns;
                        self.dns_port = 53;
                    }
                }
                for waiter in core::mem::take(&mut self.config6_waiters) {
                    if waiter != 0 {
                        self.configured6(waiter);
                    }
                }
            }
            // Neighbour solicitation.
            135 if from_link && message.len() >= 24 => {
                let target = read_ip(message, 8);
                if target != self.link_local && (target != self.global6 || self.global6 == UNSPECIFIED) {
                    return;
                }
                if source != UNSPECIFIED {
                    if let Some((_, option)) = options(&message[24..]).find(|(kind, o)| *kind == 1 && o.len() >= 8) {
                        self.learn(source, option[2..8].try_into().unwrap());
                    }
                }
                // Solicited and override, unless it came from nobody in
                // particular, in which case the answer goes to everyone.
                let mut advert = [0u8; 32];
                advert[0] = 136;
                advert[4] = if source == UNSPECIFIED { 0x20 } else { 0x60 };
                advert[8..24].copy_from_slice(&target);
                advert[24..26].copy_from_slice(&[2, 1]);
                advert[26..32].copy_from_slice(&self.mac);
                let to = if source == UNSPECIFIED { ALL_NODES } else { source };
                self.send_icmpv6(&to, &mut advert);
            }
            // Neighbour advertisement.
            136 if from_link && message.len() >= 24 => {
                let target = read_ip(message, 8);
                if let Some((_, option)) = options(&message[24..]).find(|(kind, o)| *kind == 2 && o.len() >= 8) {
                    self.learn(target, option[2..8].try_into().unwrap());
                }
            }
            _ => {}
        }
    }

    /// Wrap `payload` in IPv6 and Ethernet and send it, finding the next hop's
    /// MAC first if need be.
    fn send_ipv6(&mut self, destination: &Ip, next_header: u8, payload: &[u8]) {
        let mut frame = [0u8; MAX_FRAME];
        let length = 54 + payload.len();
        if length > MAX_FRAME {
            return;
        }
        frame[6..12].copy_from_slice(&self.mac);
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        frame[20] = next_header;
        // Neighbour discovery insists on 255; nothing else minds it.
        frame[21] = 255;
        frame[22..38].copy_from_slice(&self.source_for(destination));
        frame[38..54].copy_from_slice(destination);
        frame[54..length].copy_from_slice(payload);

        if destination[0] == 0xFF {
            frame[0..2].copy_from_slice(&[0x33, 0x33]);
            frame[2..6].copy_from_slice(&destination[12..]);
            user::net_send(&frame[..length]);
            return;
        }
        let on_link = is_link_local(destination)
            || (self.global6 != UNSPECIFIED && destination[..8] == self.global6[..8]);
        let next_hop = if on_link { *destination } else { self.router6 };
        if next_hop == UNSPECIFIED {
            return;
        }
        if let Some(&(_, mac)) = self.arp.iter().find(|(known, _)| *known == next_hop) {
            frame[0..6].copy_from_slice(&mac);
            user::net_send(&frame[..length]);
            return;
        }
        self.park(&frame[..length], next_hop);
        self.solicit_neighbour(next_hop);
    }

    /// Checksum an ICMPv6 message and send it.
    fn send_icmpv6(&mut self, destination: &Ip, message: &mut [u8]) {
        message[2..4].fill(0);
        let source = self.source_for(destination);
        let sum = transport_checksum(PROTOCOL_ICMPV6, &source, destination, message);
        message[2..4].copy_from_slice(&sum.to_be_bytes());
        self.send_ipv6(destination, PROTOCOL_ICMPV6, message);
    }

    fn solicit_neighbour(&mut self, target: Ip) {
        let mut solicitation = [0u8; 32];
        solicitation[0] = 135;
        solicitation[8..24].copy_from_slice(&target);
        solicitation[24..26].copy_from_slice(&[1, 1]);
        solicitation[26..32].copy_from_slice(&self.mac);
        self.send_icmpv6(&solicited_node(&target), &mut solicitation);
    }

    fn solicit_router(&mut self) {
        let mut solicitation = [0u8; 16];
        solicitation[0] = 133;
        solicitation[8..10].copy_from_slice(&[1, 1]);
        solicitation[10..16].copy_from_slice(&self.mac);
        self.send_icmpv6(&ALL_ROUTERS, &mut solicitation);
    }

    fn solicit_tick(&mut self) {
        if self.global6 != UNSPECIFIED || self.solicited >= SOLICITATIONS {
            return;
        }
        self.solicit_waited += 1;
        if self.solicit_waited >= REQUEST_TICKS {
            self.solicit_waited = 0;
            self.solicited += 1;
            self.solicit_router();
        }
    }

    fn config6(&mut self, reply: u64) {
        if self.global6 != UNSPECIFIED {
            self.configured6(reply);
        } else if let Some(slot) = self.config6_waiters.iter_mut().find(|waiter| **waiter == 0) {
            *slot = reply;
        }
    }

    fn configured6(&self, reply: u64) {
        let half = |ip: &Ip, at: usize| u64::from_be_bytes(ip[at..at + 8].try_into().unwrap());
        let words = [half(&self.global6, 0), half(&self.global6, 8), half(&self.dns6, 0), half(&self.dns6, 8)];
        user::ipc_send(reply, &user::Message { tag: net::TAG_NET_CONFIGURED6, words, sender: 0, sender_user: 0 });
    }
}

/// The type-length-value options neighbour discovery carries: each option's
/// kind, and the whole option. Stops at one that claims no length or runs off
/// the end.
fn options(bytes: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut at = 0;
    core::iter::from_fn(move || {
        let length = *bytes.get(at + 1)? as usize * 8;
        if length == 0 || at + length > bytes.len() {
            return None;
        }
        let option = &bytes[at..at + length];
        at += length;
        Some((option[0], option))
    })
}
