//! The Ring 3 runtime for Kernel Panda.
//!
//! Thin wrappers over the syscall ABI, an entry-point macro, and a panic
//! handler. Deliberately tiny: everything here runs unprivileged, and the more
//! there is of it the more there is to get wrong in a process the kernel is
//! supposed to be able to distrust.

#![no_std]

use core::arch::asm;

/// Syscall numbers. Must match `kernel/src/syscall.rs`.
pub mod nr {
    pub const EXIT: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const YIELD: u64 = 2;
    pub const GET_TID: u64 = 3;
    pub const IPC_CREATE: u64 = 4;
    pub const IPC_SEND: u64 = 5;
    pub const IPC_RECV: u64 = 6;
    pub const IPC_GRANT: u64 = 7;
    pub const BUF_CREATE: u64 = 8;
    pub const BUF_MAP: u64 = 9;
    pub const BUF_SHARE: u64 = 10;
    pub const BUF_INFO: u64 = 11;
    pub const BUF_SCANOUT: u64 = 12;
    pub const READ: u64 = 13;
    pub const FILE_READ: u64 = 14;
    pub const FILE_WRITE: u64 = 15;
    pub const FILE_CREATE: u64 = 16;
    pub const FILE_REMOVE: u64 = 17;
    pub const FILE_STAT: u64 = 18;
    pub const FILE_LIST: u64 = 19;
    pub const PORT_READ: u64 = 20;
    pub const PORT_WRITE: u64 = 21;
    pub const IRQ_BIND: u64 = 22;
    pub const NET_INFO: u64 = 23;
    pub const NET_SEND: u64 = 24;
    pub const NET_RECEIVE: u64 = 25;
    pub const NET_BIND: u64 = 26;
    pub const RING_CREATE: u64 = 27;
    pub const RING_MAP: u64 = 28;
    pub const RING_WAIT: u64 = 29;
    pub const RING_WAKE: u64 = 30;
    pub const GET_USER: u64 = 31;
    pub const FILE_OWNER: u64 = 32;
    pub const FILE_CHMOD: u64 = 33;
}

/// Message layout shared with the kernel. Changing either side alone breaks IPC
/// silently.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Message {
    pub tag: u64,
    pub words: [u64; 4],
    /// Written by the kernel; whatever a sender puts here is discarded.
    pub sender: u64,
    /// The sender's user, written by the kernel the same way.
    pub sender_user: u64,
}

/// Buffer geometry, shared with the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BufferInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bytes_per_pixel: u32,
    pub size: u64,
}

/// Entry is a software interrupt, so RCX and R11 survive -- unlike `syscall`,
/// which clobbers both. Only RAX is modified by the kernel; everything else is
/// restored, which is why nothing else is listed as clobbered.
///
/// `nostack` is accurate: `int` pushes onto the *kernel* stack, not this one.
#[inline(always)]
pub fn syscall(number: u64, a: u64, b: u64, c: u64) -> i64 {
    let result: i64;
    // SAFETY: the kernel's syscall entry saves and restores every general
    // purpose register except RAX, which carries the return value.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            options(nostack),
        );
    }
    result
}

/// As [`syscall`], with a fourth argument.
///
/// R10 rather than RCX, matching the kernel's table. The Linux convention this
/// borrows from uses R10 for the fourth argument because `syscall` clobbers RCX
/// -- entry here is `int 0x80`, which does not, but keeping the register
/// assignment means the ABI does not have to change if the mechanism ever does.
#[inline(always)]
pub fn syscall4(number: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let result: i64;
    // SAFETY: as `syscall`; the kernel restores every register but RAX.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            options(nostack),
        );
    }
    result
}

pub fn exit(code: u64) -> ! {
    syscall(nr::EXIT, code, 0, 0);
    unreachable!()
}

pub fn write(text: &str) -> i64 {
    syscall(nr::WRITE, 1, text.as_ptr() as u64, text.len() as u64)
}

/// Read up to `buffer.len()` bytes, blocking until at least one arrives.
pub fn read(buffer: &mut [u8]) -> i64 {
    syscall(nr::READ, 0, buffer.as_mut_ptr() as u64, buffer.len() as u64)
}

pub fn yield_now() {
    syscall(nr::YIELD, 0, 0, 0);
}

pub fn thread_id() -> i64 {
    syscall(nr::GET_TID, 0, 0, 0)
}

pub fn ipc_send(endpoint: u64, message: &Message) -> i64 {
    syscall(nr::IPC_SEND, endpoint, message as *const Message as u64, 0)
}

pub fn ipc_receive(endpoint: u64, message: &mut Message) -> i64 {
    syscall(nr::IPC_RECV, endpoint, message as *mut Message as u64, 0)
}

/// A new endpoint, owned by the caller with every right. Returns its id.
pub fn ipc_create(capacity: u64) -> i64 {
    syscall(nr::IPC_CREATE, capacity, 0, 0)
}

pub fn ipc_grant(endpoint: u64, thread: u64, rights: u64) -> i64 {
    syscall(nr::IPC_GRANT, endpoint, thread, rights)
}

/// Read one byte from an I/O port this process was granted.
pub fn port_read(port: u16) -> i64 {
    syscall(nr::PORT_READ, port as u64, 0, 0)
}

pub fn port_write(port: u16, value: u8) -> i64 {
    syscall(nr::PORT_WRITE, port as u64, value as u64, 0)
}

/// Have interrupts on ISA line `irq` arrive on `endpoint` as messages.
pub fn irq_bind(irq: u64, endpoint: u64) -> i64 {
    syscall(nr::IRQ_BIND, irq, endpoint, 0)
}

/// The network card's MAC address. Network stack only.
pub fn net_info(mac: &mut [u8; 6]) -> i64 {
    syscall(nr::NET_INFO, mac.as_mut_ptr() as u64, 0, 0)
}

/// Put one Ethernet frame on the wire. Network stack only.
pub fn net_send(frame: &[u8]) -> i64 {
    syscall(nr::NET_SEND, frame.as_ptr() as u64, frame.len() as u64, 0)
}

/// Take one received frame; returns its length, or zero if none was waiting.
pub fn net_receive(buffer: &mut [u8]) -> i64 {
    syscall(nr::NET_RECEIVE, buffer.as_mut_ptr() as u64, buffer.len() as u64, 0)
}

/// Have arriving frames announced on `endpoint`. Network stack only.
pub fn net_bind(endpoint: u64) -> i64 {
    syscall(nr::NET_BIND, endpoint, 0, 0)
}

/// Tag of the kernel's "frames have arrived" notification.
pub const TAG_NET_RECEIVED: u64 = 0x2_0000;

/// Message rings shared between two processes. See `kernel/src/ring.rs` for the
/// layout and the reasoning behind it.
pub mod ring {
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::{nr, syscall};

    pub const SLOT_BYTES: usize = 64;
    pub type Slot = [u8; SLOT_BYTES];

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Side {
        Sender = 0,
        Receiver = 1,
    }

    const PAGE: u64 = 4096;

    /// Attempts before a side goes to sleep.
    ///
    /// Sleeping costs a system call and a wake another, and when the other side
    /// is running on its own core the next message is usually a few instructions
    /// away. Without this, a receiver that keeps up empties the ring after every
    /// message and sleeps each time -- which put 38,000 system calls into 50,000
    /// messages, most of the cost of an endpoint for none of its simplicity.
    const SPINS: u32 = 2_000;

    fn spin_for(mut attempt: impl FnMut() -> bool) -> bool {
        for _ in 0..SPINS {
            if attempt() {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Create a ring of `slots` messages. Returns its endpoint id, which is
    /// granted like any other.
    pub fn create(slots: u32) -> i64 {
        syscall(nr::RING_CREATE, slots as u64, 0, 0)
    }

    /// One side of a mapped ring.
    pub struct Ring {
        endpoint: u64,
        base: u64,
        slots: u32,
    }

    impl Ring {
        /// Map a side. Refused without the matching right, or if another
        /// thread already holds that side.
        pub fn map(endpoint: u64, side: Side) -> Result<Ring, i64> {
            let base = syscall(nr::RING_MAP, endpoint, side as u64, 0);
            if base < 0 {
                return Err(base);
            }
            let base = base as u64;
            // From the page neither side can write.
            let slots = Self::counter_at(base).load(Ordering::Relaxed);
            Ok(Ring { endpoint, base, slots })
        }

        fn counter_at(address: u64) -> &'static AtomicU32 {
            // SAFETY: inside the ring's header pages, mapped for as long as this
            // process lives. Read-only where this side may not write -- and
            // nothing here writes those.
            unsafe { &*(address as *const AtomicU32) }
        }

        fn tail(&self) -> &AtomicU32 {
            Self::counter_at(self.base + PAGE)
        }
        fn sender_sleeping(&self) -> &AtomicU32 {
            Self::counter_at(self.base + PAGE + 4)
        }
        fn head(&self) -> &AtomicU32 {
            Self::counter_at(self.base + 2 * PAGE)
        }
        fn receiver_sleeping(&self) -> &AtomicU32 {
            Self::counter_at(self.base + 2 * PAGE + 4)
        }

        fn slot(&self, index: u32) -> u64 {
            self.base + 3 * PAGE + (index % self.slots) as u64 * SLOT_BYTES as u64
        }

        /// Messages waiting, or `None` if the other side has broken the ring.
        fn queued(&self) -> Option<u32> {
            let queued = self.tail().load(Ordering::SeqCst).wrapping_sub(self.head().load(Ordering::SeqCst));
            (queued <= self.slots).then_some(queued)
        }

        fn wake_other(&self) {
            syscall(nr::RING_WAKE, self.endpoint, 0, 0);
        }

        /// Park until `ready`, flagging it first so the other side knows to
        /// wake this one. Returns false if the ring is broken.
        fn sleep_until(&self, flag: &AtomicU32, ready: impl Fn(u32) -> bool) -> bool {
            // An exchange, so the flag is committed before the look that follows.
            flag.swap(1, Ordering::SeqCst);
            let outcome = match self.queued() {
                None => false,
                Some(queued) if ready(queued) => true,
                Some(_) => {
                    syscall(nr::RING_WAIT, self.endpoint, 0, 0);
                    true
                }
            };
            flag.swap(0, Ordering::SeqCst);
            outcome
        }

        /// Send without waiting. False if the ring is full or broken.
        pub fn try_send(&self, message: &Slot) -> bool {
            let tail = self.tail().load(Ordering::SeqCst);
            match self.queued() {
                Some(queued) if queued < self.slots => {}
                _ => return false,
            }
            // SAFETY: a slot inside this side's writable slot pages.
            unsafe {
                core::ptr::copy_nonoverlapping(message.as_ptr(), self.slot(tail) as *mut u8, SLOT_BYTES)
            };
            // Published by exchange before the flag is read. See the kernel's
            // notes on why the order and the instruction both matter.
            self.tail().swap(tail.wrapping_add(1), Ordering::SeqCst);
            if self.receiver_sleeping().load(Ordering::SeqCst) != 0 {
                self.wake_other();
            }
            true
        }

        /// Send, waiting for room. False if the ring is broken.
        pub fn send(&self, message: &Slot) -> bool {
            loop {
                if spin_for(|| self.try_send(message)) {
                    return true;
                }
                if !self.sleep_until(self.sender_sleeping(), |queued| queued < self.slots) {
                    return false;
                }
            }
        }

        /// Receive without waiting. False if the ring is empty or broken.
        pub fn try_receive(&self, out: &mut Slot) -> bool {
            let head = self.head().load(Ordering::SeqCst);
            match self.queued() {
                Some(queued) if queued > 0 => {}
                _ => return false,
            }
            // SAFETY: a slot inside the slot pages, readable by both sides.
            unsafe {
                core::ptr::copy_nonoverlapping(self.slot(head) as *const u8, out.as_mut_ptr(), SLOT_BYTES)
            };
            self.head().swap(head.wrapping_add(1), Ordering::SeqCst);
            if self.sender_sleeping().load(Ordering::SeqCst) != 0 {
                self.wake_other();
            }
            true
        }

        /// Receive, waiting for a message. False if the ring is broken.
        pub fn receive(&self, out: &mut Slot) -> bool {
            loop {
                if spin_for(|| self.try_receive(out)) {
                    return true;
                }
                if !self.sleep_until(self.receiver_sleeping(), |queued| queued > 0) {
                    return false;
                }
            }
        }

        /// Where the ring is mapped. Tests use it to try writing where they may
        /// not.
        pub fn base(&self) -> u64 {
            self.base
        }
    }
}

/// What the network daemon and its clients say to each other.
///
/// Addresses are IPv4 in network order packed into the low 32 bits. A client
/// names a reply endpoint it has already granted the daemon `SEND` on, and
/// shares any buffer it names with the daemon first.
pub mod net {
    /// `[address, reply endpoint, token, 0]`: send an echo request. The answer
    /// arrives on the reply endpoint as [`TAG_PONG`].
    pub const TAG_PING: u64 = 1;
    /// `[token, address, 0, 0]`.
    pub const TAG_PONG: u64 = 2;
    /// `[port, reply endpoint, buffer, 0]`: datagrams to `port` are copied into
    /// `buffer` and announced as [`TAG_DATAGRAM`]. One datagram at a time: the
    /// next overwrites the last.
    pub const TAG_UDP_BIND: u64 = 3;
    /// `[length, source address, source port, local port]`.
    pub const TAG_DATAGRAM: u64 = 4;
    /// `[buffer, length, destination address, local port << 16 | remote port]`.
    pub const TAG_UDP_SEND: u64 = 5;

    pub const fn address(a: u8, b: u8, c: u8, d: u8) -> u64 {
        (a as u64) << 24 | (b as u64) << 16 | (c as u64) << 8 | d as u64
    }
}

/// The `sender` of a message the kernel wrote itself. No thread has this id.
pub const KERNEL_SENDER: u64 = u64::MAX;

/// Tag of an interrupt notification from the kernel. `words[0]` is the line.
pub const TAG_IRQ: u64 = 0x1_0000;

/// What the input daemon, the compositor and its clients say to each other.
pub mod input {
    /// Stop. From the input daemon, when escape is pressed.
    pub const TAG_SHUTDOWN: u64 = 0;
    /// `[ascii or 0, keycode, pressed, modifiers]`. The keycode is the set 1
    /// scancode, with 0x100 added for the E0-prefixed keys.
    pub const TAG_KEY: u64 = 1;
    /// `[dx, dy, buttons, 0]`. Screen directions -- positive dy is down -- as
    /// two's complement. Buttons: bit 0 left, 1 right, 2 middle.
    pub const TAG_POINTER: u64 = 3;
    /// From a client: send my key events to endpoint `words[0]` while I have
    /// focus. The compositor must already hold `SEND` on it.
    pub const TAG_LISTEN: u64 = 4;
    /// From the kernel only: thread `words[0]` is the input daemon, and its key
    /// and pointer events are to be believed.
    pub const TAG_INPUT_SOURCE: u64 = 5;

    pub const MODIFIER_SHIFT: u64 = 1 << 0;
    pub const MODIFIER_CTRL: u64 = 1 << 1;
    pub const MODIFIER_ALT: u64 = 1 << 2;
}

pub fn buffer_create(width: u64, height: u64) -> i64 {
    syscall(nr::BUF_CREATE, width, height, 0)
}

pub fn buffer_map(buffer: u64) -> i64 {
    syscall(nr::BUF_MAP, buffer, 0, 0)
}

pub fn buffer_share(buffer: u64, target: u64) -> i64 {
    syscall(nr::BUF_SHARE, buffer, target, 0)
}

pub fn buffer_info(buffer: u64, info: &mut BufferInfo) -> i64 {
    syscall(nr::BUF_INFO, buffer, info as *mut BufferInfo as u64, 0)
}

pub fn scanout() -> i64 {
    syscall(nr::BUF_SCANOUT, 0, 0, 0)
}

// --- files -------------------------------------------------------------------

/// Read a whole file into `buffer`. Returns the bytes read.
pub fn file_read(path: &str, buffer: &mut [u8]) -> i64 {
    syscall4(
        nr::FILE_READ,
        path.as_ptr() as u64,
        path.len() as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    )
}

/// Replace a file's contents.
pub fn file_write(path: &str, data: &[u8]) -> i64 {
    syscall4(
        nr::FILE_WRITE,
        path.as_ptr() as u64,
        path.len() as u64,
        data.as_ptr() as u64,
        data.len() as u64,
    )
}

pub fn file_create(path: &str) -> i64 {
    syscall(nr::FILE_CREATE, path.as_ptr() as u64, path.len() as u64, 0)
}

pub fn dir_create(path: &str) -> i64 {
    syscall(nr::FILE_CREATE, path.as_ptr() as u64, path.len() as u64, 1)
}

pub fn file_remove(path: &str) -> i64 {
    syscall(nr::FILE_REMOVE, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Size into `size`; returns 1 for a directory, 0 for a file.
pub fn file_stat(path: &str, size: &mut u64) -> i64 {
    syscall(
        nr::FILE_STAT,
        path.as_ptr() as u64,
        path.len() as u64,
        size as *mut u64 as u64,
    )
}

/// The user this process runs as.
pub fn user_id() -> i64 {
    syscall(nr::GET_USER, 0, 0, 0)
}

/// A node's owner and permission bits, as `owner << 16 | mode`.
pub fn file_owner(path: &str) -> i64 {
    syscall(nr::FILE_OWNER, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Change a node's permission bits: bit 0 owner read, 1 owner write, 2 others
/// read, 3 others write. Its owner only.
pub fn file_chmod(path: &str, mode: u16) -> i64 {
    syscall(nr::FILE_CHMOD, path.as_ptr() as u64, path.len() as u64, mode as u64)
}

/// Returned when the caller's user may not do that to a file.
pub const PERMISSION_DENIED: i64 = -15;

/// Newline-separated names into `buffer`. Returns the bytes written.
pub fn dir_list(path: &str, buffer: &mut [u8]) -> i64 {
    syscall4(
        nr::FILE_LIST,
        path.as_ptr() as u64,
        path.len() as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    )
}

/// Write a decimal number to the console.
///
/// Formatting belongs in user space, not behind a syscall -- the kernel's job is
/// to move bytes, not to know what a number looks like.
pub fn write_number(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut index = digits.len();

    if value == 0 {
        write("0");
        return;
    }
    while value > 0 {
        index -= 1;
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    // SAFETY: every byte written above is an ASCII digit.
    write(unsafe { core::str::from_utf8_unchecked(&digits[index..]) });
}

/// Define a program's entry point.
///
/// The kernel enters at the ELF entry with the start-up argument in R15, so the
/// first thing that must happen is moving it somewhere the ABI can see, before
/// the compiler emits anything that might clobber it. A naked function is the
/// only way to be certain of that.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "C" fn _start() -> ! {
            ::core::arch::naked_asm!(
                "mov rdi, r15",
                "call {main}",
                // Returning from main is the same as exiting cleanly.
                "mov rax, 0",
                "xor rdi, rdi",
                "int 0x80",
                "ud2",
                main = sym $main,
            )
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    write("  [ring 3] panic: ");
    if let Some(message) = info.message().as_str() {
        write(message);
    } else {
        write("(unprintable)");
    }
    write("\n");
    exit(1)
}
