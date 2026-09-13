//! The input daemon: the PS/2 driver, in Ring 3.
//!
//! Owns the i8042 keyboard controller and nothing else. It reaches the
//! controller's two ports through system calls it was granted, hears the
//! keyboard and mouse interrupt lines as messages from the kernel, and turns
//! what the devices say into key and pointer events for one consumer -- the
//! compositor. No other process holds the grants, which is what stops anything
//! else from watching the keyboard.
//!
//! The controller does no DMA, so unlike the disk driver this one is genuinely
//! contained: the worst a compromised input daemon can do is lie about keys.

#![no_std]
#![no_main]

use panda_user::{self as user, input};

user::entry!(main);

const DATA: u16 = 0x60;
/// Status when read, command when written.
const COMMAND: u16 = 0x64;

const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;
/// The byte waiting came from the mouse.
const STATUS_FROM_MOUSE: u8 = 1 << 5;

const KEYBOARD_IRQ: u64 = 1;
const MOUSE_IRQ: u64 = 12;

/// Set 1 scancode of the escape key, which ends the session.
const ESCAPE: u64 = 0x01;

/// How long to poll the controller during start-up. Generous: every poll is a
/// system call, and a controller that is not there must fail rather than hang.
const POLLS: usize = 100_000;

extern "C" fn main(consumer: u64) {
    let interrupts = user::ipc_create(16);
    if interrupts < 0 {
        fail("could not create an endpoint");
    }
    let interrupts = interrupts as u64;

    if !init_controller() {
        fail("the PS/2 controller did not answer");
    }

    // Bound, then drained. An interrupt raised before the bind went nowhere, and
    // the line is edge-triggered, so whatever it announced is only found by
    // looking.
    if user::irq_bind(KEYBOARD_IRQ, interrupts) < 0 || user::irq_bind(MOUSE_IRQ, interrupts) < 0 {
        fail("could not bind the controller's interrupts");
    }

    let mut decoder = Decoder::new(consumer);
    drain(&mut decoder);

    loop {
        let mut message = user::Message::default();
        if user::ipc_receive(interrupts, &mut message) < 0 {
            user::exit(1);
        }
        if message.sender == user::KERNEL_SENDER && message.tag == user::TAG_IRQ {
            drain(&mut decoder);
        }
    }
}

fn fail(why: &str) -> ! {
    user::write("  [input] ");
    user::write(why);
    user::write("\n");
    user::exit(1)
}

fn status() -> u8 {
    user::port_read(COMMAND) as u8
}

/// Wait until the controller will take another byte.
fn ready_for_input() -> bool {
    (0..POLLS).any(|_| status() & STATUS_INPUT_FULL == 0)
}

fn command(byte: u8) -> bool {
    ready_for_input() && user::port_write(COMMAND, byte) >= 0
}

fn write_data(byte: u8) -> bool {
    ready_for_input() && user::port_write(DATA, byte) >= 0
}

fn read_data() -> Option<u8> {
    (0..POLLS)
        .find(|_| status() & STATUS_OUTPUT_FULL != 0)
        .map(|_| user::port_read(DATA) as u8)
}

/// Put the controller in a known state: both devices on, both interrupts on,
/// and the keyboard translated to scancode set 1.
///
/// Whatever the firmware left behind is not trusted -- some leave translation
/// off, some leave the mouse clock disabled -- so the configuration byte is
/// rewritten rather than assumed.
fn init_controller() -> bool {
    // Both devices off while this happens, so nothing they send is mistaken for
    // a reply.
    if !command(0xAD) || !command(0xA7) {
        return false;
    }
    for _ in 0..16 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        user::port_read(DATA);
    }

    if !command(0x20) {
        return false;
    }
    let Some(mut config) = read_data() else {
        return false;
    };
    // Bits 0 and 1: interrupt on keyboard and mouse data. Bit 6: translate to
    // set 1. Bits 4 and 5: the two clocks' *disable* bits, cleared.
    config |= 0x01 | 0x02 | 0x40;
    config &= !0x30;
    if !command(0x60) || !write_data(config) {
        return false;
    }

    if !command(0xAE) || !command(0xA8) {
        return false;
    }

    // Tell the mouse to start reporting. It acknowledges with 0xFA; a machine
    // without one does not, and that is not a reason to lose the keyboard.
    if command(0xD4) && write_data(0xF4) {
        let _ = read_data();
    }
    true
}

/// Read everything the controller has.
///
/// Bounded, so a status bit stuck high cannot pin a core. The controller holds
/// one byte at a time and raises a fresh interrupt for the next, so stopping
/// early loses nothing.
fn drain(decoder: &mut Decoder) {
    for _ in 0..64 {
        let status = status();
        if status & STATUS_OUTPUT_FULL == 0 {
            return;
        }
        let byte = user::port_read(DATA) as u8;
        if status & STATUS_FROM_MOUSE != 0 {
            decoder.mouse(byte);
        } else {
            decoder.key(byte);
        }
    }
}

/// US layout, indexed by set 1 scancode, for 0x00 to 0x39.
const UNSHIFTED: &[u8; 0x3A] =
    b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
const SHIFTED: &[u8; 0x3A] =
    b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

struct Decoder {
    consumer: u64,
    /// The previous byte was 0xE0.
    extended: bool,
    left_shift: bool,
    right_shift: bool,
    ctrl: bool,
    alt: bool,
    packet: [u8; 3],
    filled: usize,
}

impl Decoder {
    fn new(consumer: u64) -> Self {
        Self {
            consumer,
            extended: false,
            left_shift: false,
            right_shift: false,
            ctrl: false,
            alt: false,
            packet: [0; 3],
            filled: 0,
        }
    }

    fn send(&self, tag: u64, words: [u64; 4]) {
        let message = user::Message {
            tag,
            words,
            sender: 0,
        };
        user::ipc_send(self.consumer, &message);
    }

    /// One set 1 byte. The Pause key's E1 sequence is not recognised; its bytes
    /// come out as meaningless key events rather than being decoded.
    fn key(&mut self, byte: u8) {
        if byte == 0xE0 {
            self.extended = true;
            return;
        }

        let pressed = byte & 0x80 == 0;
        let code = (byte & 0x7F) as u64 | if self.extended { 0x100 } else { 0 };
        self.extended = false;

        match code {
            0x2A => self.left_shift = pressed,
            0x36 => self.right_shift = pressed,
            0x1D | 0x11D => self.ctrl = pressed,
            0x38 | 0x138 => self.alt = pressed,
            _ => {}
        }

        if code == ESCAPE && pressed {
            self.send(input::TAG_SHUTDOWN, [0; 4]);
            user::exit(0);
        }

        let shift = self.left_shift || self.right_shift;
        let modifiers = if shift { input::MODIFIER_SHIFT } else { 0 }
            | if self.ctrl { input::MODIFIER_CTRL } else { 0 }
            | if self.alt { input::MODIFIER_ALT } else { 0 };

        let table = if shift { SHIFTED } else { UNSHIFTED };
        let ascii = match table.get(code as usize) {
            // Sanitised: printable characters and the few control keys a text
            // consumer expects. Nothing else is passed off as text.
            Some(&ch) if pressed && ((0x20..=0x7E).contains(&ch) || b"\n\t\x08".contains(&ch)) => {
                ch as u64
            }
            _ => 0,
        };

        self.send(input::TAG_KEY, [ascii, code, pressed as u64, modifiers]);
    }

    /// One byte of a three-byte mouse packet.
    fn mouse(&mut self, byte: u8) {
        // The first byte always has bit 3 set. Anything else here means a byte
        // was lost, and accepting it would misread every packet after.
        if self.filled == 0 && byte & 0x08 == 0 {
            return;
        }
        self.packet[self.filled] = byte;
        self.filled += 1;
        if self.filled < 3 {
            return;
        }
        self.filled = 0;

        let [flags, x, y] = self.packet;
        // Overflow: the movement is meaningless, not merely large.
        if flags & 0xC0 != 0 {
            return;
        }
        // Nine-bit two's complement, the ninth bit in the flags.
        let dx = x as i64 - if flags & 0x10 != 0 { 256 } else { 0 };
        let dy = y as i64 - if flags & 0x20 != 0 { 256 } else { 0 };

        // PS/2 counts up as positive; the screen counts down.
        self.send(
            input::TAG_POINTER,
            [dx as u64, (-dy) as u64, (flags & 0x07) as u64, 0],
        );
    }
}
