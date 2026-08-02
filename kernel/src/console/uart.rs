//! A 16550 UART driver for the serial console.
//!
//! Written in-house rather than pulled from crates.io: it is barely a hundred
//! lines, it is the PRD's Phase 1 Milestone 3 in its own right, and the serial
//! port is the one output path the whole system is debugged through. It should
//! not be something we take on trust.
//!
//! Register layout, all offsets from the port base. Note that offsets 0 and 1
//! change meaning depending on the DLAB bit in the line-control register:
//!
//! ```text
//! +0  DLAB=0  RBR (read) / THR (write)     received / transmit byte
//! +0  DLAB=1  DLL                          baud rate divisor, low byte
//! +1  DLAB=0  IER                          interrupt enable
//! +1  DLAB=1  DLM                          baud rate divisor, high byte
//! +2          IIR (read) / FCR (write)     interrupt id / FIFO control
//! +3          LCR                          line control (word length, DLAB)
//! +4          MCR                          modem control (DTR/RTS/loopback)
//! +5          LSR                          line status (data ready, THR empty)
//! ```

use core::fmt;

use x86_64::instructions::port::{Port, PortReadOnly};

use crate::sync::Mutex;

/// First serial port. Fixed by convention on every PC-compatible machine, and
/// the port QEMU attaches to stdio.
pub const COM1_BASE: u16 = 0x3F8;

/// Line control: set DLAB to expose the divisor latch at offsets 0 and 1.
const LCR_DLAB: u8 = 0x80;
/// Line control: 8 data bits, no parity, one stop bit. Also clears DLAB.
const LCR_8N1: u8 = 0x03;

/// Divisor 3 against the 115200 Hz base clock gives 38400 baud.
const DIVISOR_38400_LO: u8 = 0x03;
const DIVISOR_38400_HI: u8 = 0x00;

/// Enable the FIFOs, clear both of them, and interrupt at a 14-byte threshold.
const FCR_ENABLE_AND_CLEAR: u8 = 0xC7;

/// Modem control: loopback, plus OUT1/OUT2/RTS. Used only for the self-test.
const MCR_LOOPBACK: u8 = 0x1E;
/// Modem control: DTR, RTS, OUT1, OUT2 asserted; loopback off.
const MCR_NORMAL: u8 = 0x0F;

/// Line status: a received byte is waiting in the receive buffer.
const LSR_DATA_READY: u8 = 0x01;
/// Line status: the transmit holding register is free.
const LSR_THR_EMPTY: u8 = 0x20;

/// Arbitrary bound so a missing or wedged UART cannot hang the boot.
const SELF_TEST_SPINS: u32 = 100_000;

pub struct SerialPort {
    data: Port<u8>,
    interrupt_enable: Port<u8>,
    fifo_control: Port<u8>,
    line_control: Port<u8>,
    modem_control: Port<u8>,
    line_status: PortReadOnly<u8>,
}

impl SerialPort {
    pub const fn new(base: u16) -> Self {
        Self {
            data: Port::new(base),
            interrupt_enable: Port::new(base + 1),
            fifo_control: Port::new(base + 2),
            line_control: Port::new(base + 3),
            modem_control: Port::new(base + 4),
            line_status: PortReadOnly::new(base + 5),
        }
    }

    /// Configure the port for 38400 8N1 with FIFOs on.
    ///
    /// Returns `false` if the loopback self-test fails, which means there is no
    /// real 16550 behind these ports.
    pub fn init(&mut self) -> bool {
        // SAFETY: these are the architecturally fixed 16550 register offsets from
        // a port base supplied at construction. The only base used in this kernel
        // is COM1 (0x3F8), which is present on the QEMU machine model and on all
        // PC-compatible hardware. No other device is touched.
        unsafe {
            self.interrupt_enable.write(0x00); // mask every UART interrupt source
            self.line_control.write(LCR_DLAB); // remap offsets 0/1 to the divisor
            self.data.write(DIVISOR_38400_LO);
            self.interrupt_enable.write(DIVISOR_38400_HI);
            self.line_control.write(LCR_8N1); // 8N1, and drop DLAB again
            self.fifo_control.write(FCR_ENABLE_AND_CLEAR);

            // Prove the chip is actually present before trusting it with every
            // log line the kernel will ever emit. In loopback the byte we send
            // must come straight back; an absent UART floats high and reads 0xFF.
            self.modem_control.write(MCR_LOOPBACK);
            self.data.write(0xAE);

            let mut spins = 0;
            while self.line_status.read() & LSR_DATA_READY == 0 {
                spins += 1;
                if spins > SELF_TEST_SPINS {
                    return false;
                }
                core::hint::spin_loop();
            }
            if self.data.read() != 0xAE {
                return false;
            }

            self.modem_control.write(MCR_NORMAL);
        }
        true
    }

    /// Take a received byte if one is waiting.
    pub fn try_read_byte(&mut self) -> Option<u8> {
        // SAFETY: polling LSR and reading RBR on the port configured by `init`.
        unsafe {
            if self.line_status.read() & LSR_DATA_READY == 0 {
                return None;
            }
            Some(self.data.read())
        }
    }

    pub fn write_byte(&mut self, byte: u8) {
        // SAFETY: polling LSR and writing THR on the port configured by `init`.
        // If no UART is present LSR reads 0xFF, so the drain loop sees THR_EMPTY
        // set and falls through rather than spinning forever.
        unsafe {
            while self.line_status.read() & LSR_THR_EMPTY == 0 {
                core::hint::spin_loop();
            }
            self.data.write(byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            // Terminals attached to a serial line want CRLF; the kernel emits
            // bare LF everywhere else.
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

pub static COM1: Mutex<SerialPort> = Mutex::new(SerialPort::new(COM1_BASE));

/// Returns `false` if the loopback self-test did not pass.
pub fn init() -> bool {
    COM1.lock().init()
}

/// Drain any bytes the UART has received.
///
/// Returns how many were handed to `sink`.
pub fn drain_input(mut sink: impl FnMut(u8)) -> usize {
    let mut port = COM1.lock();
    let mut count = 0;
    // Bounded by the FIFO depth, so a stuck data-ready bit cannot spin forever.
    while count < 32 {
        match port.try_read_byte() {
            Some(byte) => {
                sink(byte);
                count += 1;
            }
            None => break,
        }
    }
    count
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    // A write to a dead port is harmless, so this is not gated on `init`
    // succeeding -- losing the log output would be strictly worse than emitting
    // into the void.
    let _ = COM1.lock().write_fmt(args);
}
