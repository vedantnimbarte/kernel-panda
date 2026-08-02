//! Kernel console.
//!
//! Two sinks, deliberately kept separate:
//!
//! * `print!` / `println!` fan out to every sink that is up. Today that is the
//!   serial port alone.
//! * `serial_print!` / `serial_println!` go *only* to the serial port. The test
//!   harness uses these so test chatter stays off the screen and remains cleanly
//!   machine-readable on the host's stdio.

pub mod uart;

use core::fmt;

/// Bring up the serial console. Returns `false` if the UART self-test failed.
pub fn init() -> bool {
    uart::init()
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    uart::_print(args);
}

#[doc(hidden)]
pub fn _serial_print(args: fmt::Arguments) {
    uart::_print(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::console::_serial_print(::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => {
        $crate::console::_serial_print(
            ::core::format_args!("{}\n", ::core::format_args!($($arg)*))
        )
    };
}
