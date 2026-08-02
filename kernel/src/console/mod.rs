//! Kernel console.
//!
//! Two sinks, deliberately kept separate:
//!
//! * `print!` / `println!` fan out to every sink that is up -- the serial port
//!   always, and the framebuffer once the bootloader's one has been adopted.
//! * `serial_print!` / `serial_println!` go *only* to the serial port. The test
//!   harness uses these so test chatter stays off the screen and remains cleanly
//!   machine-readable on the host's stdio.

pub mod font;
pub mod framebuffer;
pub mod uart;

use core::fmt;

use bootloader_api::info::FrameBufferInfo;

/// Bring up the serial console. Returns `false` if the UART self-test failed.
pub fn init() -> bool {
    uart::init()
}

/// Adopt the bootloader's framebuffer as a second sink.
pub fn init_framebuffer(info: FrameBufferInfo, buffer: &'static mut [u8]) {
    framebuffer::init(info, buffer);
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    uart::_print(args);
    framebuffer::_print(args);
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
