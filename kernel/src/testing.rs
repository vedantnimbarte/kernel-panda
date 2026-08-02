//! Support for the custom test framework.
//!
//! There is no `std`, so there is no libtest. Each file under `tests/` compiles
//! into a complete, standalone kernel that boots under QEMU, runs its cases, and
//! reports the verdict through the `isa-debug-exit` device. `xtask runner` turns
//! that into a process exit code cargo understands.

use core::panic::PanicInfo;

use crate::arch::x86_64::qemu::{self, ExitCode};
use crate::{serial_print, serial_println};

pub trait Testable {
    fn run(&self);
}

impl<T: Fn()> Testable for T {
    fn run(&self) {
        // `type_name` gives the fully-qualified function path, which is the most
        // useful label available without a heap or a test-name registry.
        serial_print!("{} ... ", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

/// Entry point named by `#![test_runner(...)]` in each test kernel.
pub fn runner(tests: &[&dyn Testable]) {
    serial_println!("running {} test(s)", tests.len());
    for test in tests {
        test.run();
    }
    qemu::exit(ExitCode::Success);
}

/// Panic handler for test kernels: report and fail the run immediately, rather
/// than halting and letting the host time out.
pub fn panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[FAILED]");
    serial_println!("{info}");
    qemu::exit(ExitCode::Failed)
}
