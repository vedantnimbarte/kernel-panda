//! Verifies that the IDT is installed and that a recoverable exception really
//! does resume the interrupted code.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::{arch::x86_64::halt_loop, testing, BOOTLOADER_CONFIG};

entry_point!(test_kernel_main, config = &BOOTLOADER_CONFIG);

fn test_kernel_main(boot_info: &'static mut BootInfo) -> ! {
    panda_kernel::init(boot_info);
    test_main();
    halt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    testing::panic_handler(info)
}

#[test_case]
fn breakpoint_exception_is_recoverable() {
    // With no IDT entry this escalates to a double and then a triple fault, and
    // QEMU dies without ever reaching the debug-exit port. Reaching the line
    // after `int3` proves the handler ran and `iret`ed back to us.
    x86_64::instructions::interrupts::int3();
}

#[test_case]
fn execution_continues_after_several_breakpoints() {
    // Re-entering the same handler repeatedly catches a handler that corrupts
    // the stack frame it returns through -- that failure survives one trip.
    for _ in 0..4 {
        x86_64::instructions::interrupts::int3();
    }
}
