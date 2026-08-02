//! Proves the whole pipeline works end to end: the image builds, the bootloader
//! hands off, the kernel initialises, and the serial console can carry a verdict
//! back to the host.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::{arch::x86_64::halt_loop, serial_println, testing, BOOTLOADER_CONFIG};

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
fn serial_console_carries_output() {
    serial_println!("(this line proves the serial sink is live)");
}

#[test_case]
fn init_brought_every_subsystem_up() {
    // Reaching a test case at all proves `entry_point!` accepted our config and
    // the bootloader handed over with a working stack. These assertions cover
    // the rest of `init`, which reports nothing on success.
    assert!(
        panda_kernel::memory::frame::is_initialised(),
        "frame allocator was not initialised"
    );
    assert!(
        panda_kernel::memory::paging::is_initialised(),
        "page tables were not adopted"
    );
    assert!(
        panda_kernel::allocator::stats().size > 0,
        "the heap was never given any memory"
    );
}
