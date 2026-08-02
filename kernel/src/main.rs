//! Kernel Panda boot binary.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::{arch::x86_64::halt_loop, BOOTLOADER_CONFIG};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    halt_loop()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt_loop()
}
