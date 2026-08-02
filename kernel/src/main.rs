//! Kernel Panda boot binary.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::{arch::x86_64::halt_loop, console, memory, println, BOOTLOADER_CONFIG};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    let boot_info = panda_kernel::init(boot_info);

    println!();
    println!("Kernel Panda v{}", env!("CARGO_PKG_VERSION"));
    println!("  serial console : COM1 @ 38400 8N1");
    println!(
        "  framebuffer    : {}",
        if console::framebuffer::is_available() {
            "online"
        } else {
            "not provided by bootloader"
        }
    );
    println!("  descriptor tbls: GDT + TSS + IDT loaded");
    println!();

    memory::log_memory_map(&boot_info.memory_regions);
    println!();
    memory::log_usage();
    println!();

    halt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!();
    println!("KERNEL PANIC: {info}");
    halt_loop()
}
