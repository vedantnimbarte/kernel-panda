//! Kernel Panda boot binary.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::arch::x86_64::apic;
use panda_kernel::{arch::x86_64::halt_loop, console, memory, println, time, BOOTLOADER_CONFIG};

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
    println!(
        "  timer          : {}",
        if apic::is_initialised() {
            "Local APIC, periodic"
        } else {
            "unavailable"
        }
    );
    println!();

    memory::log_memory_map(&boot_info.memory_regions);
    println!();
    memory::log_usage();
    println!();

    // Proof that `alloc` is live: this allocates, grows, and reallocates.
    let squares: Vec<u64> = (1..=8u64).map(|n| n * n).collect();
    println!("alloc smoke test: {squares:?}");
    println!();

    // Proof the timer is live: without interrupts these would all read zero.
    // `hlt` parks the CPU until the next one arrives rather than spinning.
    println!("timer at {} Hz, waiting for ticks:", time::frequency_hz());
    for _ in 0..5 {
        let target = time::ticks() + time::frequency_hz() / 5;
        while time::ticks() < target {
            x86_64::instructions::hlt();
        }
        println!("  uptime {:>5} ms  ({} ticks)", time::uptime_ms(), time::ticks());
    }
    println!();

    halt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!();
    println!("KERNEL PANIC: {info}");
    halt_loop()
}
