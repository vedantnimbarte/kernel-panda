//! Kernel Panda: a bare-metal microkernel written in `no_std` Rust.
//!
//! Everything lives in the library so that the boot binary (`src/main.rs`) and
//! every integration test kernel under `tests/` share exactly one implementation.

#![no_std]
// Required for `extern "x86-interrupt"` exception handlers, which need the
// compiler to emit an iret-based epilogue and preserve the full register set.
#![feature(abi_x86_interrupt)]

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::BootInfo;

pub mod arch;
pub mod console;
pub mod sync;
pub mod testing;

/// Boot-time requests handed to the bootloader.
///
/// This is a `const` rather than a `static` on purpose: `entry_point!` serialises
/// it inside a const initialiser, and reading a `static` in const context is not
/// allowed.
pub const BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();

    // Map all of physical memory at a fixed virtual offset. This populates
    // `BootInfo::physical_memory_offset`, without which none of the Phase 2
    // page-table work is possible -- so it goes in from the very first boot
    // rather than being retrofitted later.
    config.mappings.physical_memory = Some(Mapping::Dynamic);

    // The default stack is tight for unoptimised debug builds, whose stack
    // frames are several times larger than release ones.
    config.kernel_stack_size = 128 * 1024;

    config
};

/// Bring up the subsystems every entry point needs before it can do anything
/// observable. Call exactly once, first thing.
///
/// Takes and returns `boot_info` so that later stages -- which borrow the
/// framebuffer and the memory map out of it -- can be added here without
/// changing every caller.
pub fn init(boot_info: &'static mut BootInfo) -> &'static mut BootInfo {
    // Serial first: everything after this point can report its own failures.
    let serial_ok = console::init();

    // Then the descriptor tables, so a fault during the rest of boot produces a
    // readable diagnostic instead of a silent reset.
    arch::x86_64::init();

    if !serial_ok {
        crate::println!("warning: UART loopback self-test failed; serial output may be lost");
    }

    boot_info
}
