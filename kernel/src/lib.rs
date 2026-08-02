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
/// Hands `boot_info` back so the caller can go on to use the rest of it: the
/// framebuffer is borrowed out of it here, and returning it is what keeps that
/// borrow from swallowing the whole structure.
pub fn init(boot_info: &'static mut BootInfo) -> &'static mut BootInfo {
    // Serial first: everything after this point can report its own failures.
    let serial_ok = console::init();

    // Then the descriptor tables, so a fault during the rest of boot produces a
    // readable diagnostic instead of a silent reset.
    arch::x86_64::init();

    adopt_framebuffer(boot_info);

    if !serial_ok {
        crate::println!("warning: UART loopback self-test failed; serial output may be lost");
    }

    boot_info
}

/// Hand the bootloader's framebuffer to the console.
fn adopt_framebuffer(boot_info: &mut BootInfo) {
    let Some(framebuffer) = boot_info.framebuffer.as_mut() else {
        return;
    };

    let info = framebuffer.info();
    let slice = framebuffer.buffer_mut();
    let ptr = slice.as_mut_ptr();
    let len = slice.len();

    // SAFETY: widening this borrow to 'static is sound because the bootloader
    // maps the framebuffer for the entire life of the kernel and never reclaims
    // it. `framebuffer::init` is the sole consumer and stores it behind a `Once`,
    // so the buffer is installed exactly once and never aliased -- the borrow we
    // took from `boot_info` ends here, leaving `boot_info` usable by callers.
    let buffer: &'static mut [u8] = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    console::init_framebuffer(info, buffer);
}
