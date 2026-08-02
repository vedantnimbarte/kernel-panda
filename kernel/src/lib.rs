//! Kernel Panda: a bare-metal microkernel written in `no_std` Rust.
//!
//! Everything lives in the library so that the boot binary (`src/main.rs`) and
//! every integration test kernel under `tests/` share exactly one implementation.

#![no_std]

use bootloader_api::config::{BootloaderConfig, Mapping};

pub mod arch;
pub mod sync;

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
