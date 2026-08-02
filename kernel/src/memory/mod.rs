//! Physical and virtual memory management.
//!
//! Brought up in a fixed order, each step depending on the one before it:
//!
//! 1. Read the bootloader's memory map to learn what RAM exists.
//! 2. Build the physical frame allocator over it.
//! 3. Adopt the page tables, which need the frame allocator for intermediate
//!    tables.
//! 4. Map and initialise the kernel heap, which needs both.

pub mod frame;
pub mod heap;
pub mod kstack;
pub mod paging;

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use bootloader_api::BootInfo;
use x86_64::VirtAddr;

use crate::println;

/// x86_64 base page size. Everything here works in 4 KiB frames; huge pages are
/// a Phase 3 concern.
pub const PAGE_SIZE: u64 = 4096;

/// Bring up the whole memory subsystem.
///
/// # Panics
///
/// If the bootloader did not provide the physical memory mapping that
/// `BOOTLOADER_CONFIG` asks for, or if the heap cannot be mapped. Neither is
/// recoverable -- there is no kernel without them.
pub fn init(boot_info: &mut BootInfo) {
    let physical_memory_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect(
            "bootloader provided no physical memory offset; \
             BOOTLOADER_CONFIG.mappings.physical_memory must be Mapping::Dynamic",
        );

    // SAFETY: the offset above is the bootloader's own answer to the mapping we
    // requested, so all physical memory really is mapped and writable there.
    // Both calls happen exactly once, here, in dependency order: the page-table
    // mapper needs the frame allocator to build intermediate tables.
    unsafe {
        frame::init(&boot_info.memory_regions, physical_memory_offset);
        paging::init(VirtAddr::new(physical_memory_offset));
    }

    heap::init().expect("failed to map the kernel heap");
}

/// Print the bootloader's memory map and the totals derived from it.
pub fn log_memory_map(regions: &MemoryRegions) {
    println!("physical memory map:");

    let mut usable_bytes = 0u64;
    for region in regions.iter() {
        let len = region.end - region.start;
        if region.kind == MemoryRegionKind::Usable {
            usable_bytes += len;
        }
        let (value, unit) = human_size(len);
        println!(
            "  {:#013x}..{:#013x}  {value:>5} {unit:<3}  {:?}",
            region.start, region.end, region.kind
        );
    }

    let (value, unit) = human_size(usable_bytes);
    println!("  usable: {value} {unit} across {} regions", regions.len());
}

/// Report frame allocator and heap occupancy.
pub fn log_usage() {
    frame::with(|allocator| {
        let (total, unit) = human_size(allocator.total_frames() as u64 * PAGE_SIZE);
        let (free, free_unit) = human_size(allocator.free_frames() as u64 * PAGE_SIZE);
        println!(
            "frames: {} total ({total} {unit}), {} free ({free} {free_unit}), {} in use",
            allocator.total_frames(),
            allocator.free_frames(),
            allocator.used_frames(),
        );
    });

    let stats = crate::allocator::stats();
    println!(
        "heap:   {} bytes total, {} allocated, {} peak, {} live allocations",
        stats.size, stats.allocated, stats.peak, stats.allocations
    );
}

/// Split a byte count into a value and a unit, using integer arithmetic only.
fn human_size(bytes: u64) -> (u64, &'static str) {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    const TIB: u64 = 1024 * GIB;

    if bytes >= TIB {
        (bytes / TIB, "TiB")
    } else if bytes >= GIB {
        (bytes / GIB, "GiB")
    } else if bytes >= MIB {
        (bytes / MIB, "MiB")
    } else if bytes >= KIB {
        (bytes / KIB, "KiB")
    } else {
        (bytes, "B")
    }
}
