//! Physical frame allocator, backed by a bitmap.
//!
//! One bit per 4 KiB frame, `1` meaning in use. The obvious alternative -- walking
//! the bootloader's usable regions and handing out the next frame each time -- is
//! simpler, but it cannot free. A microkernel hands physical memory back every
//! time a Ring 3 process exits, so an allocate-only design would have to be
//! thrown away in Phase 3. Better to pay for the bitmap now.
//!
//! There is no bootstrapping problem: the bootloader has already mapped all of
//! physical memory at `physical_memory_offset`, so the bitmap can be written
//! into a usable region directly, before the kernel controls any page tables.

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::PAGE_SIZE;
use crate::sync::{Mutex, Once};

pub struct BitmapFrameAllocator {
    /// One bit per frame; bit set means allocated.
    bitmap: &'static mut [u8],
    /// Number of frames the bitmap covers.
    total_frames: usize,
    used_frames: usize,
    /// Where the next linear search starts, so a long run of allocations does
    /// not rescan the same prefix every time.
    next_hint: usize,
}

impl BitmapFrameAllocator {
    fn is_used(&self, frame: usize) -> bool {
        self.bitmap[frame / 8] & (1 << (frame % 8)) != 0
    }

    fn mark_used(&mut self, frame: usize) {
        if frame >= self.total_frames || self.is_used(frame) {
            return;
        }
        self.bitmap[frame / 8] |= 1 << (frame % 8);
        self.used_frames += 1;
    }

    fn mark_free(&mut self, frame: usize) {
        if frame >= self.total_frames || !self.is_used(frame) {
            return;
        }
        self.bitmap[frame / 8] &= !(1 << (frame % 8));
        self.used_frames -= 1;
    }

    /// Allocate one frame, or `None` if physical memory is exhausted.
    pub fn allocate(&mut self) -> Option<PhysFrame<Size4KiB>> {
        // Search from the hint first, then wrap and cover what was skipped.
        let found = self
            .find_free(self.next_hint, self.total_frames)
            .or_else(|| self.find_free(0, self.next_hint))?;

        self.mark_used(found);
        self.next_hint = found + 1;
        Some(frame_at(found))
    }

    /// Allocate `count` physically contiguous frames.
    ///
    /// Needed by device drivers whose DMA engines cannot scatter-gather. Unused
    /// today, but the bitmap is the only structure that can answer this cheaply,
    /// so the capability belongs here rather than being bolted on later.
    pub fn allocate_contiguous(&mut self, count: usize) -> Option<PhysFrame<Size4KiB>> {
        if count == 0 {
            return None;
        }

        let mut start = 0;
        while start + count <= self.total_frames {
            match (start..start + count).find(|&f| self.is_used(f)) {
                // A used frame inside the window: the next possible start is
                // just past it, so skip the whole span rather than sliding by one.
                Some(blocked) => start = blocked + 1,
                None => {
                    for frame in start..start + count {
                        self.mark_used(frame);
                    }
                    return Some(frame_at(start));
                }
            }
        }
        None
    }

    /// Return a frame to the pool.
    pub fn deallocate(&mut self, frame: PhysFrame<Size4KiB>) {
        let index = (frame.start_address().as_u64() / PAGE_SIZE) as usize;
        debug_assert!(
            self.is_used(index),
            "double free of physical frame {index:#x}"
        );
        self.mark_free(index);
        // Bias the next search backwards so freed memory is reused promptly.
        self.next_hint = self.next_hint.min(index);
    }

    fn find_free(&self, from: usize, to: usize) -> Option<usize> {
        (from..to.min(self.total_frames)).find(|&f| !self.is_used(f))
    }

    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    pub fn used_frames(&self) -> usize {
        self.used_frames
    }

    pub fn free_frames(&self) -> usize {
        self.total_frames - self.used_frames
    }
}

// SAFETY: every frame handed out is marked used in the bitmap before it is
// returned, and is only ever returned again after an explicit `deallocate`. The
// bitmap starts fully set and is cleared only for regions the bootloader
// reported as `Usable`, so frames holding the kernel, the bootloader's own
// structures, or MMIO are never produced.
unsafe impl FrameAllocator<Size4KiB> for BitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate()
    }
}

impl FrameDeallocator<Size4KiB> for BitmapFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        self.deallocate(frame);
    }
}

fn frame_at(index: usize) -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(PhysAddr::new(index as u64 * PAGE_SIZE))
}

static ALLOCATOR: Once<Mutex<BitmapFrameAllocator>> = Once::new();

/// Build the bitmap from the bootloader's memory map.
///
/// # Safety
///
/// `physical_memory_offset` must be the base of a complete, writable mapping of
/// physical memory, exactly as requested by `BOOTLOADER_CONFIG`. Call once.
pub unsafe fn init(regions: &MemoryRegions, physical_memory_offset: u64) {
    // Size the bitmap from the highest *usable* address, not the highest address
    // in the map. Firmware puts MMIO windows near the top of the address space --
    // QEMU's sits at 0xfd_0000_0000 -- and covering up to there would mean
    // tracking a terabyte of address space, a 32 MiB bitmap carved out of 246 MiB
    // of real RAM.
    //
    // Nothing is lost by ignoring it: this allocator only ever hands out RAM.
    // Device memory is mapped through `paging::map_to_frame`, which takes an
    // explicit frame and never consults the bitmap.
    let highest_usable = regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .map(|r| r.end)
        .max()
        .unwrap_or(0);
    let total_frames = (highest_usable / PAGE_SIZE) as usize;
    let bitmap_bytes = total_frames.div_ceil(8);

    // Host the bitmap in the largest usable region: the biggest region is the
    // one least harmed by losing a few frames off the front.
    let host = regions
        .iter()
        .filter(|r| r.kind == MemoryRegionKind::Usable)
        .filter(|r| (r.end - r.start) as usize >= bitmap_bytes)
        .max_by_key(|r| r.end - r.start)
        .expect("no usable memory region is large enough to hold the frame bitmap");

    // SAFETY: `host` came from the bootloader's own map and is marked Usable, so
    // nothing else claims it. The caller guarantees all physical memory is mapped
    // at `physical_memory_offset`, so this address is valid and writable, and
    // the region was filtered to be at least `bitmap_bytes` long.
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(
            (physical_memory_offset + host.start) as *mut u8,
            bitmap_bytes,
        )
    };

    // Start from "everything is taken" and only release what the bootloader
    // explicitly reported as usable. Getting this backwards would hand out the
    // kernel's own memory.
    bitmap.fill(0xFF);

    let mut allocator = BitmapFrameAllocator {
        bitmap,
        total_frames,
        used_frames: total_frames,
        next_hint: 0,
    };

    for region in regions.iter().filter(|r| r.kind == MemoryRegionKind::Usable) {
        // Only whole frames lying entirely inside the region are usable, so round
        // the start up and the end down.
        let first = region.start.div_ceil(PAGE_SIZE) as usize;
        let last = (region.end / PAGE_SIZE) as usize;
        for frame in first..last {
            allocator.mark_free(frame);
        }
    }

    // Reclaim nothing that the bitmap itself occupies.
    let bitmap_first = (host.start / PAGE_SIZE) as usize;
    let bitmap_last = (host.start + bitmap_bytes as u64).div_ceil(PAGE_SIZE) as usize;
    for frame in bitmap_first..bitmap_last {
        allocator.mark_used(frame);
    }

    // Hold back the whole first megabyte.
    //
    // The bootloader reports most of it as usable, and arithmetically it is --
    // but real-mode structures live down there, and a processor coming out of
    // reset can only start from an address below 1 MiB. Handing any of it to a
    // general allocation means the SMP trampoline eventually lands on top of
    // whatever was given out, which presents as an application processor that
    // silently fails to start rather than as a memory error.
    //
    // 256 frames, on a machine with tens of thousands.
    const LOW_MEMORY_FRAMES: usize = (1024 * 1024) / PAGE_SIZE as usize;
    for frame in 0..LOW_MEMORY_FRAMES.min(allocator.total_frames) {
        allocator.mark_used(frame);
    }

    ALLOCATOR.call_once(|| Mutex::new(allocator));
}

/// Run `f` with exclusive access to the frame allocator.
///
/// # Panics
///
/// If `init` has not run.
pub fn with<R>(f: impl FnOnce(&mut BitmapFrameAllocator) -> R) -> R {
    let allocator = ALLOCATOR
        .get()
        .expect("frame allocator used before memory::init");
    f(&mut allocator.lock())
}

/// Whether the allocator has been initialised.
pub fn is_initialised() -> bool {
    ALLOCATOR.get().is_some()
}
