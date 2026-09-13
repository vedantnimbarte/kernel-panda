//! Memory a device reads and writes by itself.
//!
//! A DMA engine addresses physical memory, knows nothing of page tables, and
//! usually wants its rings and tables in one contiguous run. This hands out
//! such a run, mapped where the driver asked, uncached and zeroed.

use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::{frame, paging};

/// Physically contiguous memory shared with a device.
///
/// Freed when dropped, which for a device found at boot never happens. Kept as
/// an owned type anyway so the lifetime is stated rather than implied.
pub struct DmaRegion {
    physical: PhysAddr,
    virtual_base: u64,
    frames: u64,
}

impl DmaRegion {
    /// Allocate `frames` contiguous physical frames and map them uncached.
    pub fn new(frames: u64, virtual_base: u64) -> Option<Self> {
        let first = frame::with(|allocator| allocator.allocate_contiguous(frames as usize))?;

        // Uncached and write-through. The device updates these structures by
        // DMA; a cached view can answer a read from a line fetched before it
        // did, which shows up as a command that never appears to complete.
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH
            | PageTableFlags::NO_EXECUTE;

        for index in 0..frames {
            let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                x86_64::VirtAddr::new(virtual_base + index * 4096),
            );
            let target = PhysFrame::<Size4KiB>::containing_address(
                first.start_address() + index * 4096,
            );
            // SAFETY: the frames were just allocated contiguously and belong to
            // nobody else, and the caller reserved this virtual range.
            if unsafe { paging::map_to_frame(page, target, flags) }.is_err() {
                for done in 0..index {
                    let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                        x86_64::VirtAddr::new(virtual_base + done * 4096),
                    );
                    let _ = paging::unmap(page);
                }
                frame::with(|allocator| {
                    for offset in 0..frames {
                        allocator.deallocate(PhysFrame::containing_address(
                            first.start_address() + offset * 4096,
                        ));
                    }
                });
                return None;
            }
        }

        // Zeroed, because the device reads these before the CPU has written
        // every field and whatever the last owner left looks like a command.
        // SAFETY: just mapped, writable, and this size.
        unsafe {
            core::ptr::write_bytes(virtual_base as *mut u8, 0, (frames * 4096) as usize);
        }

        Some(Self {
            physical: first.start_address(),
            virtual_base,
            frames,
        })
    }

    pub fn physical_at(&self, offset: u64) -> u64 {
        self.physical.as_u64() + offset
    }

    pub fn virtual_at(&self, offset: u64) -> u64 {
        self.virtual_base + offset
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        for index in 0..self.frames {
            let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                x86_64::VirtAddr::new(self.virtual_base + index * 4096),
            );
            let _ = paging::unmap_and_free(page);
        }
    }
}

