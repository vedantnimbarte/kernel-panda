//! Bump allocator.
//!
//! Allocation is a pointer increment; freeing does nothing until the last live
//! allocation goes away, at which point the whole heap resets. Useless as a
//! general allocator, valuable as a diagnostic: if `Box::new` faults under this,
//! the problem is the page mapping, not the allocator.
//!
//! Select it with `--features bump-allocator`.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use super::{align_up, HeapStats, Locked};

pub struct BumpAllocator {
    heap_start: usize,
    heap_end: usize,
    /// Address of the next byte to hand out.
    next: usize,
    allocations: usize,
    peak: usize,
}

impl BumpAllocator {
    pub const fn new() -> Self {
        Self { heap_start: 0, heap_end: 0, next: 0, allocations: 0, peak: 0 }
    }

    /// # Safety
    ///
    /// The range must be mapped, writable, and owned exclusively by the heap.
    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.heap_start = heap_start;
        self.heap_end = heap_start.saturating_add(heap_size);
        self.next = heap_start;
    }

    pub fn stats(&self) -> HeapStats {
        HeapStats {
            size: self.heap_end - self.heap_start,
            allocated: self.next - self.heap_start,
            peak: self.peak,
            allocations: self.allocations,
        }
    }

    /// Always one: everything above the bump pointer is a single free block.
    /// Present so both allocators expose the same diagnostic surface.
    pub fn free_region_count(&self) -> usize {
        usize::from(self.next < self.heap_end)
    }

    pub fn largest_free_region(&self) -> usize {
        self.heap_end - self.next
    }
}

impl Default for BumpAllocator {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for Locked<BumpAllocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut bump = self.lock();

        let start = align_up(bump.next, layout.align());
        let Some(end) = start.checked_add(layout.size()) else {
            return ptr::null_mut();
        };
        if end > bump.heap_end {
            return ptr::null_mut();
        }

        bump.next = end;
        bump.allocations += 1;
        bump.peak = bump.peak.max(end - bump.heap_start);
        start as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        let mut bump = self.lock();
        bump.allocations -= 1;
        // The only reclamation a bump allocator can do: once nothing is live,
        // the whole heap is free again.
        if bump.allocations == 0 {
            bump.next = bump.heap_start;
        }
    }
}
