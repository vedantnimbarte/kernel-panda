//! Free-list heap allocator with coalescing.
//!
//! Free blocks are threaded together through a linked list whose nodes live
//! *inside* the free memory itself, so the allocator needs no storage of its own.
//! The list is kept sorted by address, which is what makes coalescing cheap:
//! merging a returned block only ever has to look at its two immediate
//! neighbours.
//!
//! Coalescing is the whole point. Without it, a long run of alternating
//! allocations and frees shatters the heap into thousands of unusable fragments
//! and the kernel dies of exhaustion with most of its memory nominally free.

use core::alloc::{GlobalAlloc, Layout};
use core::{mem, ptr};

use super::{adjust_layout, align_up, HeapStats, Locked};

struct ListNode {
    size: usize,
    next: Option<&'static mut ListNode>,
}

impl ListNode {
    const fn new(size: usize) -> Self {
        Self { size, next: None }
    }

    fn start_addr(&self) -> usize {
        self as *const Self as usize
    }

    fn end_addr(&self) -> usize {
        self.start_addr() + self.size
    }
}

pub struct LinkedListAllocator {
    /// Sentinel. Lives in the allocator struct, not in the heap, so it must
    /// never be treated as a mergeable neighbour.
    head: ListNode,
    size: usize,
    allocated: usize,
    peak: usize,
    allocations: usize,
}

impl LinkedListAllocator {
    pub const fn new() -> Self {
        Self {
            head: ListNode::new(0),
            size: 0,
            allocated: 0,
            peak: 0,
            allocations: 0,
        }
    }

    /// # Safety
    ///
    /// The range must be mapped, writable, and owned exclusively by the heap.
    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.size = heap_size;
        // SAFETY: forwarded from this function's contract.
        unsafe { self.add_free_region(heap_start, heap_size) };
    }

    /// Return `[addr, addr + size)` to the free list, merging it with any
    /// adjacent free blocks.
    ///
    /// # Safety
    ///
    /// The range must lie inside the heap, be node-aligned, and not be reachable
    /// from the free list or from any live allocation.
    unsafe fn add_free_region(&mut self, addr: usize, size: usize) {
        debug_assert_eq!(align_up(addr, mem::align_of::<ListNode>()), addr);
        debug_assert!(size >= mem::size_of::<ListNode>());

        // Find the last node that sits below `addr`. The list is address-sorted,
        // so this is the only candidate for a backward merge, and its successor
        // is the only candidate for a forward one.
        let mut current = &mut self.head;
        let mut at_head = true;
        loop {
            let advance = match &current.next {
                Some(region) => region.start_addr() < addr,
                None => false,
            };
            if !advance {
                break;
            }
            current = current.next.as_mut().unwrap();
            at_head = false;
        }

        let mut new_size = size;

        // Merge forward: absorb the successor if it starts exactly where this
        // block ends.
        let following = match current.next.take() {
            Some(region) if addr + new_size == region.start_addr() => {
                new_size += region.size;
                region.next.take()
            }
            other => other,
        };

        // Merge backward, but never into the sentinel: its address is inside the
        // allocator struct and has nothing to do with the heap.
        if !at_head && current.end_addr() == addr {
            current.size += new_size;
            current.next = following;
            return;
        }

        // SAFETY: `addr` is node-aligned with at least `size` bytes behind it by
        // this function's contract, and it is currently owned by nobody -- the
        // neighbours that could reach it were just detached. Writing a node
        // header here cannot clobber live data.
        unsafe {
            let node = addr as *mut ListNode;
            node.write(ListNode { size: new_size, next: following });
            current.next = Some(&mut *node);
        }
    }

    /// Detach and return the first block that can satisfy `size`/`align`, along
    /// with the address the allocation should start at.
    fn find_region(&mut self, size: usize, align: usize) -> Option<(&'static mut ListNode, usize)> {
        let mut current = &mut self.head;

        while let Some(ref mut region) = current.next {
            if let Some(alloc_start) = Self::try_carve(region, size, align) {
                let next = region.next.take();
                let found = current.next.take().unwrap();
                current.next = next;
                return Some((found, alloc_start));
            }
            current = current.next.as_mut().unwrap();
        }

        None
    }

    /// Where an allocation would start inside `region`, or `None` if it does not
    /// fit usefully.
    fn try_carve(region: &ListNode, size: usize, align: usize) -> Option<usize> {
        let alloc_start = align_up(region.start_addr(), align);
        let alloc_end = alloc_start.checked_add(size)?;

        if alloc_end > region.end_addr() {
            return None;
        }

        // A leftover tail too small to hold a node header could never be
        // returned to the list, so treat this region as unusable rather than
        // silently leaking the remainder.
        let excess = region.end_addr() - alloc_end;
        if excess > 0 && excess < mem::size_of::<ListNode>() {
            return None;
        }

        Some(alloc_start)
    }

    pub fn stats(&self) -> HeapStats {
        HeapStats {
            size: self.size,
            allocated: self.allocated,
            peak: self.peak,
            allocations: self.allocations,
        }
    }

    /// Number of blocks on the free list.
    ///
    /// Diagnostic. A heap that has been fully emptied should report exactly one,
    /// which is the only direct evidence that coalescing works.
    pub fn free_region_count(&self) -> usize {
        let mut count = 0;
        let mut current = &self.head;
        while let Some(region) = &current.next {
            count += 1;
            current = region;
        }
        count
    }

    /// Size of the largest single free block.
    pub fn largest_free_region(&self) -> usize {
        let mut largest = 0;
        let mut current = &self.head;
        while let Some(region) = &current.next {
            largest = largest.max(region.size);
            current = region;
        }
        largest
    }
}

impl Default for LinkedListAllocator {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for Locked<LinkedListAllocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let (size, align) = adjust_layout::<ListNode>(layout);
        let mut allocator = self.lock();

        let Some((region, alloc_start)) = allocator.find_region(size, align) else {
            return ptr::null_mut();
        };

        // Read the geometry out before touching the list again -- `region` is
        // detached, and its header is about to be overwritten.
        let region_start = region.start_addr();
        let region_end = region.end_addr();
        let alloc_end = alloc_start + size; // `try_carve` already checked this

        // Hand back the alignment padding at the front when it is big enough to
        // be a block in its own right. (When it is not, those few bytes are lost
        // until the neighbouring block is freed and merges over them.)
        let front_padding = alloc_start - region_start;
        if front_padding >= mem::size_of::<ListNode>() {
            // SAFETY: this sub-range is inside the detached region, is
            // node-aligned because `region_start` was, and is not yet reachable
            // from the free list.
            unsafe { allocator.add_free_region(region_start, front_padding) };
        }

        let excess = region_end - alloc_end;
        if excess > 0 {
            // SAFETY: the tail of the detached region. `try_carve` guaranteed it
            // is at least one node in size, and `alloc_end` is aligned because
            // both `alloc_start` and `size` are node-aligned multiples.
            unsafe { allocator.add_free_region(alloc_end, excess) };
        }

        allocator.allocated += size;
        allocator.allocations += 1;
        allocator.peak = allocator.peak.max(allocator.allocated);

        alloc_start as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let (size, _) = adjust_layout::<ListNode>(layout);
        let mut allocator = self.lock();

        // SAFETY: `ptr` came from `alloc` with this same layout, so it is
        // node-aligned, `size` bytes long, inside the heap, and -- because the
        // caller is giving it up -- no longer reachable from anywhere else.
        unsafe { allocator.add_free_region(ptr as usize, size) };

        allocator.allocated -= size;
        allocator.allocations -= 1;
    }
}
