//! The kernel heap.
//!
//! Two implementations live here. The bump allocator came first and is kept
//! deliberately: when something goes wrong with a fresh heap it isolates "is the
//! page mapping correct?" from "is the allocator correct?", which is otherwise a
//! miserable thing to untangle. The linked-list allocator is the real one and is
//! the default.
//!
//! PRD 2.1 asks that dynamic allocation inside the kernel stay strictly limited,
//! so both track their own usage and expose it through [`stats`]. A microkernel
//! whose Ring 0 heap grows without bound has lost the plot.

pub mod bump;
pub mod linked_list;

use core::alloc::Layout;
use core::mem;

use crate::sync::{IrqMutex, IrqMutexGuard};

#[cfg(feature = "bump-allocator")]
pub use bump::BumpAllocator as SelectedAllocator;
#[cfg(not(feature = "bump-allocator"))]
pub use linked_list::LinkedListAllocator as SelectedAllocator;

/// A spinlock that `GlobalAlloc` can be implemented on.
///
/// `GlobalAlloc` takes `&self`, so the allocator's interior mutability has to
/// come from somewhere. Implementing the trait directly on `Mutex<A>` is not
/// possible -- neither is local to this crate.
///
/// It masks interrupts, and that is not optional. The timer handler allocates:
/// it reaps finished threads, which drops their boxed control blocks, and it
/// buffers console input into a growable queue. With a plain spinlock, a tick
/// landing while any thread sits inside `alloc` deadlocks the machine outright --
/// the handler spins on a lock whose holder can never be scheduled again.
pub struct Locked<A> {
    inner: IrqMutex<A>,
}

impl<A> Locked<A> {
    pub const fn new(inner: A) -> Self {
        Self {
            inner: IrqMutex::new(inner),
        }
    }

    pub fn lock(&self) -> IrqMutexGuard<'_, A> {
        self.inner.lock()
    }
}

#[global_allocator]
static KERNEL_HEAP: Locked<SelectedAllocator> = Locked::new(SelectedAllocator::new());

/// A snapshot of heap usage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeapStats {
    /// Total bytes the heap was given.
    pub size: usize,
    /// Bytes currently handed out, including per-allocation rounding.
    pub allocated: usize,
    /// High-water mark of `allocated` since boot.
    pub peak: usize,
    /// Live allocation count.
    pub allocations: usize,
}

/// Hand the heap its backing memory.
///
/// # Safety
///
/// The range `[heap_start, heap_start + heap_size)` must be mapped, writable,
/// and used by nothing else. Call once.
pub unsafe fn init(heap_start: usize, heap_size: usize) {
    // SAFETY: forwarded from this function's contract.
    unsafe { KERNEL_HEAP.lock().init(heap_start, heap_size) };
}

/// Current heap usage.
pub fn stats() -> HeapStats {
    KERNEL_HEAP.lock().stats()
}

/// Number of separate free blocks.
///
/// After everything has been freed this should be 1. Any larger number means
/// the heap has fragmented and blocks that ought to have merged did not.
pub fn free_region_count() -> usize {
    KERNEL_HEAP.lock().free_region_count()
}

/// Size of the largest single free block.
pub fn largest_free_region() -> usize {
    KERNEL_HEAP.lock().largest_free_region()
}

/// Round `addr` up to the next multiple of `align`, which must be a power of two.
pub(crate) fn align_up(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (addr + align - 1) & !(align - 1)
}

/// Normalise a `Layout` so every block is large enough and aligned enough to be
/// reused as a free-list node once it is returned.
pub(crate) fn adjust_layout<T>(layout: Layout) -> (usize, usize) {
    let layout = layout
        .align_to(mem::align_of::<T>())
        .expect("alignment overflow while adjusting a heap layout")
        .pad_to_align();
    (layout.size().max(mem::size_of::<T>()), layout.align())
}
