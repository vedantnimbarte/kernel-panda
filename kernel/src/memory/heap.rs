//! Kernel heap region.
//!
//! Carves a virtual address range out of nothing, backs every page of it with a
//! freshly allocated physical frame, and hands the result to the global
//! allocator. This is the step that turns `alloc` -- `Box`, `Vec`, `String` -- on.

use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

use super::paging::{self, MapError};

/// Base of the kernel heap.
///
/// Chosen to sit far away from anything the bootloader maps, and to be obvious
/// in a hex dump when a pointer goes astray.
pub const HEAP_START: usize = 0x_4444_4444_0000;

/// 1 MiB. Ample for the bookkeeping a microkernel should be doing, and small
/// enough that runaway allocation fails loudly and early -- PRD 2.1 asks that
/// kernel-side dynamic allocation stay strictly limited.
pub const HEAP_SIZE: usize = 1024 * 1024;

/// Map the heap range and initialise the global allocator.
pub fn init() -> Result<(), MapError> {
    let page_range = {
        let start = VirtAddr::new(HEAP_START as u64);
        let end = start + (HEAP_SIZE - 1) as u64;
        Page::range_inclusive(
            Page::<Size4KiB>::containing_address(start),
            Page::containing_address(end),
        )
    };

    // NO_EXECUTE would be the right flag for a data-only region, but it faults
    // unless EFER.NXE is on. Left off until that is verified rather than
    // assumed; see the hardening notes in README.md.
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    for page in page_range {
        paging::map(page, flags)?;
    }

    // SAFETY: every page in the range was just mapped to a frame the allocator
    // handed out exclusively, so the whole span is present, writable, and owned
    // by nothing else. This runs once, from `memory::init`.
    unsafe { crate::allocator::init(HEAP_START, HEAP_SIZE) };

    Ok(())
}
