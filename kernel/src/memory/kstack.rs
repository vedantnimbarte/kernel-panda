//! Kernel stacks, each with a guard page beneath it.
//!
//! These used to be heap allocations. That works right up until a thread
//! recurses too far, at which point it writes straight through the bottom of
//! its stack into whatever the allocator happened to put below -- another
//! thread's control block, a free-list node, a buffer. Nothing faults. The
//! damage surfaces later, somewhere unrelated, as corruption with no path back
//! to its cause.
//!
//! Giving each stack its own virtual range with an unmapped page underneath
//! turns that into a page fault on the first byte past the end. On a kernel
//! thread the fault then escalates to a double fault -- the handler cannot push
//! a frame onto the stack that just ran out -- which lands on the IST stack and
//! prints. Loud, immediate, and pointing at the thread that did it.

use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

use crate::memory::paging;
use crate::sync::Mutex;

const PAGE_SIZE: u64 = 4096;

/// Where kernel stacks live. Clear of the heap, the APIC window and user space.
pub const KSTACK_BASE: u64 = 0x0000_5555_0000_0000;

/// Address space reserved per stack. Larger than the stack itself so the guard
/// page is followed by slack -- two stacks are never adjacent, which means an
/// overflow cannot skip the guard and land in the neighbour.
pub const KSTACK_SLOT_SIZE: u64 = 64 * 1024;

/// Usable stack, in pages. 32 KiB, matching what the heap-backed stacks gave.
pub const KSTACK_PAGES: u64 = 8;

/// How many kernel stacks can exist at once.
pub const MAX_STACKS: usize = 128;

static SLOTS: Mutex<[bool; MAX_STACKS]> = Mutex::new([false; MAX_STACKS]);

/// A mapped kernel stack. Unmaps itself and releases its slot when dropped.
#[derive(Debug)]
pub struct KernelStack {
    slot: usize,
    top: u64,
}

impl KernelStack {
    /// Highest address of the stack, which is where a thread starts from --
    /// x86 stacks grow downward.
    pub fn top(&self) -> u64 {
        self.top
    }

    /// Lowest mapped address.
    pub fn bottom(&self) -> u64 {
        self.top - KSTACK_PAGES * PAGE_SIZE
    }

    /// The unmapped page below the stack. Touching it is the overflow.
    pub fn guard_page(&self) -> u64 {
        slot_base(self.slot)
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        let space = paging::kernel_space();
        for index in 0..KSTACK_PAGES {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                self.bottom() + index * PAGE_SIZE,
            ));
            let _ = paging::unmap_and_free_in(&space, page);
        }

        crate::sync::without_interrupts(|| {
            SLOTS.lock()[self.slot] = false;
        });
    }
}

fn slot_base(slot: usize) -> u64 {
    KSTACK_BASE + slot as u64 * KSTACK_SLOT_SIZE
}

/// Map a fresh kernel stack, or `None` if the region is full.
pub fn allocate() -> Option<KernelStack> {
    let slot = crate::sync::without_interrupts(|| {
        let mut slots = SLOTS.lock();
        let index = slots.iter().position(|used| !*used)?;
        slots[index] = true;
        Some(index)
    })?;

    // The guard page is simply never mapped. It costs no memory -- only address
    // space, of which there is a great deal.
    let bottom = slot_base(slot) + PAGE_SIZE;
    let top = bottom + KSTACK_PAGES * PAGE_SIZE;

    // Stacks hold data. Marking them non-executable means a corrupted return
    // address cannot turn stack contents into instructions.
    let flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let space = paging::kernel_space();

    for index in 0..KSTACK_PAGES {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(bottom + index * PAGE_SIZE));
        if paging::map_in(&space, page, flags).is_err() {
            // Unwind what was mapped, or a failed allocation leaks both frames
            // and a slot.
            for done in 0..index {
                let page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                    bottom + done * PAGE_SIZE,
                ));
                let _ = paging::unmap_and_free_in(&space, page);
            }
            crate::sync::without_interrupts(|| SLOTS.lock()[slot] = false);
            return None;
        }
    }

    Some(KernelStack { slot, top })
}

/// Stacks currently allocated. Diagnostic, and used by tests.
pub fn in_use() -> usize {
    crate::sync::without_interrupts(|| SLOTS.lock().iter().filter(|used| **used).count())
}
