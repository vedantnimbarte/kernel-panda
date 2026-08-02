//! Virtual memory: page table management.
//!
//! The bootloader leaves us in long mode with paging already on and all of
//! physical memory mapped at a known offset. That offset is what makes this
//! module simple: any physical address can be read or written by adding the
//! offset to it, so walking and editing page tables needs no recursive mapping
//! and no temporary windows.

use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::mapper::{
    FlagUpdateError, MapToError, TranslateResult, UnmapError,
};
use x86_64::structures::paging::{
    Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use super::frame;
use crate::sync::{without_interrupts, Mutex, Once};

static PHYSICAL_OFFSET: Once<VirtAddr> = Once::new();

/// Serialises page-table edits. The tables themselves are reached through CR3 or
/// an explicit address space, so this guards the editing, not a cached mapper.
static PAGING: Mutex<()> = Mutex::new(());

/// Level 4 index covering the whole user region.
///
/// One entry spans 512 GiB and the user region is 1 GiB, so all of it lives
/// under a single index -- which is what makes a per-process address space cheap:
/// clone the kernel's table and give this one slot a private subtree.
const USER_L4_INDEX: usize = (crate::userspace::USER_BASE >> 39) as usize & 0x1FF;

/// A page-table hierarchy: one level 4 frame, and everything below it.
///
/// Copying the kernel's entries into each new space rather than rebuilding them
/// means the two share the *same* lower tables by pointer, so a later kernel
/// mapping is visible everywhere at once. That holds only while no kernel
/// mapping needs a brand-new level 4 entry after the first process is created --
/// every kernel region already has its slot populated during boot, and adding
/// one later would silently be invisible to existing processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSpace {
    level_4: PhysFrame<Size4KiB>,
}

impl AddressSpace {
    /// The address space currently loaded in CR3.
    pub fn active() -> Self {
        Self {
            level_4: Cr3::read().0,
        }
    }

    /// Build a new space that shares every kernel mapping but has its own,
    /// empty, user region.
    pub fn new_user() -> Option<Self> {
        let offset = *PHYSICAL_OFFSET.get()?;
        let frame = crate::memory::frame::with(|allocator| allocator.allocate())?;

        let kernel = Cr3::read().0;

        // SAFETY: both frames are mapped through the complete physical memory
        // window, so these are live, aligned page tables. The new one was just
        // handed out by the frame allocator, so nothing else refers to it.
        unsafe {
            let source = &*((offset + kernel.start_address().as_u64()).as_ptr::<PageTable>());
            let destination =
                &mut *((offset + frame.start_address().as_u64()).as_mut_ptr::<PageTable>());

            destination.zero();
            for index in 0..512 {
                if index != USER_L4_INDEX {
                    destination[index] = source[index].clone();
                }
            }
        }

        Some(Self { level_4: frame })
    }

    pub fn frame(&self) -> PhysFrame<Size4KiB> {
        self.level_4
    }

    /// Load this space into CR3.
    ///
    /// # Safety
    ///
    /// Every mapping the currently executing code depends on -- its own code, its
    /// stack, and anything it is about to touch -- must exist in this space.
    /// Kernel mappings are shared by construction, so this is safe for any space
    /// built by `new_user`.
    pub unsafe fn activate(&self) {
        if Cr3::read().0 == self.level_4 {
            return;
        }
        // SAFETY: forwarded from this function's contract.
        unsafe { Cr3::write(self.level_4, Cr3Flags::empty()) };
    }

    /// Free this space: the user subtree's page tables and the level 4 frame.
    ///
    /// Only the user slot is walked. Every other level 4 entry points at a table
    /// the kernel and all other processes are still using, so freeing those
    /// would hand live page tables back to the allocator.
    ///
    /// The data pages themselves are *not* freed here -- they are unmapped and
    /// released by whoever owns them, before this is called. This frees the
    /// tables that described them.
    ///
    /// # Safety
    ///
    /// The space must not be active on any CPU, and its data pages must already
    /// have been released.
    pub unsafe fn release(self) {
        if let Some(offset) = PHYSICAL_OFFSET.get().copied() {
            // SAFETY: the level 4 frame is live and reachable through the
            // physical memory window.
            let user_entry = unsafe {
                let table = &*((offset + self.level_4.start_address().as_u64())
                    .as_ptr::<PageTable>());
                table[USER_L4_INDEX].clone()
            };

            if user_entry.flags().contains(PageTableFlags::PRESENT) {
                if let Ok(p3) = user_entry.frame() {
                    // SAFETY: reached only from this space's private user slot,
                    // so nothing else refers to these tables.
                    unsafe { free_table_tree(p3, 3, offset) };
                }
            }
        }

        crate::memory::frame::with(|allocator| allocator.deallocate(self.level_4));
    }
}

/// Errors from establishing a mapping. Narrower than the `x86_64` crate's
/// equivalent, and phrased in terms of what the caller can do about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Physical memory is exhausted, either for the target frame or for an
    /// intermediate page table.
    OutOfFrames,
    /// The virtual page is already mapped. Unmap it first if that is intended.
    AlreadyMapped,
    /// A huge page covers this address, so there is no level-1 table to edit.
    HugePageInTheWay,
}

impl From<MapToError<Size4KiB>> for MapError {
    fn from(error: MapToError<Size4KiB>) -> Self {
        match error {
            MapToError::FrameAllocationFailed => MapError::OutOfFrames,
            MapToError::PageAlreadyMapped(_) => MapError::AlreadyMapped,
            MapToError::ParentEntryHugePage => MapError::HugePageInTheWay,
        }
    }
}

/// Adopt the page tables the bootloader built.
///
/// # Safety
///
/// `physical_memory_offset` must be the base of a complete mapping of physical
/// memory. Call once, and only after `frame::init`.
pub unsafe fn init(physical_memory_offset: VirtAddr) {
    PHYSICAL_OFFSET.call_once(|| physical_memory_offset);
    // The tables the bootloader built. Every process space is cloned from these,
    // and threads without one of their own run here.
    KERNEL_SPACE.call_once(AddressSpace::active);
}

/// Free a page table and every table beneath it, but not the data pages the
/// bottom level points at.
///
/// `level` is 3 for a P3, 2 for a P2, 1 for a P1. The recursion stops before
/// dereferencing level 1's entries, because those are data frames belonging to
/// whoever mapped them -- freeing them here would be a double free.
///
/// # Safety
///
/// `frame` must be a live page table at `level`, reachable only from the space
/// being destroyed.
unsafe fn free_table_tree(frame: PhysFrame<Size4KiB>, level: u8, offset: VirtAddr) {
    if level > 1 {
        // SAFETY: a live page table, reachable through the physical window.
        let table =
            unsafe { &*((offset + frame.start_address().as_u64()).as_ptr::<PageTable>()) };

        for entry in table.iter() {
            let flags = entry.flags();
            // A huge page's entry points at data, not at another table.
            if !flags.contains(PageTableFlags::PRESENT)
                || flags.contains(PageTableFlags::HUGE_PAGE)
            {
                continue;
            }
            if let Ok(child) = entry.frame() {
                // SAFETY: reached only through this subtree.
                unsafe { free_table_tree(child, level - 1, offset) };
            }
        }
    }

    crate::memory::frame::with(|allocator| allocator.deallocate(frame));
}

static KERNEL_SPACE: Once<AddressSpace> = Once::new();

/// The address space kernel threads run in.
pub fn kernel_space() -> AddressSpace {
    *KERNEL_SPACE
        .get()
        .expect("page tables used before memory::init")
}

/// Map `page` to a freshly allocated physical frame.
///
/// Returns the frame that was allocated, so the caller can hand it back with
/// `unmap` later.
pub fn map(page: Page<Size4KiB>, flags: PageTableFlags) -> Result<PhysFrame<Size4KiB>, MapError> {
    with_mapper(|mapper| {
        frame::with(|allocator| {
            let target = allocator.allocate().ok_or(MapError::OutOfFrames)?;

            // SAFETY: `target` was just allocated and is therefore not mapped
            // anywhere else, so creating this mapping cannot alias existing
            // memory. Intermediate tables come from the same allocator.
            match unsafe { mapper.map_to(page, target, flags, allocator) } {
                Ok(flush) => {
                    flush.flush();
                    Ok(target)
                }
                Err(error) => {
                    // The frame was allocated speculatively, before we knew
                    // whether the mapping would succeed. Failing to hand it back
                    // would leak a frame on every rejected map -- and the most
                    // common rejection, `PageAlreadyMapped`, is a caller bug that
                    // tends to happen in a loop.
                    allocator.deallocate(target);
                    Err(error.into())
                }
            }
        })
    })
}

/// Map `page` to a specific physical frame.
///
/// For MMIO and for adopting memory the kernel does not own. The frame is not
/// taken from the allocator, so it must not be returned to it either.
///
/// # Safety
///
/// `target` must not be memory managed by the frame allocator, or aliasing
/// results.
pub unsafe fn map_to_frame(
    page: Page<Size4KiB>,
    target: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), MapError> {
    with_mapper(|mapper| {
        frame::with(|allocator| {
            // SAFETY: forwarded from this function's contract; intermediate page
            // tables still come from the frame allocator.
            let flush = unsafe { mapper.map_to(page, target, flags, allocator) }?;
            flush.flush();
            Ok(())
        })
    })
}

/// Remove a mapping and return the frame it pointed at, without freeing it.
pub fn unmap(page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, UnmapError> {
    with_mapper(|mapper| {
        let (frame, flush) = mapper.unmap(page)?;
        // Stale TLB entries would let the unmapped address keep working, which
        // hides use-after-free bugs until the worst possible moment.
        flush.flush();
        Ok(frame)
    })
}

/// Remove a mapping and return its frame to the physical allocator.
pub fn unmap_and_free(page: Page<Size4KiB>) -> Result<(), UnmapError> {
    let released = unmap(page)?;
    frame::with(|allocator| allocator.deallocate(released));
    Ok(())
}

/// Translate a virtual address, or `None` if it is not mapped.
pub fn translate(address: VirtAddr) -> Option<PhysAddr> {
    with_mapper(|mapper| match mapper.translate(address) {
        TranslateResult::Mapped { frame, offset, .. } => Some(frame.start_address() + offset),
        _ => None,
    })
}

/// The effective page-table flags for an address, or `None` if it is unmapped.
///
/// This is what makes it possible to validate a pointer handed in by user space:
/// the kernel can ask whether a page is actually present, actually writable, and
/// actually reachable from Ring 3 before it dereferences anything.
pub fn flags(address: VirtAddr) -> Option<PageTableFlags> {
    with_mapper(|mapper| match mapper.translate(address) {
        TranslateResult::Mapped { flags, .. } => Some(flags),
        _ => None,
    })
}

/// Change the permissions on an existing mapping without moving it.
///
/// Used to drop `WRITABLE` from a user code page once its contents have been
/// copied in, so a process cannot rewrite its own instructions.
pub fn set_flags(page: Page<Size4KiB>, flags: PageTableFlags) -> Result<(), FlagUpdateError> {
    with_mapper(|mapper| {
        // SAFETY: this only narrows or widens permissions on a mapping that
        // already exists; it cannot point the page at different memory. The
        // caller is responsible for the permissions making sense.
        let flush = unsafe { mapper.update_flags(page, flags) }?;
        flush.flush();
        Ok(())
    })
}

/// Whether paging has been initialised.
pub fn is_initialised() -> bool {
    PHYSICAL_OFFSET.get().is_some()
}

/// Run `f` against the page tables currently loaded in CR3.
///
/// Built from CR3 on each call rather than cached. A cached mapper would always
/// describe the boot tables, so once processes have address spaces of their own
/// it would answer questions about the wrong one -- silently, and only for user
/// addresses.
///
/// Lock ordering: taken *before* the frame allocator's lock. Every path needing
/// both goes through this module, so the order cannot be inverted elsewhere.
fn with_mapper<R>(f: impl FnOnce(&mut OffsetPageTable<'static>) -> R) -> R {
    with_space(&AddressSpace::active(), f)
}

/// Run `f` against a specific address space, which need not be the active one.
///
/// Editing an inactive space is sound because every physical frame is reachable
/// through the offset window; only the TLB is per-CPU, and an inactive space has
/// no entries in it.
fn with_space<R>(
    space: &AddressSpace,
    f: impl FnOnce(&mut OffsetPageTable<'static>) -> R,
) -> R {
    without_interrupts(|| {
        let _guard = PAGING.lock();
        let offset = *PHYSICAL_OFFSET
            .get()
            .expect("page tables used before memory::init");

        // SAFETY: `space` names a live level 4 frame, reachable through the
        // complete physical memory window the caller of `init` promised. The
        // lock above makes this the only mapper alive at a time.
        let mut mapper = unsafe {
            let table = &mut *((offset + space.frame().start_address().as_u64())
                .as_mut_ptr::<PageTable>());
            OffsetPageTable::new(table, offset)
        };
        f(&mut mapper)
    })
}

/// Map `page` to a fresh frame inside `space`.
pub fn map_in(
    space: &AddressSpace,
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame<Size4KiB>, MapError> {
    with_space(space, |mapper| {
        frame::with(|allocator| {
            let target = allocator.allocate().ok_or(MapError::OutOfFrames)?;

            // SAFETY: `target` was just allocated, so it is mapped nowhere else.
            match unsafe { mapper.map_to(page, target, flags, allocator) } {
                Ok(flush) => {
                    flush.flush();
                    Ok(target)
                }
                Err(error) => {
                    allocator.deallocate(target);
                    Err(error.into())
                }
            }
        })
    })
}

/// Map `page` to a specific frame inside `space`.
///
/// # Safety
///
/// `target` must not be memory the frame allocator manages, or it will be
/// handed out twice.
pub unsafe fn map_to_frame_in(
    space: &AddressSpace,
    page: Page<Size4KiB>,
    target: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), MapError> {
    with_space(space, |mapper| {
        frame::with(|allocator| {
            // SAFETY: forwarded from this function's contract.
            let flush = unsafe { mapper.map_to(page, target, flags, allocator) }?;
            flush.flush();
            Ok(())
        })
    })
}

/// Remove a mapping from `space`, returning its frame without freeing it.
pub fn unmap_in(
    space: &AddressSpace,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, UnmapError> {
    with_space(space, |mapper| {
        let (frame, flush) = mapper.unmap(page)?;
        flush.flush();
        Ok(frame)
    })
}

/// Remove a mapping from `space` and return its frame to the allocator.
pub fn unmap_and_free_in(space: &AddressSpace, page: Page<Size4KiB>) -> Result<(), UnmapError> {
    let released = unmap_in(space, page)?;
    frame::with(|allocator| allocator.deallocate(released));
    Ok(())
}

/// Page flags for an address within `space`.
pub fn flags_in(space: &AddressSpace, address: VirtAddr) -> Option<PageTableFlags> {
    with_space(space, |mapper| match mapper.translate(address) {
        TranslateResult::Mapped { flags, .. } => Some(flags),
        _ => None,
    })
}
