//! Virtual memory: page table management.
//!
//! The bootloader leaves us in long mode with paging already on and all of
//! physical memory mapped at a known offset. That offset is what makes this
//! module simple: any physical address can be read or written by adding the
//! offset to it, so walking and editing page tables needs no recursive mapping
//! and no temporary windows.

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::{
    FlagUpdateError, MapToError, TranslateResult, UnmapError,
};
use x86_64::structures::paging::{
    Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use super::frame;
use crate::sync::{Mutex, Once};

static MAPPER: Once<Mutex<OffsetPageTable<'static>>> = Once::new();

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
    // SAFETY: forwarded from this function's contract.
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    // SAFETY: likewise -- `OffsetPageTable` requires exactly the guarantee the
    // caller is making, that the offset maps all of physical memory.
    let mapper = unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) };
    MAPPER.call_once(|| Mutex::new(mapper));
}

/// # Safety
///
/// The caller must guarantee physical memory is fully mapped at
/// `physical_memory_offset`, and must not call this while another `&mut` to the
/// level 4 table is alive.
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    // CR3 holds the physical address of the active level 4 table.
    let (frame, _flags) = Cr3::read();
    let virt = physical_memory_offset + frame.start_address().as_u64();

    // SAFETY: CR3 always points at a valid, aligned level 4 table, and the
    // caller guarantees that adding the offset yields a live writable mapping of
    // it. The `'static` lifetime is honest: the table lives as long as the kernel.
    unsafe { &mut *virt.as_mut_ptr() }
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

/// Whether the mapper has been initialised.
pub fn is_initialised() -> bool {
    MAPPER.get().is_some()
}

/// Run `f` with exclusive access to the active page tables.
///
/// Lock ordering: this is always taken *before* the frame allocator's lock.
/// Every path that needs both goes through this module, so the order cannot be
/// inverted elsewhere.
fn with_mapper<R>(f: impl FnOnce(&mut OffsetPageTable<'static>) -> R) -> R {
    let mapper = MAPPER
        .get()
        .expect("page tables used before memory::init");
    f(&mut mapper.lock())
}
