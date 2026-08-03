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

/// Free a page table, every table beneath it, and every data page they map.
///
/// `level` is 3 for a P3, 2 for a P2, 1 for a P1. Level 1 entries point at data
/// frames, and those are freed too -- which is only correct because by the time
/// a space is destroyed, anything shared has already withdrawn its mappings.
/// `gbm::release_thread` runs before `userspace::release_slot` for exactly this
/// reason: a buffer another process still holds must be unmapped from here
/// first, or its frames would go back to the allocator while still in use.
///
/// # Safety
///
/// `frame` must be a live page table at `level`, reachable only from the space
/// being destroyed, and every frame under it must be owned solely by it.
unsafe fn free_table_tree(frame: PhysFrame<Size4KiB>, level: u8, offset: VirtAddr) {
    // SAFETY: a live page table, reachable through the physical window.
    let table = unsafe { &*((offset + frame.start_address().as_u64()).as_ptr::<PageTable>()) };

    for entry in table.iter() {
        let flags = entry.flags();
        // A huge page's entry points at data, not at another table. Nothing here
        // maps huge pages, so skipping is the conservative choice.
        if !flags.contains(PageTableFlags::PRESENT) || flags.contains(PageTableFlags::HUGE_PAGE) {
            continue;
        }
        let Ok(child) = entry.frame() else {
            continue;
        };

        if level > 1 {
            // SAFETY: reached only through this subtree.
            unsafe { free_table_tree(child, level - 1, offset) };
        } else {
            // A data page belonging to this process alone.
            crate::memory::frame::with(|allocator| allocator.deallocate(child));
        }
    }

    crate::memory::frame::with(|allocator| allocator.deallocate(frame));
}

/// Borrow a page table through the physical memory window.
///
/// # Safety
///
/// `frame` must hold a live page table, and the caller must hold `PAGING` --
/// this hands out a `&mut` to memory that is reachable from several places at
/// once.
unsafe fn table_at(frame: PhysFrame<Size4KiB>, offset: VirtAddr) -> &'static mut PageTable {
    // SAFETY: forwarded from this function's contract; the window maps every
    // physical address, and a page table is 4 KiB and frame aligned.
    unsafe { &mut *((offset + frame.start_address().as_u64()).as_mut_ptr::<PageTable>()) }
}

fn table_is_empty(table: &PageTable) -> bool {
    table.iter().all(|entry| entry.is_unused())
}

/// Free page tables that the last unmap left with nothing in them.
///
/// Unmapping a page clears one level 1 entry and stops. The P1 that held it, and
/// the P2 and P3 above, stay allocated forever -- so a workload that maps and
/// unmaps across a wide address range leaks 4 KiB per level per region, and
/// nothing ever gives it back.
///
/// Level 4 is deliberately never touched. Every entry there outside the user
/// slot is shared *by pointer* with every process's cloned table, so clearing
/// one would unmap a whole kernel region from every space at once and hand a
/// live table back to the allocator. The user slot has its own path:
/// `AddressSpace::release` frees that subtree wholesale when the process exits.
///
/// The levels below level 4 are the same physical tables in every space, so
/// freeing one there is right rather than merely tolerable -- the mapping really
/// has gone everywhere.
///
/// Returns true if anything was freed, which the caller needs to know: dropping
/// a table invalidates cached *paging structures*, not just page translations,
/// and those survive a single-address invalidation.
///
/// # Safety
///
/// `page` must have just been unmapped from `space`, and `PAGING` must be held.
unsafe fn reclaim_empty_tables(
    space: &AddressSpace,
    page: Page<Size4KiB>,
    offset: VirtAddr,
) -> bool {
    // Walk down, remembering each table and the index within it that leads to
    // the next. `parents[i]` is the table at level 4 - i; `children[i]` is the
    // frame its entry points at.
    let indices = [page.p4_index(), page.p3_index(), page.p2_index()];
    let mut parents = [space.frame(); 3];
    let mut children = [space.frame(); 3];

    let mut current = space.frame();
    for level in 0..3 {
        // SAFETY: `current` is a live page table -- the level 4 frame on the
        // first pass, and thereafter one reached through a present, non-huge
        // entry. The caller holds `PAGING`.
        let table = unsafe { table_at(current, offset) };
        let entry = &table[indices[level]];
        let flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT) || flags.contains(PageTableFlags::HUGE_PAGE) {
            return false;
        }
        let Ok(child) = entry.frame() else {
            return false;
        };

        parents[level] = current;
        children[level] = child;
        current = child;
    }

    // Bottom up, stopping at the first table that still has something in it: a
    // P2 cannot be empty while the P1 under it survives. Level 0 -- clearing an
    // entry in the level 4 table -- is excluded for the reason above.
    let mut freed = false;
    for level in (1..3).rev() {
        // SAFETY: a live page table reached through the walk above.
        let child = unsafe { table_at(children[level], offset) };
        if !table_is_empty(child) {
            break;
        }

        // SAFETY: likewise, and the entry being cleared is the one that points
        // at the table about to be freed.
        let parent = unsafe { table_at(parents[level], offset) };
        parent[indices[level]].set_unused();

        frame::with(|allocator| allocator.deallocate(children[level]));
        freed = true;
    }

    freed
}

static KERNEL_SPACE: Once<AddressSpace> = Once::new();

/// Base of the complete physical memory window.
///
/// Anything with a physical address -- ACPI tables, MMIO, another CPU's page
/// tables -- is reachable by adding this to it.
pub fn physical_offset() -> VirtAddr {
    *PHYSICAL_OFFSET
        .get()
        .expect("physical memory window used before memory::init")
}

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
    let space = AddressSpace::active();
    let frame = with_space(
        &space,
        |mapper| -> Result<PhysFrame<Size4KiB>, UnmapError> {
            let (frame, flush) = mapper.unmap(page)?;
            // Stale TLB entries would let the unmapped address keep working,
            // which hides use-after-free bugs until the worst possible moment.
            flush.flush();
            Ok(frame)
        },
    )?;

    if reclaim_tables_for(&space, page) {
        shoot_down_all_if_shared(&space);
    } else {
        shoot_down_if_shared(&space, page);
    }
    Ok(frame)
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
    let frame = with_space(
        space,
        |mapper| -> Result<PhysFrame<Size4KiB>, UnmapError> {
            let (frame, flush) = mapper.unmap(page)?;
            // Flushes this CPU only. The TLB is not coherent across processors.
            flush.flush();
            Ok(frame)
        },
    )?;

    if reclaim_tables_for(space, page) {
        shoot_down_all_if_shared(space);
    } else {
        shoot_down_if_shared(space, page);
    }
    Ok(frame)
}

/// Take the paging lock and drop any table the unmap of `page` emptied.
///
/// Runs after the mapper has been given back rather than alongside it: an
/// `OffsetPageTable` holds a `&mut` to the level 4 table, and reaching into the
/// same tables through the physical window while it is alive would be two
/// mutable paths to one object.
///
/// Re-checking emptiness under the lock is what makes the gap between the two
/// harmless. Every edit goes through this lock, so a table that gained an entry
/// in between is simply seen to be non-empty and left alone.
fn reclaim_tables_for(space: &AddressSpace, page: Page<Size4KiB>) -> bool {
    without_interrupts(|| {
        let _guard = PAGING.lock();
        let Some(offset) = PHYSICAL_OFFSET.get().copied() else {
            return false;
        };

        // SAFETY: the page was just unmapped from `space`, and the lock is held.
        let freed = unsafe { reclaim_empty_tables(space, page, offset) };

        if freed {
            // Invalidating one address is not enough here. Processors cache
            // *paging structures* as well as translations, so a P2 that still
            // remembers a P1 we have just handed back to the allocator would
            // walk into whatever gets allocated next.
            x86_64::instructions::tlb::flush_all();
        }
        freed
    })
}

/// Ask the other processors to forget their translations, if this space is one
/// they share.
///
/// Only the kernel's own tables are shared. A process's are used by whichever
/// CPU is running it, and the CR3 reload on the way in already flushes
/// everything non-global -- so a shootdown there would be pure cost.
fn shoot_down_if_shared(space: &AddressSpace, page: Page<Size4KiB>) {
    if KERNEL_SPACE.get() == Some(space) {
        crate::arch::x86_64::apic::shoot_down_page(page.start_address().as_u64());
    }
}

/// As above, but for a change the other processors cannot be told about one
/// address at a time.
///
/// Freeing an intermediate page table invalidates what they cached about the
/// *structure*, not just one leaf, and a single-address invalidation does not
/// reach that.
fn shoot_down_all_if_shared(space: &AddressSpace) {
    if KERNEL_SPACE.get() == Some(space) {
        crate::arch::x86_64::apic::broadcast_tlb_shootdown();
    }
}

/// Remove a mapping from `space` and return its frame to the allocator.
pub fn unmap_and_free_in(space: &AddressSpace, page: Page<Size4KiB>) -> Result<(), UnmapError> {
    let released = unmap_in(space, page)?;
    frame::with(|allocator| allocator.deallocate(released));
    Ok(())
}

/// Change permissions on an existing mapping inside `space`.
pub fn set_flags_in(
    space: &AddressSpace,
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), FlagUpdateError> {
    with_space(space, |mapper| -> Result<(), FlagUpdateError> {
        // SAFETY: only narrows or widens permissions on a mapping that already
        // exists; it cannot point the page at different memory.
        let flush = unsafe { mapper.update_flags(page, flags) }?;
        flush.flush();
        Ok(())
    })?;

    // Narrowing permissions matters as much as unmapping: another CPU holding a
    // writable entry for a page just made read-only would keep writing to it.
    shoot_down_if_shared(space, page);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitError {
    /// Nothing maps the address.
    NotMapped,
    /// No frame for the new table.
    OutOfFrames,
}

/// Break the huge page covering `address` into the next size down, repeating
/// until it is described by 4 KiB entries.
///
/// The bootloader covers the physical-memory window with 2 MiB pages where it
/// can, which is efficient and exactly wrong when one 4 KiB page inside it needs
/// different treatment -- device registers that must not be cached, say. Without
/// this, the only options are to change the memory type of the whole 2 MiB or to
/// leave two mappings of one page disagreeing about it.
///
/// A no-op if the address is already mapped by a 4 KiB page.
///
/// The permissions move down a level rather than being duplicated: the effective
/// right to read, write or reach a page from Ring 3 is the AND of every level,
/// so the new parent entry is made permissive and the leaves carry what the huge
/// entry said. Execute permission is the other way round -- `NO_EXECUTE` is ORed
/// down the path -- so it must be cleared on the parent and set on the leaves,
/// or the split would silently make an executable range non-executable.
pub fn split_huge_page(address: VirtAddr) -> Result<(), SplitError> {
    loop {
        match mapping_size(address) {
            None => return Err(SplitError::NotMapped),
            Some(4096) => return Ok(()),
            Some(_) => {}
        }

        let offset = physical_offset();
        let outcome = without_interrupts(|| -> Result<(), SplitError> {
            let _guard = PAGING.lock();
            let space = AddressSpace::active();

            // Walk to the entry that is huge. Level 3 covers 1 GiB, level 2
            // covers 2 MiB; both are split the same way, into 512 entries of
            // the size below.
            // SAFETY: the level 4 frame is live and the lock is held.
            let level_4 = unsafe { table_at(space.frame(), offset) };
            let l3_entry = &mut level_4[address.p4_index()];
            if !l3_entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(SplitError::NotMapped);
            }
            let l3_frame = l3_entry.frame().map_err(|_| SplitError::NotMapped)?;

            // SAFETY: reached through a present, non-huge level 4 entry.
            let level_3 = unsafe { table_at(l3_frame, offset) };
            let entry = &mut level_3[address.p3_index()];
            let flags = entry.flags();
            if !flags.contains(PageTableFlags::PRESENT) {
                return Err(SplitError::NotMapped);
            }

            if flags.contains(PageTableFlags::HUGE_PAGE) {
                let base = entry.addr();
                // SAFETY: splitting a live 1 GiB entry into 512 2 MiB entries
                // describing exactly the same memory.
                return unsafe {
                    populate_split(entry, base, flags, offset, 2 * 1024 * 1024, true)
                };
            }

            let l2_frame = entry.frame().map_err(|_| SplitError::NotMapped)?;
            // SAFETY: reached through a present, non-huge level 3 entry.
            let level_2 = unsafe { table_at(l2_frame, offset) };
            let entry = &mut level_2[address.p2_index()];
            let flags = entry.flags();
            if !flags.contains(PageTableFlags::PRESENT) {
                return Err(SplitError::NotMapped);
            }
            if !flags.contains(PageTableFlags::HUGE_PAGE) {
                // Already 4 KiB below here.
                return Ok(());
            }

            let base = entry.addr();
            // SAFETY: splitting a live 2 MiB entry into 512 4 KiB entries
            // describing exactly the same memory.
            unsafe { populate_split(entry, base, flags, offset, 4096, false) }
        });

        outcome?;

        // The structure changed, not just one translation, so the caches of
        // paging structures have to go -- here and on every other processor.
        x86_64::instructions::tlb::flush_all();
        crate::arch::x86_64::apic::broadcast_tlb_shootdown();
    }
}

/// Replace a huge entry with a table of 512 smaller ones covering the same
/// memory.
///
/// # Safety
///
/// `entry` must be a present huge entry at the level above `step`, `base` its
/// frame address, and `PAGING` must be held.
unsafe fn populate_split(
    entry: &mut x86_64::structures::paging::page_table::PageTableEntry,
    base: PhysAddr,
    flags: PageTableFlags,
    offset: VirtAddr,
    step: u64,
    children_are_huge: bool,
) -> Result<(), SplitError> {
    let table_frame = frame::with(|allocator| allocator.allocate()).ok_or(SplitError::OutOfFrames)?;

    // SAFETY: freshly allocated, so nothing else refers to it, and reachable
    // through the physical window.
    let table = unsafe { table_at(table_frame, offset) };
    table.zero();

    let mut child_flags = flags;
    if !children_are_huge {
        child_flags.remove(PageTableFlags::HUGE_PAGE);
    }

    for index in 0..512u64 {
        table[index as usize].set_addr(base + index * step, child_flags);
    }

    // Permissive at the parent: reading, writing and Ring 3 access are the AND
    // of every level, so a restriction set here would apply to all 512. NX is
    // ORed instead, so it must not be set here either -- the leaves carry it.
    let mut parent_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        parent_flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    entry.set_addr(table_frame.start_address(), parent_flags);

    Ok(())
}

/// How large a page maps an address, if any does.
///
/// Needed to tell a 4 KiB mapping that can simply have its flags changed from a
/// huge one that would have to be split first.
pub fn mapping_size(address: VirtAddr) -> Option<u64> {
    with_mapper(|mapper| match mapper.translate(address) {
        TranslateResult::Mapped { frame, .. } => Some(frame.size()),
        _ => None,
    })
}

/// Page flags for an address within `space`.
pub fn flags_in(space: &AddressSpace, address: VirtAddr) -> Option<PageTableFlags> {
    with_space(space, |mapper| match mapper.translate(address) {
        TranslateResult::Mapped { flags, .. } => Some(flags),
        _ => None,
    })
}
