//! A minimal ELF64 loader.
//!
//! Enough to load the statically linked, non-relocatable binaries the userland
//! crate produces: validate the header, map each `PT_LOAD` segment where its
//! program header says, and report the entry point.
//!
//! No relocation processing, because none is needed. Every user binary links at
//! the same fixed base and each process has its own address space, so two
//! programs at the same virtual address never meet. That is what per-process
//! page tables bought -- without them each binary would need a distinct base
//! baked in at link time, or this would need to apply a relocation table.

use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

use crate::memory::paging::{self, AddressSpace};

const PAGE_SIZE: u64 = 4096;

const MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// e_ident[4]: 2 means 64-bit.
const CLASS_64: u8 = 2;
/// e_ident[5]: 1 means little-endian.
const DATA_LITTLE_ENDIAN: u8 = 1;
/// e_machine: x86-64.
const MACHINE_X86_64: u16 = 0x3E;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Not an ELF file, or not one this kernel can run.
    NotSupported,
    /// A header pointed outside the image.
    Malformed,
    /// A segment asked to be loaded outside the user region.
    OutOfBounds,
    /// Ran out of memory mapping a segment.
    Mapping,
}

/// Where a loaded image ended up.
#[derive(Debug, Clone, Copy)]
pub struct LoadedImage {
    pub entry: VirtAddr,
    /// One past the highest address any segment occupies, page aligned.
    pub end: VirtAddr,
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16, ElfError> {
    let bytes = image
        .get(offset..offset + 2)
        .ok_or(ElfError::Malformed)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32, ElfError> {
    let bytes = image
        .get(offset..offset + 4)
        .ok_or(ElfError::Malformed)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(image: &[u8], offset: usize) -> Result<u64, ElfError> {
    let bytes = image
        .get(offset..offset + 8)
        .ok_or(ElfError::Malformed)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(value))
}

/// Map every `PT_LOAD` segment of `image` into `space`.
///
/// The whole image must land inside `[region_start, region_end)`; a segment
/// asking to be loaded anywhere else is refused rather than trusted, because a
/// header claiming a kernel address would otherwise have the loader overwrite
/// the kernel on the program's behalf.
pub fn load(
    space: &AddressSpace,
    image: &[u8],
    region_start: u64,
    region_end: u64,
) -> Result<LoadedImage, ElfError> {
    if image.get(..4) != Some(&MAGIC[..]) {
        return Err(ElfError::NotSupported);
    }
    if image.get(4).copied() != Some(CLASS_64)
        || image.get(5).copied() != Some(DATA_LITTLE_ENDIAN)
        || read_u16(image, 18)? != MACHINE_X86_64
    {
        return Err(ElfError::NotSupported);
    }

    let entry = read_u64(image, 24)?;
    let program_header_offset = read_u64(image, 32)? as usize;
    let program_header_size = read_u16(image, 54)? as usize;
    let program_header_count = read_u16(image, 56)? as usize;

    if program_header_size < 56 {
        return Err(ElfError::Malformed);
    }

    let mut highest = region_start;

    for index in 0..program_header_count {
        let header = program_header_offset
            .checked_add(index * program_header_size)
            .ok_or(ElfError::Malformed)?;

        if read_u32(image, header)? != PT_LOAD {
            continue;
        }

        // Permissions are applied in the second pass, once the contents are in.
        let file_offset = read_u64(image, header + 8)? as usize;
        let virtual_address = read_u64(image, header + 16)?;
        let file_size = read_u64(image, header + 32)?;
        let memory_size = read_u64(image, header + 40)?;

        if memory_size == 0 {
            continue;
        }
        if file_size > memory_size {
            return Err(ElfError::Malformed);
        }

        let segment_end = virtual_address
            .checked_add(memory_size)
            .ok_or(ElfError::Malformed)?;
        if virtual_address < region_start || segment_end > region_end {
            return Err(ElfError::OutOfBounds);
        }

        let source = image
            .get(file_offset..file_offset + file_size as usize)
            .ok_or(ElfError::Malformed)?;

        // Map the whole span writable first: the contents have to be copied in
        // before the real permissions go on, and a read-only text segment cannot
        // be written to.
        let first = virtual_address & !(PAGE_SIZE - 1);
        let last = (segment_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        let staging = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE;

        let mut address = first;
        while address < last {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(address));
            // Segments can share a page -- .text and .rodata routinely do -- so an
            // already-mapped page is expected rather than an error.
            if paging::flags_in(space, VirtAddr::new(address)).is_none() {
                paging::map_in(space, page, staging).map_err(|_| ElfError::Mapping)?;
            }
            address += PAGE_SIZE;
        }

        // The staging mapping is user-accessible, so SMAP applies even though
        // this is the kernel writing to its own freshly created pages.
        crate::arch::x86_64::with_user_access(|| {
            // SAFETY: the span was just mapped present and writable in `space`,
            // and the caller guarantees `space` is the active one.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source.as_ptr(),
                    virtual_address as *mut u8,
                    file_size as usize,
                );
                // .bss lives in the gap between file size and memory size and
                // must start zeroed; the frames come from the allocator with
                // whatever the last owner left in them.
                core::ptr::write_bytes(
                    (virtual_address + file_size) as *mut u8,
                    0,
                    (memory_size - file_size) as usize,
                );
            }
        });

        highest = highest.max(last);
    }

    // Now the contents are in place, narrow each segment to what it asked for.
    for index in 0..program_header_count {
        let header = program_header_offset + index * program_header_size;
        if read_u32(image, header)? != PT_LOAD {
            continue;
        }

        let flags = read_u32(image, header + 4)?;
        let virtual_address = read_u64(image, header + 16)?;
        let memory_size = read_u64(image, header + 40)?;
        if memory_size == 0 {
            continue;
        }

        let mut final_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if flags & PF_W != 0 {
            final_flags |= PageTableFlags::WRITABLE;
        }
        if flags & PF_X == 0 {
            final_flags |= PageTableFlags::NO_EXECUTE;
        }

        let first = virtual_address & !(PAGE_SIZE - 1);
        let last = (virtual_address + memory_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        let mut address = first;
        while address < last {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(address));
            // Best effort: where two segments share a page the stricter pass
            // runs last, which is the safe direction to be wrong in.
            let _ = paging::set_flags_in(space, page, final_flags);
            address += PAGE_SIZE;
        }
    }

    if entry < region_start || entry >= highest {
        return Err(ElfError::OutOfBounds);
    }

    Ok(LoadedImage {
        entry: VirtAddr::new(entry),
        end: VirtAddr::new(highest),
    })
}
