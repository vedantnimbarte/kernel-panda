//! Generic buffer management.
//!
//! Graphics memory that outlives a single process and can be handed between
//! them. A client allocates a buffer, renders into it, and passes the handle to
//! the compositor over IPC; the compositor maps the same physical frames and
//! reads them. Nothing is copied through the kernel.
//!
//! Handles are checked the same way IPC endpoints are: holding a buffer id is
//! not permission to map it. The owner may share a buffer with a specific
//! thread, and only the owner and its share list can map.
//!
//! The scanout buffer is the exception that makes the whole thing useful -- it
//! wraps the display controller's own memory rather than frames from the
//! allocator, which is how a Ring 3 compositor gets to put pixels on a screen.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::paging;
use crate::sched::ThreadId;
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::Error;
use crate::{console, userspace};

const PAGE_SIZE: u64 = 4096;

/// Pixel width used for newly created buffers.
///
/// Taken from the display rather than fixed, because they have to agree: QEMU's
/// framebuffer is 24-bit, and a client rendering 32-bit pixels into it would
/// produce an image sheared a little further right on every row. Falling back to
/// four bytes only matters on a machine with no framebuffer at all, where
/// nothing will be composited anyway.
pub fn bytes_per_pixel() -> u32 {
    console::framebuffer::info().map_or(4, |info| info.bytes_per_pixel as u32)
}

/// Ceiling on a single allocation, so one process cannot exhaust physical
/// memory by asking for an enormous buffer.
const MAX_BUFFER_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BufferId(pub u64);

/// Shared with user space, so the layout is part of the ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BufferInfo {
    pub width: u32,
    pub height: u32,
    /// Bytes per row. Not always `width * 4` -- the scanout buffer inherits the
    /// hardware's stride, which is commonly padded.
    pub stride: u32,
    pub bytes_per_pixel: u32,
    pub size: u64,
}

struct Buffer {
    info: BufferInfo,
    frames: Vec<PhysFrame<Size4KiB>>,
    /// False for the scanout buffer: those frames are the display controller's
    /// memory, not the frame allocator's, and returning them would be a
    /// catastrophic double free.
    owns_frames: bool,
    owner: ThreadId,
    shared_with: Vec<ThreadId>,
    /// Where each thread has it mapped.
    mappings: Vec<(ThreadId, u64)>,
    /// Set when the owner exits while someone else still holds a reference.
    ///
    /// A buffer cannot simply die with its creator. The whole point of sharing
    /// one is that a second process is using it, and a client that renders a
    /// frame and exits immediately is the normal case, not an unusual one --
    /// freeing on owner exit pulls the surface out from under the compositor
    /// before it has drawn it.
    orphaned: bool,
}

impl Buffer {
    fn may_access(&self, thread: ThreadId) -> bool {
        self.owner == thread || self.shared_with.contains(&thread)
    }
}

struct Registry {
    buffers: BTreeMap<u64, Buffer>,
    next_id: u64,
    /// Next free offset in each thread's buffer area, so two buffers mapped by
    /// the same thread never overlap.
    next_offset: BTreeMap<usize, u64>,
    /// The scanout buffer, created on first request and shared thereafter.
    scanout: Option<BufferId>,
    /// Threads permitted to obtain the scanout buffer at all.
    ///
    /// Reaching the screen is authority, not a service. Without this list any
    /// Ring 3 process could ask for the framebuffer and be handed it, which
    /// means reading everything displayed and drawing anything it liked over
    /// the top -- in a system whose whole point is that a process gets only what
    /// it was given.
    display_servers: Vec<ThreadId>,
}

impl Registry {
    fn new() -> Self {
        Self {
            buffers: BTreeMap::new(),
            next_id: 1,
            next_offset: BTreeMap::new(),
            scanout: None,
            display_servers: Vec::new(),
        }
    }
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    without_interrupts(|| {
        let mut guard = REGISTRY.lock();
        f(guard.get_or_insert_with(Registry::new))
    })
}

/// Allocate a buffer backed by fresh physical frames.
pub fn create(owner: ThreadId, width: u32, height: u32) -> Result<BufferId, Error> {
    if width == 0 || height == 0 {
        return Err(Error::InvalidArgument);
    }

    let depth = bytes_per_pixel();
    let stride = width.checked_mul(depth).ok_or(Error::InvalidArgument)?;
    let size = (stride as u64)
        .checked_mul(height as u64)
        .ok_or(Error::InvalidArgument)?;

    if size > MAX_BUFFER_BYTES {
        return Err(Error::InvalidArgument);
    }

    let pages = size.div_ceil(PAGE_SIZE);
    let mut frames = Vec::new();

    // Take the frames up front. A partial allocation that then fails has to give
    // everything back, or a process can leak physical memory by asking for
    // buffers it knows will not fit.
    for _ in 0..pages {
        match crate::memory::frame::with(|allocator| allocator.allocate()) {
            Some(frame) => frames.push(frame),
            None => {
                crate::memory::frame::with(|allocator| {
                    for frame in frames.drain(..) {
                        allocator.deallocate(frame);
                    }
                });
                return Err(Error::OutOfMemory);
            }
        }
    }

    Ok(with(|registry| {
        let id = registry.next_id;
        registry.next_id += 1;
        registry.buffers.insert(
            id,
            Buffer {
                info: BufferInfo {
                    width,
                    height,
                    stride,
                    bytes_per_pixel: depth,
                    size,
                },
                frames,
                owns_frames: true,
                owner,
                shared_with: Vec::new(),
                mappings: Vec::new(),
                orphaned: false,
            },
        );
        BufferId(id)
    }))
}

/// The display's own memory, as a buffer.
///
/// Created once and shared on every later call: there is one screen, and two
/// independent handles to it would let two compositors fight over the same
/// pixels without either knowing.
pub fn scanout(owner: ThreadId) -> Result<BufferId, Error> {
    // Checked before anything else is looked up, so a caller with no business
    // here cannot even learn whether a display exists.
    if !is_display_server(owner) {
        return Err(Error::NoCapability);
    }

    let info = console::framebuffer::info().ok_or(Error::NoSuchEndpoint)?;
    let virtual_base = console::framebuffer::buffer_address().ok_or(Error::NoSuchEndpoint)?;
    let physical_base = paging::translate(VirtAddr::new(virtual_base))
        .ok_or(Error::BadPointer)?
        .as_u64();

    let size = info.byte_len as u64;
    let pages = size.div_ceil(PAGE_SIZE);

    // The display's memory is physically contiguous, so the frame list is just
    // an arithmetic sequence from the BAR.
    let frames = (0..pages)
        .map(|index| PhysFrame::containing_address(PhysAddr::new(physical_base + index * PAGE_SIZE)))
        .collect();

    Ok(with(|registry| {
        if let Some(existing) = registry.scanout {
            // Whoever asks second gets access rather than a second handle.
            if let Some(buffer) = registry.buffers.get_mut(&existing.0) {
                if !buffer.may_access(owner) {
                    buffer.shared_with.push(owner);
                }
            }
            return existing;
        }

        let id = registry.next_id;
        registry.next_id += 1;
        registry.buffers.insert(
            id,
            Buffer {
                info: BufferInfo {
                    width: info.width as u32,
                    height: info.height as u32,
                    stride: (info.stride * info.bytes_per_pixel) as u32,
                    bytes_per_pixel: info.bytes_per_pixel as u32,
                    size,
                },
                frames,
                owns_frames: false,
                owner,
                shared_with: Vec::new(),
                mappings: Vec::new(),
                orphaned: false,
            },
        );

        registry.scanout = Some(BufferId(id));
        BufferId(id)
    }))
}

/// Designate a thread as a display server, letting it obtain the scanout buffer.
///
/// Deliberately not a syscall. Ring 3 must not be able to promote itself to
/// owning the screen; the grant comes from whoever spawned the display server,
/// which today is the kernel and later would be a service manager.
pub fn allow_display_server(thread: ThreadId) {
    with(|registry| {
        if !registry.display_servers.contains(&thread) {
            registry.display_servers.push(thread);
        }
    });
}

/// Whether a thread may obtain the scanout buffer.
pub fn is_display_server(thread: ThreadId) -> bool {
    with(|registry| registry.display_servers.contains(&thread))
}

/// Let `target` map this buffer. Owner only.
pub fn share(owner: ThreadId, target: ThreadId, buffer: BufferId) -> Result<(), Error> {
    with(|registry| {
        let entry = registry
            .buffers
            .get_mut(&buffer.0)
            .ok_or(Error::NoSuchEndpoint)?;

        if entry.owner != owner {
            return Err(Error::NoCapability);
        }
        if !entry.shared_with.contains(&target) {
            entry.shared_with.push(target);
        }
        Ok(())
    })
}

/// Map a buffer into a thread's slot and return the address it landed at.
///
/// Mapping twice returns the existing address rather than consuming more of the
/// slot.
pub fn map(thread: ThreadId, buffer: BufferId) -> Result<u64, Error> {
    // Collect what is needed under the lock, then map outside it: establishing a
    // mapping takes the page-table and frame-allocator locks, and nesting those
    // under this one in some paths but not others is how deadlocks appear.
    let (frames, size, address) = with(|registry| {
        let entry = registry
            .buffers
            .get_mut(&buffer.0)
            .ok_or(Error::NoSuchEndpoint)?;

        if !entry.may_access(thread) {
            return Err(Error::NoCapability);
        }

        if let Some((_, existing)) = entry.mappings.iter().find(|(id, _)| *id == thread) {
            return Ok((Vec::new(), 0u64, *existing));
        }

        // The thread's allocated slot, not its id. Those were the same thing
        // until slots became reusable, and conflating them is what let the
        // seventeenth user program index past the end of the region.
        let slot = userspace::ensure_slot(thread).ok_or(Error::OutOfMemory)?;
        let slot_base = userspace::slot_base_of(slot);
        let offset = registry
            .next_offset
            .entry(thread.0)
            .or_insert(userspace::BUFFER_AREA_OFFSET);

        let address = slot_base + *offset;
        let span = entry.info.size.div_ceil(PAGE_SIZE) * PAGE_SIZE;

        if *offset + span > userspace::SLOT_SIZE {
            return Err(Error::OutOfMemory);
        }
        *offset += span;

        entry.mappings.push((thread, address));
        Ok((entry.frames.clone(), entry.info.size, address))
    })?;

    // Already mapped.
    if size == 0 {
        return Ok(address);
    }

    // Pixels, never instructions. A shared buffer a client can write and a
    // compositor maps would otherwise be an ideal place to stage code.
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    for (index, frame) in frames.iter().enumerate() {
        let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(VirtAddr::new(
            address + index as u64 * PAGE_SIZE,
        ));

        // SAFETY: for an allocated buffer these frames came from the frame
        // allocator and are owned by this buffer alone. For the scanout buffer
        // they are the display controller's MMIO window, which the allocator
        // never hands out because it sits far above the highest usable RAM
        // address. Either way nothing else will map them behind our back.
        unsafe { paging::map_to_frame(page, *frame, flags) }.map_err(|_| Error::OutOfMemory)?;
    }

    Ok(address)
}

/// Release a buffer and return its frames to the allocator. Owner only.
///
/// Every mapping is torn down first. Freeing frames that are still reachable
/// from a user address space is a use-after-free the kernel handed out itself --
/// the process would go on writing into memory the allocator had given to
/// someone else.
pub fn destroy(owner: ThreadId, buffer: BufferId) -> Result<(), Error> {
    let (frames, mappings, span) = with(|registry| {
        let entry = registry
            .buffers
            .get(&buffer.0)
            .ok_or(Error::NoSuchEndpoint)?;

        if entry.owner != owner {
            return Err(Error::NoCapability);
        }
        if registry.scanout == Some(buffer) {
            // There is one screen and it is not the caller's to destroy.
            return Err(Error::InvalidArgument);
        }

        let entry = registry
            .buffers
            .remove(&buffer.0)
            .expect("present a moment ago");
        let span = entry.info.size.div_ceil(PAGE_SIZE);
        let frames = if entry.owns_frames {
            entry.frames
        } else {
            Vec::new()
        };
        Ok((frames, entry.mappings, span))
    })?;

    for (_, address) in mappings {
        for index in 0..span {
            let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                VirtAddr::new(address + index * PAGE_SIZE),
            );
            // The frames are freed below rather than here, so `unmap` is used
            // instead of `unmap_and_free`: a scanout buffer's frames belong to
            // the display controller and must never reach the allocator.
            let _ = paging::unmap(page);
        }
    }

    crate::memory::frame::with(|allocator| {
        for frame in frames {
            allocator.deallocate(frame);
        }
    });

    Ok(())
}

/// Release everything a thread holds: its own buffers, its mappings of other
/// people's buffers, and its share entries.
///
/// Called when the thread exits. Without it a process that allocated a
/// framebuffer-sized buffer leaked those frames for the rest of the system's
/// uptime, and nothing ever noticed.
pub fn release_thread(thread: ThreadId) {
    let (frames, unmap) = with(|registry| {
        let scanout = registry.scanout;
        let mut frames: Vec<PhysFrame<Size4KiB>> = Vec::new();
        let mut unmap: Vec<(u64, u64)> = Vec::new();

        // Drop this thread's mappings and share entries everywhere, and mark
        // anything it owned as orphaned rather than destroying it outright.
        for (id, buffer) in registry.buffers.iter_mut() {
            if let Some(index) = buffer.mappings.iter().position(|(t, _)| *t == thread) {
                let (_, address) = buffer.mappings.remove(index);
                unmap.push((address, buffer.info.size.div_ceil(PAGE_SIZE)));
            }
            buffer.shared_with.retain(|other| *other != thread);

            if buffer.owner == thread && scanout != Some(BufferId(*id)) {
                buffer.orphaned = true;
            }
        }

        // Now free the orphans nobody is left holding. A buffer whose owner has
        // gone but which a compositor still has mapped stays alive until that
        // reference goes too -- last one out frees it.
        let unreferenced: Vec<u64> = registry
            .buffers
            .iter()
            .filter(|(id, buffer)| {
                buffer.orphaned
                    && buffer.mappings.is_empty()
                    && buffer.shared_with.is_empty()
                    && scanout != Some(BufferId(**id))
            })
            .map(|(id, _)| *id)
            .collect();

        for id in unreferenced {
            if let Some(buffer) = registry.buffers.remove(&id) {
                if buffer.owns_frames {
                    frames.extend(buffer.frames);
                }
            }
        }

        registry.next_offset.remove(&thread.0);
        registry.display_servers.retain(|other| *other != thread);
        (frames, unmap)
    });

    for (address, pages) in unmap {
        for index in 0..pages {
            let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                VirtAddr::new(address + index * PAGE_SIZE),
            );
            // `unmap`, not `unmap_and_free`: scanout frames belong to the
            // display controller and must never reach the frame allocator.
            let _ = paging::unmap(page);
        }
    }

    crate::memory::frame::with(|allocator| {
        for frame in frames {
            allocator.deallocate(frame);
        }
    });
}

pub fn info(thread: ThreadId, buffer: BufferId) -> Result<BufferInfo, Error> {
    with(|registry| {
        let entry = registry
            .buffers
            .get(&buffer.0)
            .ok_or(Error::NoSuchEndpoint)?;
        if !entry.may_access(thread) {
            return Err(Error::NoCapability);
        }
        Ok(entry.info)
    })
}

/// Whether a thread may map a buffer. Diagnostic, and used by tests.
pub fn may_access(thread: ThreadId, buffer: BufferId) -> bool {
    with(|registry| {
        registry
            .buffers
            .get(&buffer.0)
            .is_some_and(|entry| entry.may_access(thread))
    })
}

/// Number of live buffers.
pub fn count() -> usize {
    with(|registry| registry.buffers.len())
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

fn current() -> Result<ThreadId, Error> {
    crate::sched::current_id().ok_or(Error::InvalidArgument)
}

pub fn sys_create(width: u64, height: u64) -> Result<i64, Error> {
    let width = u32::try_from(width).map_err(|_| Error::InvalidArgument)?;
    let height = u32::try_from(height).map_err(|_| Error::InvalidArgument)?;
    Ok(create(current()?, width, height)?.0 as i64)
}

pub fn sys_scanout() -> Result<i64, Error> {
    Ok(scanout(current()?)?.0 as i64)
}

pub fn sys_map(buffer: u64) -> Result<i64, Error> {
    Ok(map(current()?, BufferId(buffer))? as i64)
}

pub fn sys_share(buffer: u64, target: u64) -> Result<i64, Error> {
    let target = usize::try_from(target).map_err(|_| Error::InvalidArgument)?;
    share(current()?, ThreadId(target), BufferId(buffer))?;
    Ok(0)
}

pub fn sys_info(buffer: u64, pointer: u64) -> Result<i64, Error> {
    let size = core::mem::size_of::<BufferInfo>() as u64;
    if !userspace::validate_user_buffer(pointer, size, true) {
        return Err(Error::BadPointer);
    }

    let info = info(current()?, BufferId(buffer))?;

    // SAFETY: the range was just confirmed present, user-accessible and writable
    // for the whole struct. Unaligned because nothing obliges user space to
    // align its buffer.
    unsafe { core::ptr::write_unaligned(pointer as *mut BufferInfo, info) };
    Ok(0)
}
