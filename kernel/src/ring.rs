//! Rings: message queues two processes share, with no system call per message.
//!
//! An endpoint moves every message through the kernel: a system call to send,
//! one to receive, and a context switch in between whenever the receiver was
//! waiting. A ring moves them through memory both processes map. The sender
//! writes a 64-byte slot and advances a counter; the receiver reads the slot and
//! advances its own. The kernel's part is setting that memory up, deciding who
//! may map which side, and waking a side that has gone to sleep -- which in a
//! busy channel is rarely.
//!
//! A ring is an endpoint with pages attached, so everything capabilities already
//! do applies unchanged: holding `SEND` is what lets a thread map the ring as its
//! sender, `RECEIVE` as its receiver, and `GRANT` hands either on.
//!
//! ## One writer per page
//!
//! ```text
//! page 0        the kernel's:   slot count, read-only to both
//! page 1        the sender's:   tail, sender-sleeping flag
//! page 2        the receiver's: head, receiver-sleeping flag
//! pages 3..     the slots, written by the sender
//! ```
//!
//! Each counter page is writable by exactly one side and read-only to the other.
//! The slot count is on a page of its own because both sides size their reads
//! by it: in either side's page, that side could inflate it and point the other
//! past the end of the ring. The
//! receiver cannot forge a message or move the sender's tail; the sender cannot
//! move the receiver's head. What either can still do is lie in its own page --
//! a tail that runs past the head by more than the ring holds -- and both sides
//! must treat that as a broken channel. It stays a broken *channel*: the memory
//! is the ring's own, and no value in it reaches past it.
//!
//! Exactly one thread maps each side. A second sender would race the first on a
//! counter nothing locks, so the side is claimed by whoever maps it first.
//!
//! ## Sleeping without losing a wake
//!
//! A side about to wait sets its flag with a single exchange, looks again, and
//! only then asks the kernel to park it; the kernel looks a third time under its
//! lock. The other side publishes its counter with an exchange and then reads
//! the flag, waking the sleeper through the kernel if it is set. On x86 an
//! exchange with memory is a locked instruction, which commits the write before
//! the following read -- so of the two, at least one sees the other's write, and
//! the Dekker-shaped race that would park a receiver next to a message cannot
//! happen.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;

use crate::ipc::{self, EndpointId, Rights};
use crate::memory::{frame, paging};
use crate::sched::{self, ThreadId};
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::{Error, SyscallResult};

/// Bytes in one slot.
pub const SLOT_BYTES: u64 = 64;
/// Most slots a ring may have: 256 KiB of messages.
pub const MAX_SLOTS: u32 = 4096;

// Offsets within the header pages. Part of the ABI.
pub const SLOT_COUNT: u64 = 0;
pub const TAIL: u64 = 0;
pub const SENDER_SLEEPING: u64 = 4;
pub const HEAD: u64 = 0;
pub const RECEIVER_SLEEPING: u64 = 4;

const PAGE_SIZE: u64 = 4096;
const INFO_PAGE: usize = 0;
const SENDER_PAGE: usize = 1;
const RECEIVER_PAGE: usize = 2;
const FIRST_SLOT_PAGE: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Sender = 0,
    Receiver = 1,
}

impl Side {
    fn from_raw(raw: u64) -> Result<Side, Error> {
        match raw {
            0 => Ok(Side::Sender),
            1 => Ok(Side::Receiver),
            _ => Err(Error::InvalidArgument),
        }
    }

    fn right(self) -> Rights {
        match self {
            Side::Sender => Rights::SEND,
            Side::Receiver => Rights::RECEIVE,
        }
    }
}

struct Ring {
    owner: ThreadId,
    /// The owner has exited; the ring lives on while either side maps it.
    owner_gone: bool,
    frames: Vec<PhysFrame<Size4KiB>>,
    slots: u32,
    /// Who mapped each side, and where.
    sides: [Option<(ThreadId, u64)>; 2],
    /// A side parked in `wait`.
    sleeping: [Option<ThreadId>; 2],
}

impl Ring {
    fn counter(&self, page: usize, offset: u64) -> u32 {
        let address = paging::physical_offset() + self.frames[page].start_address().as_u64() + offset;
        // SAFETY: a frame this ring owns, reached through the physical-memory
        // window, which maps every frame whichever address space is loaded.
        unsafe { core::ptr::read_volatile(address.as_ptr::<u32>()) }
    }

    /// Messages waiting, or `None` if the counters are inconsistent -- one side
    /// has written something the ring cannot hold.
    fn queued(&self) -> Option<u32> {
        let queued = self.counter(SENDER_PAGE, TAIL).wrapping_sub(self.counter(RECEIVER_PAGE, HEAD));
        (queued <= self.slots).then_some(queued)
    }

    /// Whether a side waiting now would have something to do.
    fn ready_for(&self, side: Side) -> bool {
        match (side, self.queued()) {
            // A broken ring wakes everyone, so each finds out for itself.
            (_, None) => true,
            (Side::Receiver, Some(queued)) => queued > 0,
            (Side::Sender, Some(queued)) => queued < self.slots,
        }
    }
}

static RINGS: Mutex<BTreeMap<u64, Ring>> = Mutex::new(BTreeMap::new());

fn with<R>(f: impl FnOnce(&mut BTreeMap<u64, Ring>) -> R) -> R {
    without_interrupts(|| f(&mut RINGS.lock()))
}

/// Create a ring of `slots` messages, owned by `owner` with every right.
pub fn create(owner: ThreadId, slots: u32) -> Result<EndpointId, Error> {
    if !(2..=MAX_SLOTS).contains(&slots) {
        return Err(Error::InvalidArgument);
    }
    // The endpoint first: it is what the owner's quota counts, and refusing
    // there costs no memory.
    let endpoint = ipc::create(owner, 1)?;

    let pages = FIRST_SLOT_PAGE + (slots as u64 * SLOT_BYTES).div_ceil(PAGE_SIZE) as usize;
    let mut frames = Vec::with_capacity(pages);
    for _ in 0..pages {
        let Some(frame) = frame::with(|allocator| allocator.allocate()) else {
            frame::with(|allocator| frames.iter().for_each(|f| allocator.deallocate(*f)));
            return Err(Error::OutOfMemory);
        };
        frames.push(frame);
    }

    let offset = paging::physical_offset();
    for frame in &frames {
        // SAFETY: frames just allocated, reached through the physical window.
        // Zeroed, because a counter left from a previous owner is a message.
        unsafe {
            core::ptr::write_bytes((offset + frame.start_address().as_u64()).as_mut_ptr::<u8>(), 0, PAGE_SIZE as usize)
        };
    }
    let count = offset + frames[INFO_PAGE].start_address().as_u64() + SLOT_COUNT;
    // SAFETY: as above. Read by both sides, written only here.
    unsafe { core::ptr::write_volatile(count.as_mut_ptr::<u32>(), slots) };

    with(|rings| {
        rings.insert(
            endpoint.0,
            Ring {
                owner,
                owner_gone: false,
                frames,
                slots,
                sides: [None, None],
                sleeping: [None, None],
            },
        )
    });
    Ok(endpoint)
}

/// Map one side of a ring into `thread`, returning where. Mapping the same
/// side again returns the same address.
pub fn map(thread: ThreadId, endpoint: EndpointId, side: Side) -> Result<u64, Error> {
    if !ipc::rights_of(thread, endpoint).contains(side.right()) {
        return Err(Error::NoCapability);
    }

    let (frames, address) = with(|rings| -> Result<_, Error> {
        let ring = rings.get_mut(&endpoint.0).ok_or(Error::NoSuchEndpoint)?;
        match ring.sides[side as usize] {
            Some((holder, address)) if holder == thread => return Ok((Vec::new(), address)),
            // One writer per counter. See the module notes.
            Some(_) => return Err(Error::AlreadyExists),
            None => {}
        }
        let span = ring.frames.len() as u64 * PAGE_SIZE;
        let address = crate::gbm::reserve_address(thread, span)?;
        ring.sides[side as usize] = Some((thread, address));
        Ok((ring.frames.clone(), address))
    })?;

    let target = sched::address_space_of(thread).unwrap_or_else(paging::kernel_space);
    let read_only = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;
    for (index, frame) in frames.iter().enumerate() {
        let writable = match side {
            Side::Sender => index == SENDER_PAGE || index >= FIRST_SLOT_PAGE,
            Side::Receiver => index == RECEIVER_PAGE,
        };
        let flags = if writable { read_only | PageTableFlags::WRITABLE } else { read_only };
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(address + index as u64 * PAGE_SIZE));
        // SAFETY: the ring's own frames, owned by it and freed only once no side
        // maps them, at an address reserved for this thread alone.
        unsafe { paging::map_to_frame_in(&target, page, *frame, flags) }.map_err(|_| Error::OutOfMemory)?;
    }
    Ok(address)
}

/// Park `thread` until its side of the ring has something to do.
pub fn wait(thread: ThreadId, endpoint: EndpointId) -> Result<(), Error> {
    loop {
        let parked = without_interrupts(|| -> Result<bool, Error> {
            let should_block = {
                let mut rings = RINGS.lock();
                let ring = rings.get_mut(&endpoint.0).ok_or(Error::NoSuchEndpoint)?;
                let side = side_of(ring, thread)?;
                if ring.ready_for(side) {
                    false
                } else {
                    ring.sleeping[side as usize] = Some(thread);
                    true
                }
            };
            // The lock is released before parking. A wake landing in between is
            // recorded, and `block_current` declines to park.
            Ok(should_block && sched::block_current())
        })?;

        if !parked {
            let ready = with(|rings| {
                let ring = rings.get(&endpoint.0).ok_or(Error::NoSuchEndpoint)?;
                Ok::<bool, Error>(ring.ready_for(side_of(ring, thread)?))
            })?;
            if ready {
                return Ok(());
            }
        }
        // Woken, or a wake raced the park: look again.
    }
}

/// Wake the other side of the ring, if it is parked.
pub fn wake(thread: ThreadId, endpoint: EndpointId) -> Result<(), Error> {
    let sleeper = with(|rings| {
        let ring = rings.get_mut(&endpoint.0).ok_or(Error::NoSuchEndpoint)?;
        let other = match side_of(ring, thread)? {
            Side::Sender => Side::Receiver,
            Side::Receiver => Side::Sender,
        };
        Ok::<_, Error>(ring.sleeping[other as usize].take())
    })?;
    // Outside the ring lock: waking takes a processor's.
    if let Some(sleeper) = sleeper {
        sched::unblock(sleeper);
    }
    Ok(())
}

fn side_of(ring: &Ring, thread: ThreadId) -> Result<Side, Error> {
    if ring.sides[Side::Sender as usize].is_some_and(|(holder, _)| holder == thread) {
        Ok(Side::Sender)
    } else if ring.sides[Side::Receiver as usize].is_some_and(|(holder, _)| holder == thread) {
        Ok(Side::Receiver)
    } else {
        Err(Error::NoCapability)
    }
}

/// Rings that exist. Diagnostic, and used by tests.
pub fn count() -> usize {
    with(|rings| rings.len())
}

/// Withdraw a thread from every ring, before its address space is destroyed.
///
/// Must run before `userspace::release_slot`: tearing down a space frees the
/// data frames mapped in it, and a ring's frames are not the thread's to free.
/// A ring whose owner is gone and which nobody maps any longer is freed here.
pub fn release_thread(thread: ThreadId) {
    let (unmap, freed) = with(|rings| {
        let mut unmap = Vec::new();
        for ring in rings.values_mut() {
            if ring.owner == thread {
                ring.owner_gone = true;
            }
            for side in ring.sides.iter_mut() {
                if let Some((holder, address)) = *side {
                    if holder == thread {
                        unmap.push((address, ring.frames.len() as u64));
                        *side = None;
                    }
                }
            }
            for sleeper in ring.sleeping.iter_mut() {
                if *sleeper == Some(thread) {
                    *sleeper = None;
                }
            }
        }

        let dead: Vec<u64> = rings
            .iter()
            .filter(|(_, ring)| ring.owner_gone && ring.sides.iter().all(Option::is_none))
            .map(|(id, _)| *id)
            .collect();
        let freed: Vec<Vec<PhysFrame<Size4KiB>>> =
            dead.into_iter().filter_map(|id| rings.remove(&id)).map(|ring| ring.frames).collect();
        (unmap, freed)
    });

    let target = sched::address_space_of(thread).unwrap_or_else(paging::kernel_space);
    for (address, pages) in unmap {
        for index in 0..pages {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(address + index * PAGE_SIZE));
            // `unmap`, not `unmap_and_free`: the frames are the ring's.
            let _ = paging::unmap_in(&target, page);
        }
    }
    frame::with(|allocator| {
        for frames in freed {
            for frame in frames {
                allocator.deallocate(frame);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

fn current() -> Result<ThreadId, Error> {
    sched::current_id().ok_or(Error::InvalidArgument)
}

pub fn sys_create(slots: u64) -> SyscallResult {
    let slots = u32::try_from(slots).map_err(|_| Error::InvalidArgument)?;
    Ok(create(current()?, slots)?.0 as i64)
}

pub fn sys_map(endpoint: u64, side: u64) -> SyscallResult {
    Ok(map(current()?, EndpointId(endpoint), Side::from_raw(side)?)? as i64)
}

pub fn sys_wait(endpoint: u64) -> SyscallResult {
    wait(current()?, EndpointId(endpoint))?;
    Ok(0)
}

pub fn sys_wake(endpoint: u64) -> SyscallResult {
    wake(current()?, EndpointId(endpoint))?;
    Ok(0)
}
