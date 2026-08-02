//! Capability-mediated inter-process communication.
//!
//! Endpoints are bounded ring buffers of fixed-size messages. Sending never
//! blocks -- a full queue is an error the sender must handle -- while receiving
//! blocks until something arrives, which is what lets a daemon sit idle without
//! spinning.
//!
//! ## Capabilities
//!
//! There is no ambient authority. Naming an endpoint is not permission to use
//! it: every operation checks that the calling thread holds a capability with
//! the matching right, and ids are unforgeable only in the sense that holding
//! one is useless without the capability. A thread can hand rights to another
//! thread only if it holds `GRANT`, and only rights it already has -- so
//! authority can be narrowed as it is passed along, never widened.
//!
//! This is what keeps user processes apart while they still share one address
//! space. Until each process gets its own page tables, capabilities are the
//! isolation boundary rather than a second layer behind it.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::sched::{self, ThreadId};
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::{Error, SyscallResult};
use crate::userspace;

/// Payload words per message. Small on purpose: IPC that needs to move bulk data
/// should move a handle to shared pages, not copy the pages through the kernel.
pub const MAX_MESSAGE_WORDS: usize = 4;

/// Upper bound on an endpoint's queue, so one process cannot make the kernel
/// allocate without limit on its behalf.
pub const MAX_CAPACITY: usize = 256;

/// Endpoints one thread may own.
///
/// Without a cap, a process loops on `create` until the kernel heap is gone and
/// takes the whole system down with it -- denial of service from Ring 3 with four
/// instructions.
pub const MAX_ENDPOINTS_PER_THREAD: usize = 32;

/// Distinct endpoints one thread may hold capabilities for. Bounds the growth of
/// the capability table when a thread is on the receiving end of many grants.
pub const MAX_CAPABILITIES_PER_THREAD: usize = 128;

/// Shared with user space, so the layout is part of the ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Message {
    pub tag: u64,
    pub words: [u64; MAX_MESSAGE_WORDS],
    /// Stamped by the kernel on the way through. A sender cannot forge it, so a
    /// receiver can trust it for authentication.
    pub sender: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndpointId(pub u64);

/// What a capability permits. Hand-rolled rather than pulling in `bitflags`,
/// which is not currently a direct dependency and would not earn its place for
/// three bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u64);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const SEND: Rights = Rights(1 << 0);
    pub const RECEIVE: Rights = Rights(1 << 1);
    /// Permission to pass rights on to another thread.
    pub const GRANT: Rights = Rights(1 << 2);

    const ALL_BITS: u64 = 0b111;

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn intersection(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Discards bits that do not name a right, so a user-supplied integer can
    /// never turn into authority that does not exist.
    pub const fn from_bits_truncate(bits: u64) -> Rights {
        Rights(bits & Self::ALL_BITS)
    }
}

struct Endpoint {
    queue: VecDeque<Message>,
    capacity: usize,
    /// Threads blocked in `recv` on this endpoint, oldest first.
    waiting: VecDeque<ThreadId>,
    /// Recorded so the endpoint can be torn down when its creator exits.
    owner: ThreadId,
}

struct Registry {
    endpoints: BTreeMap<u64, Endpoint>,
    next_id: u64,
    /// Capabilities held per thread, keyed by raw thread id.
    capabilities: BTreeMap<usize, Vec<(u64, Rights)>>,
}

impl Registry {
    fn new() -> Self {
        Self {
            endpoints: BTreeMap::new(),
            // Start at 1 so zero is never a valid endpoint id.
            next_id: 1,
            capabilities: BTreeMap::new(),
        }
    }

    fn rights_of(&self, thread: ThreadId, endpoint: u64) -> Rights {
        self.capabilities
            .get(&thread.0)
            .and_then(|list| {
                list.iter()
                    .find(|(id, _)| *id == endpoint)
                    .map(|(_, rights)| *rights)
            })
            .unwrap_or(Rights::NONE)
    }

    fn add_rights(&mut self, thread: ThreadId, endpoint: u64, rights: Rights) -> Result<(), Error> {
        let list = self.capabilities.entry(thread.0).or_default();
        match list.iter_mut().find(|(id, _)| *id == endpoint) {
            // Widening an existing capability costs no new storage.
            Some((_, existing)) => *existing = existing.union(rights),
            None => {
                if list.len() >= MAX_CAPABILITIES_PER_THREAD {
                    return Err(Error::QuotaExceeded);
                }
                list.push((endpoint, rights));
            }
        }
        Ok(())
    }

    fn endpoints_owned_by(&self, thread: ThreadId) -> usize {
        self.endpoints
            .values()
            .filter(|endpoint| endpoint.owner == thread)
            .count()
    }
}

static REGISTRY: Mutex<Option<Registry>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    without_interrupts(|| {
        let mut guard = REGISTRY.lock();
        f(guard.get_or_insert_with(Registry::new))
    })
}

// ---------------------------------------------------------------------------
// Kernel-facing API
// ---------------------------------------------------------------------------

/// Create an endpoint owned by `owner`, who receives every right over it.
pub fn create(owner: ThreadId, capacity: usize) -> Result<EndpointId, Error> {
    if capacity == 0 || capacity > MAX_CAPACITY {
        return Err(Error::InvalidArgument);
    }

    with(|registry| {
        if registry.endpoints_owned_by(owner) >= MAX_ENDPOINTS_PER_THREAD {
            return Err(Error::QuotaExceeded);
        }

        let id = registry.next_id;
        registry.next_id += 1;

        registry.endpoints.insert(
            id,
            Endpoint {
                queue: VecDeque::new(),
                capacity,
                waiting: VecDeque::new(),
                owner,
            },
        );

        registry.add_rights(
            owner,
            id,
            Rights::SEND.union(Rights::RECEIVE).union(Rights::GRANT),
        )?;

        Ok(EndpointId(id))
    })
}

/// Pass rights to another thread.
///
/// The granter must hold `GRANT`, and can only pass on rights it already holds:
/// `rights` is intersected with the granter's own. Authority narrows as it
/// travels and can never widen.
pub fn grant(
    granter: ThreadId,
    target: ThreadId,
    endpoint: EndpointId,
    rights: Rights,
) -> Result<(), Error> {
    with(|registry| {
        if !registry.endpoints.contains_key(&endpoint.0) {
            return Err(Error::NoSuchEndpoint);
        }

        let held = registry.rights_of(granter, endpoint.0);
        if !held.contains(Rights::GRANT) {
            return Err(Error::NoCapability);
        }

        let effective = rights.intersection(held);
        if effective.is_empty() {
            return Err(Error::NoCapability);
        }

        registry.add_rights(target, endpoint.0, effective)
    })
}

/// Enqueue a message. Never blocks.
///
/// The `sender` field of `message` is overwritten with the real sender.
pub fn send(sender: ThreadId, endpoint: EndpointId, mut message: Message) -> Result<(), Error> {
    let woken = with(|registry| {
        if !registry.rights_of(sender, endpoint.0).contains(Rights::SEND) {
            // Deliberately indistinguishable from "no such endpoint" would be
            // better for probing resistance, but a clear error is worth more
            // while the system is this young.
            return Err(Error::NoCapability);
        }

        let queue = registry
            .endpoints
            .get_mut(&endpoint.0)
            .ok_or(Error::NoSuchEndpoint)?;

        if queue.queue.len() >= queue.capacity {
            return Err(Error::QueueFull);
        }

        message.sender = sender.0 as u64;
        queue.queue.push_back(message);

        Ok(queue.waiting.pop_front())
    })?;

    // Outside the registry lock: waking touches the scheduler, and taking the
    // two locks in the other order anywhere else would be a deadlock.
    if let Some(thread) = woken {
        sched::unblock(thread);
    }

    Ok(())
}

/// Take the next message, blocking until one arrives.
pub fn receive(receiver: ThreadId, endpoint: EndpointId) -> Result<Message, Error> {
    loop {
        // Interrupts stay off across both the registration and the block, and
        // splitting them is a lost wakeup: a sender arriving in the gap pops
        // this thread off the waiter list and calls `unblock`, which does
        // nothing because the thread is still `Running`. It then blocks with
        // nothing left to wake it, and sleeps forever.
        //
        // The registry lock is still released before blocking -- holding a lock
        // across a context switch would leave it held by a thread that is no
        // longer running.
        let outcome = without_interrupts(|| -> Result<Option<Message>, Error> {
            let popped = {
                let mut guard = REGISTRY.lock();
                let registry = guard.get_or_insert_with(Registry::new);

                if !registry
                    .rights_of(receiver, endpoint.0)
                    .contains(Rights::RECEIVE)
                {
                    return Err(Error::NoCapability);
                }

                let queue = registry
                    .endpoints
                    .get_mut(&endpoint.0)
                    .ok_or(Error::NoSuchEndpoint)?;

                match queue.queue.pop_front() {
                    Some(message) => Some(message),
                    None => {
                        // Guarded, so a thread that loops round after a wake it
                        // could not use does not accumulate duplicate entries.
                        if !queue.waiting.contains(&receiver) {
                            queue.waiting.push_back(receiver);
                        }
                        None
                    }
                }
            };

            if popped.is_none() {
                sched::block_current();
            }
            Ok(popped)
        })?;

        // Re-check rather than trust the wake: a spurious one is then harmless.
        if let Some(message) = outcome {
            return Ok(message);
        }
    }
}

/// Take a message if one is queued, without blocking.
pub fn try_receive(receiver: ThreadId, endpoint: EndpointId) -> Result<Option<Message>, Error> {
    with(|registry| {
        if !registry
            .rights_of(receiver, endpoint.0)
            .contains(Rights::RECEIVE)
        {
            return Err(Error::NoCapability);
        }

        let queue = registry
            .endpoints
            .get_mut(&endpoint.0)
            .ok_or(Error::NoSuchEndpoint)?;

        Ok(queue.queue.pop_front())
    })
}

/// Forget a thread: drop its capabilities, its endpoints, and any record of it
/// waiting on someone else's.
///
/// Called when the thread exits. Capability lists are keyed by thread id and ids
/// are never reused, so without this the registry grows for the life of the
/// system and endpoints outlive every process that could ever have used them.
pub fn release_thread(thread: ThreadId) {
    with(|registry| {
        registry.capabilities.remove(&thread.0);

        let owned: Vec<u64> = registry
            .endpoints
            .iter()
            .filter(|(_, endpoint)| endpoint.owner == thread)
            .map(|(id, _)| *id)
            .collect();
        for id in owned {
            registry.endpoints.remove(&id);
        }

        // A thread can be parked on an endpoint it does not own -- leaving a
        // stale id there would have a later sender wake a thread that no longer
        // exists, or worse, one that reused the slot.
        for endpoint in registry.endpoints.values_mut() {
            endpoint.waiting.retain(|waiter| *waiter != thread);
        }
    });
}

/// Rights a thread holds over an endpoint. Diagnostic, and used by tests.
pub fn rights_of(thread: ThreadId, endpoint: EndpointId) -> Rights {
    with(|registry| registry.rights_of(thread, endpoint.0))
}

/// Messages currently queued on an endpoint.
pub fn queued(endpoint: EndpointId) -> usize {
    with(|registry| {
        registry
            .endpoints
            .get(&endpoint.0)
            .map_or(0, |queue| queue.queue.len())
    })
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

fn current() -> Result<ThreadId, Error> {
    sched::current_id().ok_or(Error::InvalidArgument)
}

pub fn sys_create(capacity: u64) -> SyscallResult {
    let capacity = usize::try_from(capacity).map_err(|_| Error::InvalidArgument)?;
    let endpoint = create(current()?, capacity)?;
    Ok(endpoint.0 as i64)
}

pub fn sys_grant(endpoint: u64, target: u64, rights: u64) -> SyscallResult {
    let target = usize::try_from(target).map_err(|_| Error::InvalidArgument)?;
    grant(
        current()?,
        ThreadId(target),
        EndpointId(endpoint),
        Rights::from_bits_truncate(rights),
    )?;
    Ok(0)
}

pub fn sys_send(endpoint: u64, pointer: u64) -> SyscallResult {
    let message = read_user_message(pointer)?;
    send(current()?, EndpointId(endpoint), message)?;
    Ok(0)
}

pub fn sys_recv(endpoint: u64, pointer: u64) -> SyscallResult {
    // Validate the destination before blocking, so a bad pointer is an
    // immediate error rather than a thread that sleeps and then faults.
    let size = core::mem::size_of::<Message>() as u64;
    if !userspace::validate_user_buffer(pointer, size, true) {
        return Err(Error::BadPointer);
    }

    let message = receive(current()?, EndpointId(endpoint))?;

    // Re-validate: this thread slept, and in principle its mappings could have
    // changed while it was away.
    if !userspace::validate_user_buffer(pointer, size, true) {
        return Err(Error::BadPointer);
    }

    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: the range was just confirmed present, user-accessible and
        // writable across the whole struct, and the guard lets Ring 0 reach it.
        // `write_unaligned` because nothing obliges user space to align its
        // buffer.
        unsafe { core::ptr::write_unaligned(pointer as *mut Message, message) };
    });

    Ok(0)
}

fn read_user_message(pointer: u64) -> Result<Message, Error> {
    let size = core::mem::size_of::<Message>() as u64;
    if !userspace::validate_user_buffer(pointer, size, false) {
        return Err(Error::BadPointer);
    }

    Ok(crate::arch::x86_64::with_user_access(|| {
        // SAFETY: validated above as present and user-readable for the full
        // struct, and the guard lets Ring 0 reach it. `read_unaligned` because
        // user space is under no obligation to align it.
        unsafe { core::ptr::read_unaligned(pointer as *const Message) }
    }))
}
