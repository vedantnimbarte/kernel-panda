//! Per-process resource limits.
//!
//! The limits used to be four constants, identical for every thread in the
//! system. That bounds the damage one process can do, which is the important
//! half, but it says the compositor and a throwaway test program deserve the
//! same share of the machine -- and it gives whoever launches a process no way
//! to say otherwise.
//!
//! A thread's limits are now set by whoever spawned it, and the rule is the one
//! the capability system already uses: **authority narrows, never widens**. A
//! thread can hand a child less than it has, and cannot hand it more, so a
//! process cannot raise its own ceiling by spawning a helper and asking the
//! helper for memory. The kernel starts with [`Quota::DEFAULT`] and everything
//! descends from that.

use alloc::vec::Vec;

use crate::sched::ThreadId;
use crate::sync::{without_interrupts, Mutex};

/// What one thread may hold at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Endpoints it may own.
    pub endpoints: usize,
    /// Distinct endpoints it may hold capabilities for. Bounds the capability
    /// table when a thread is on the receiving end of many grants.
    pub capabilities: usize,
    /// Graphics buffers it may own at once.
    pub buffers: usize,
    /// Total bytes across those buffers.
    pub buffer_bytes: u64,
}

impl Quota {
    /// What a thread gets when nobody said otherwise.
    pub const DEFAULT: Quota = Quota {
        endpoints: 32,
        capabilities: 128,
        buffers: 16,
        buffer_bytes: 64 * 1024 * 1024,
    };

    /// Nothing at all. Useful for a process that should hold no resources of
    /// its own.
    pub const NOTHING: Quota = Quota {
        endpoints: 0,
        capabilities: 0,
        buffers: 0,
        buffer_bytes: 0,
    };

    /// The most this quota can grant: each field capped by `self`.
    ///
    /// This is what makes the limits a hierarchy rather than a suggestion. A
    /// thread asking to give a child more than it has gets the child capped at
    /// its own share, silently -- there is nothing to report, because the child
    /// still receives a perfectly valid quota.
    pub fn narrow_to(self, requested: Quota) -> Quota {
        Quota {
            endpoints: requested.endpoints.min(self.endpoints),
            capabilities: requested.capabilities.min(self.capabilities),
            buffers: requested.buffers.min(self.buffers),
            buffer_bytes: requested.buffer_bytes.min(self.buffer_bytes),
        }
    }
}

/// Threads with a quota other than the default.
///
/// A list rather than a map: it is consulted on every `create` and read far more
/// often than it is written, but it only ever holds the threads somebody has
/// deliberately restricted -- which is a handful, not one entry per thread.
static ASSIGNED: Mutex<Vec<(ThreadId, Quota)>> = Mutex::new(Vec::new());

/// What `thread` may hold.
pub fn of(thread: ThreadId) -> Quota {
    without_interrupts(|| {
        ASSIGNED
            .lock()
            .iter()
            .find(|(id, _)| *id == thread)
            .map(|(_, quota)| *quota)
            .unwrap_or(Quota::DEFAULT)
    })
}

/// Give `target` a quota, capped by what `granter` itself holds.
///
/// Returns what the target actually got.
pub fn grant(granter: ThreadId, target: ThreadId, requested: Quota) -> Quota {
    let allowed = of(granter).narrow_to(requested);

    without_interrupts(|| {
        let mut assigned = ASSIGNED.lock();
        match assigned.iter_mut().find(|(id, _)| *id == target) {
            Some((_, existing)) => *existing = allowed,
            None => assigned.push((target, allowed)),
        }
    });

    allowed
}

/// Forget a thread's quota. Called when it exits, or the list grows for the
/// life of the system.
pub fn release_thread(thread: ThreadId) {
    without_interrupts(|| ASSIGNED.lock().retain(|(id, _)| *id != thread));
}

/// Threads currently holding a non-default quota. Diagnostic, and used by
/// tests.
pub fn assigned_count() -> usize {
    without_interrupts(|| ASSIGNED.lock().len())
}
