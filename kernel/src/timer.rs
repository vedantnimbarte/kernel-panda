//! One-shot timers for Ring 3: after a delay, a message from the kernel.
//!
//! A process that has to act on time -- resend what was not acknowledged, give
//! up on what never answered -- waits in `ipc_receive` like any other. A timer
//! puts a message in that same queue when it comes due, so waiting for a reply
//! and waiting for a deadline are one wait.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ipc::{self, EndpointId, Message, Rights};
use crate::sched::{self, ThreadId};
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::{Error, SyscallResult};

/// Tag of a timer's message. `words[0]` is the cookie it was set with.
pub const TAG_TIMER: u64 = 0x3_0000;

/// Pending timers one thread may have. Setting another on the same endpoint
/// replaces the old one rather than counting against this.
const PER_THREAD: usize = 8;

struct Timer {
    deadline: u64,
    owner: ThreadId,
    endpoint: EndpointId,
    cookie: u64,
}

static TIMERS: Mutex<Vec<Timer>> = Mutex::new(Vec::new());

/// The earliest deadline, so a tick with nothing due never takes the lock.
static NEXT: AtomicU64 = AtomicU64::new(u64::MAX);

/// Deliver `cookie` to `endpoint` after `ms` milliseconds, replacing any timer
/// the caller already has on it. The caller must be able to receive there: a
/// timer is a message to oneself, not a way to post into someone else's queue.
pub fn sys_set(endpoint: u64, ms: u64, cookie: u64) -> SyscallResult {
    let owner = sched::current_id().ok_or(Error::InvalidArgument)?;
    let endpoint = EndpointId(endpoint);
    if !ipc::rights_of(owner, endpoint).contains(Rights::RECEIVE) {
        return Err(Error::NoCapability);
    }

    let hz = crate::time::frequency_hz().max(1);
    let deadline = crate::time::ticks().saturating_add(ms.saturating_mul(hz).div_ceil(1000).max(1));

    without_interrupts(|| {
        let mut timers = TIMERS.lock();
        timers.retain(|timer| timer.owner != owner || timer.endpoint != endpoint);
        if timers.iter().filter(|timer| timer.owner == owner).count() >= PER_THREAD {
            return Err(Error::QuotaExceeded);
        }
        timers.push(Timer { deadline, owner, endpoint, cookie });
        NEXT.fetch_min(deadline, Ordering::AcqRel);
        Ok(0)
    })
}

/// Fire what is due. Called on every timer tick.
pub fn on_tick(now: u64) {
    if now < NEXT.load(Ordering::Acquire) {
        return;
    }

    let due = without_interrupts(|| {
        let mut timers = TIMERS.lock();
        let mut due = Vec::new();
        let mut earliest = u64::MAX;
        timers.retain(|timer| {
            if timer.deadline <= now {
                due.push((timer.endpoint, timer.cookie));
                false
            } else {
                earliest = earliest.min(timer.deadline);
                true
            }
        });
        NEXT.store(earliest, Ordering::Release);
        due
    });

    for (endpoint, cookie) in due {
        let message = Message { tag: TAG_TIMER, words: [cookie, 0, 0, 0], sender: 0, sender_user: 0 };
        // A full queue loses the tick; its owner is plainly already awake.
        let _ = ipc::notify(endpoint, message);
    }
}

/// Forget a thread's timers when it exits.
pub fn release_thread(thread: ThreadId) {
    without_interrupts(|| TIMERS.lock().retain(|timer| timer.owner != thread));
}
