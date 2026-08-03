//! Synchronisation primitives.
//!
//! The rest of the kernel locks through this module rather than naming a crate
//! directly, so the primitive underneath can change without touching call sites.
//! It has: [`Mutex`] is now an in-house ticket lock.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

pub use spin::{Lazy, Once};

pub use x86_64::instructions::interrupts::without_interrupts;

/// A first-come-first-served spinlock.
///
/// A test-and-set spinlock -- which is what this replaced -- has no queue. Every
/// waiter races for the same word on release, and the winner is whichever
/// processor's cache line arrives first. That is not merely unfair in the
/// abstract: the same core tends to win repeatedly, because it is the one whose
/// cache already holds the line, so a contended lock can leave one processor
/// waiting indefinitely while its neighbour reacquires. Under the heap and frame
/// allocators, which every core touches, that is a core doing no work for
/// reasons nothing in the code explains.
///
/// A ticket lock replaces the race with a queue. Each caller takes the next
/// ticket and waits for the counter to reach it, so processors are served in
/// the order they arrived and the longest waiter is always next. The cost is one
/// extra atomic per acquisition, which is nothing beside a single contended
/// cache line bouncing between four cores.
///
/// ## Why there is no priority inheritance
///
/// The usual reason to want it is unbounded priority inversion: a `Low` thread
/// takes a lock, is preempted, and a `High` thread then waits on it for as long
/// as the scheduler keeps choosing something in between. The waiting is
/// unbounded because the holder is not running.
///
/// That cannot happen here, and the reason is structural rather than lucky:
/// **acquiring this lock masks interrupts on the holder's processor**, and every
/// lock in the kernel is this one. A thread that cannot be interrupted cannot be
/// preempted, so a holder always runs its critical section to completion and a
/// waiter waits for that section, not for a scheduling decision.
///
/// The masking used to live in a separate `IrqMutex` wrapper, leaving each call
/// site to pick the right type. That is a decision nobody should have to get
/// right repeatedly, and the one place that got it wrong -- the I/O APIC's
/// register lock -- was a plain lock taken with interrupts live.
///
/// What remains is bounded inversion: a `High` thread can wait behind a `Low`
/// one for the length of a critical section, and the ticket order means it waits
/// behind everyone who asked first. That is a fairness cost measured in
/// microseconds, not a liveness problem, and priority inheritance would not
/// remove it -- boosting a holder that is already running and cannot be
/// descheduled changes nothing.
///
/// The invariant is what makes the argument, so `a_lock_holder_cannot_be_
/// preempted` checks it rather than trusting the reading above.
pub struct Mutex<T> {
    /// Handed out to arriving callers.
    next_ticket: AtomicUsize,
    /// The ticket whose turn it is. Incremented on release.
    now_serving: AtomicUsize,
    value: UnsafeCell<T>,
}

/// Kept as a name for the cases that want to say "this one is definitely
/// reachable from an interrupt handler". Every lock masks interrupts now, so it
/// is the same type.
pub type IrqMutex<T> = Mutex<T>;
pub type IrqMutexGuard<'a, T> = MutexGuard<'a, T>;

// SAFETY: the lock is what makes `&T` from several threads sound, and it hands
// out `&mut T` to one holder at a time. `T: Send` is required because the value
// can be observed and mutated from whichever processor acquires it.
unsafe impl<T: Send> Send for Mutex<T> {}
// SAFETY: as above -- shared access is mediated entirely by the ticket counters.
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            next_ticket: AtomicUsize::new(0),
            now_serving: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Wait for this caller's turn and take the lock.
    ///
    /// Interrupts are masked before the ticket is taken, not after: a tick
    /// landing between the two would put this processor in the queue and then
    /// run a handler that queues behind itself.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        // Sampled before disabling, so nested locks restore correctly -- only
        // the outermost re-enables.
        let restore = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();

        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        while self.now_serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }

        MutexGuard {
            lock: self,
            restore,
        }
    }

    /// Take the lock only if it is free and nobody is already queued.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let restore = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();

        let serving = self.now_serving.load(Ordering::Acquire);
        // Only succeeds when the queue is empty: `next_ticket` still equals the
        // ticket being served. Taking a number and hoping would make this a
        // blocking call under another name.
        let taken = self
            .next_ticket
            .compare_exchange(serving, serving + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok();

        if !taken {
            if restore {
                x86_64::instructions::interrupts::enable();
            }
            return None;
        }

        Some(MutexGuard {
            lock: self,
            restore,
        })
    }
}

pub struct MutexGuard<'a, T> {
    lock: &'a Mutex<T>,
    /// Whether this acquisition is the one that turned interrupts off.
    restore: bool,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: holding the guard means this caller's ticket is the one being
        // served, so no other reference to the value exists.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and `&mut self` rules out a second reference through
        // this guard.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // `Release` pairs with the `Acquire` the next holder is spinning on:
        // everything written under the lock is visible to them before they see
        // their turn arrive. A plain store is enough -- only the holder ever
        // advances this, so there is nothing to race with.
        let next = self.lock.now_serving.load(Ordering::Relaxed).wrapping_add(1);
        self.lock.now_serving.store(next, Ordering::Release);

        // Order matters: hand the lock on first, then re-enable. The other way
        // round reopens the window this exists to close, for the instant
        // between the two.
        if self.restore {
            x86_64::instructions::interrupts::enable();
        }
    }
}

/// Whether interrupts are currently enabled on this CPU.
pub fn interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}
