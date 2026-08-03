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
/// This is not priority-aware: a `High` thread queues behind a `Low` one that
/// asked first. Fixing that means priority inheritance, which needs the lock to
/// know who holds it and the scheduler to be reachable from here.
pub struct Mutex<T> {
    /// Handed out to arriving callers.
    next_ticket: AtomicUsize,
    /// The ticket whose turn it is. Incremented on release.
    now_serving: AtomicUsize,
    value: UnsafeCell<T>,
}

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
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);

        while self.now_serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }

        MutexGuard { lock: self }
    }

    /// Take the lock only if it is free and nobody is already queued.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let serving = self.now_serving.load(Ordering::Acquire);
        // Only succeeds when the queue is empty: `next_ticket` still equals the
        // ticket being served. Taking a number and hoping would make this a
        // blocking call under another name.
        self.next_ticket
            .compare_exchange(serving, serving + 1, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| MutexGuard { lock: self })
    }
}

pub struct MutexGuard<'a, T> {
    lock: &'a Mutex<T>,
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
    }
}

/// A spinlock that also masks interrupts on the holding CPU.
///
/// Required for any lock that can be taken from both thread context and an
/// interrupt handler. Without the masking, a handler that needs the lock can
/// interrupt the very thread holding it, and then spins forever: the holder
/// cannot run again to release it, because the handler is standing on it. The
/// heap allocator is exactly this case -- the timer handler reaps threads and
/// buffers console input, and both of those allocate.
///
/// This is the right primitive on a multi-core machine too, not just a
/// single-core stand-in. Masking is per-CPU and stops *this* core deadlocking
/// against itself; the spin still provides mutual exclusion against the others.
/// What it must never be mistaken for is a way to get exclusion by disabling
/// interrupts alone -- that only ever worked with one core.
///
/// Inherits the ticket ordering of [`Mutex`], so a core cannot be starved of a
/// lock the others are hammering.
pub struct IrqMutex<T> {
    inner: Mutex<T>,
}

impl<T> IrqMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    pub fn lock(&self) -> IrqMutexGuard<'_, T> {
        // Sample before disabling, so nested locks restore correctly: only the
        // outermost one re-enables.
        let restore = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();

        IrqMutexGuard {
            guard: Some(self.inner.lock()),
            restore,
        }
    }
}

pub struct IrqMutexGuard<'a, T> {
    guard: Option<MutexGuard<'a, T>>,
    restore: bool,
}

impl<T> Deref for IrqMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.guard.as_ref().expect("guard taken only on drop")
    }
}

impl<T> DerefMut for IrqMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().expect("guard taken only on drop")
    }
}

impl<T> Drop for IrqMutexGuard<'_, T> {
    fn drop(&mut self) {
        // Order matters: release the spinlock first, then re-enable. Doing it
        // the other way round reopens the exact window this type exists to
        // close, for the instant between the two.
        drop(self.guard.take());
        if self.restore {
            x86_64::instructions::interrupts::enable();
        }
    }
}

/// Whether interrupts are currently enabled on this CPU.
pub fn interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}
