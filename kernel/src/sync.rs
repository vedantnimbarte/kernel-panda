//! Synchronisation primitives.
//!
//! The rest of the kernel locks through this module rather than naming a crate
//! directly, so the primitive underneath can change without touching call sites.
//! Everything here is in-house: [`Mutex`], a ticket lock; [`SleepMutex`], for
//! holding across work that waits; and [`Once`] and [`Lazy`] for values made
//! on first use.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use alloc::collections::VecDeque;

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

/// A value set at most once, by whichever caller gets there first, and read
/// freely after.
///
/// A caller arriving while another is still making the value spins until it is
/// made. So the maker must not wait on anything that is itself waiting on this
/// value -- the same processor calling back in, from inside the maker or from an
/// interrupt taken during it, spins forever. A maker that panics leaves the
/// value unmade and later callers spinning, which in a kernel whose panic stops
/// every processor is moot.
pub struct Once<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

const EMPTY: u8 = 0;
const MAKING: u8 = 1;
const MADE: u8 = 2;

// SAFETY: the value is written once, by the one caller that moved the state to
// MAKING, and only read after the state says MADE, which is never undone. It is
// shared by reference across threads, so it must be Sync, and handed over by
// whoever makes it, so Send.
unsafe impl<T: Send + Sync> Sync for Once<T> {}
// SAFETY: moving the cell moves the value with it.
unsafe impl<T: Send> Send for Once<T> {}

impl<T> Once<T> {
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    /// The value, making it with `make` if nobody has.
    pub fn call_once(&self, make: impl FnOnce() -> T) -> &T {
        loop {
            match self.state.compare_exchange(EMPTY, MAKING, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    // SAFETY: winning the exchange makes this the only writer,
                    // and no reader looks until the state is MADE.
                    unsafe { (*self.value.get()).write(make()) };
                    self.state.store(MADE, Ordering::Release);
                    break;
                }
                Err(MADE) => break,
                Err(_) => core::hint::spin_loop(),
            }
        }
        // SAFETY: MADE, so written, and never written again.
        unsafe { (*self.value.get()).assume_init_ref() }
    }

    /// The value, if it has been made.
    pub fn get(&self) -> Option<&T> {
        // SAFETY: as in `call_once`.
        (self.state.load(Ordering::Acquire) == MADE).then(|| unsafe { (*self.value.get()).assume_init_ref() })
    }
}

impl<T> Default for Once<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for Once<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == MADE {
            // SAFETY: made, and this is the last anyone sees of it.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

/// A value made by `make` the first time it is used.
pub struct Lazy<T, F = fn() -> T> {
    once: Once<T>,
    make: F,
}

impl<T, F> Lazy<T, F> {
    pub const fn new(make: F) -> Self {
        Self { once: Once::new(), make }
    }
}

impl<T, F: Fn() -> T> Deref for Lazy<T, F> {
    type Target = T;

    fn deref(&self) -> &T {
        self.once.call_once(&self.make)
    }
}

/// A lock whose waiters sleep.
///
/// [`Mutex`] spins with interrupts masked, which is right for a few
/// instructions and wrong for a disk read: a request that waits on its disk's
/// interrupt cannot be made while holding one, and neither can anything else
/// that parks. This one is held with interrupts as the caller had them, and a
/// caller that finds it taken parks until it is let go.
///
/// A caller that cannot park -- interrupts masked, no scheduler yet, or a panic
/// under way -- spins instead, so it is usable everywhere a [`Mutex`] is, only
/// slower there. Never from an interrupt handler: the holder may be the very
/// thread that was interrupted.
pub struct SleepMutex<T> {
    held: AtomicBool,
    waiters: Mutex<VecDeque<crate::sched::ThreadId>>,
    value: UnsafeCell<T>,
}

// SAFETY: `held` admits one holder at a time, as `Mutex` does.
unsafe impl<T: Send> Sync for SleepMutex<T> {}
// SAFETY: as above.
unsafe impl<T: Send> Send for SleepMutex<T> {}

pub struct SleepMutexGuard<'a, T> {
    lock: &'a SleepMutex<T>,
}

/// Whether the current caller may park.
pub fn can_sleep() -> bool {
    x86_64::instructions::interrupts::are_enabled()
        && crate::sched::is_initialised()
        && crate::sched::current_id().is_some()
        && !crate::crash::is_panicking()
}

impl<T> SleepMutex<T> {
    pub const fn new(value: T) -> Self {
        Self { held: AtomicBool::new(false), waiters: Mutex::new(VecDeque::new()), value: UnsafeCell::new(value) }
    }

    fn take(&self) -> bool {
        self.held.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    pub fn lock(&self) -> SleepMutexGuard<'_, T> {
        loop {
            if self.take() {
                return SleepMutexGuard { lock: self };
            }
            if !can_sleep() {
                core::hint::spin_loop();
                continue;
            }
            let Some(me) = crate::sched::current_id() else {
                continue;
            };
            {
                // Tried again under the waiters' lock, which the holder takes
                // after letting go: either this sees it free, or the holder
                // sees this waiter queued. There is no gap for a release to
                // fall into.
                let mut waiters = self.waiters.lock();
                if self.take() {
                    return SleepMutexGuard { lock: self };
                }
                waiters.push_back(me);
            }
            crate::sched::block_current();
        }
    }
}

impl<T> Deref for SleepMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: holding the guard means `held` is this caller's.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SleepMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above, and `&mut self` rules out a second reference.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SleepMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
        // A woken waiter tries again rather than being handed the lock, so a
        // caller arriving now may take it first. That costs the waiter a turn,
        // never correctness: it queues again.
        let next = self.lock.waiters.lock().pop_front();
        if let Some(next) = next {
            crate::sched::unblock(next);
        }
    }
}
