//! Synchronisation primitives.
//!
//! The rest of the kernel locks through this module instead of naming `spin`
//! directly. When the third-party spinlock is eventually replaced with an
//! in-house primitive -- one that is priority-correct for the Phase 3 scheduler
//! -- only this file changes.

use core::ops::{Deref, DerefMut};

pub use spin::{Lazy, Mutex, MutexGuard, Once};

pub use x86_64::instructions::interrupts::without_interrupts;

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
