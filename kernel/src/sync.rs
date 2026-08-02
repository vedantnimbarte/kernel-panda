//! Synchronisation primitives.
//!
//! The rest of the kernel locks through this module instead of naming `spin`
//! directly. When the third-party spinlock is eventually replaced with an
//! in-house primitive -- one that is priority-correct for the Phase 3 scheduler
//! -- only this file changes.

pub use spin::{Lazy, Mutex, MutexGuard, Once};

pub use x86_64::instructions::interrupts::without_interrupts;

/// Whether interrupts are currently enabled on this CPU.
pub fn interrupts_enabled() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}
