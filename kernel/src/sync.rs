//! Synchronisation primitives.
//!
//! The rest of the kernel locks through this module instead of naming `spin`
//! directly. When the third-party spinlock is eventually replaced with an
//! in-house primitive -- one that is interrupt-aware and priority-correct for
//! the Phase 3 scheduler -- only this file changes.

pub use spin::{Lazy, Mutex, MutexGuard, Once};
