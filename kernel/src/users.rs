//! Who a process is.
//!
//! Capabilities decide what a process can reach; this decides who it is, so that
//! things a process leaves behind -- files, above all -- can say who made them
//! and who else may touch them.
//!
//! A user is a number. A thread starts as the user of whoever spawned it, and
//! only kernel code can say otherwise -- which in practice means whoever starts
//! a program decides who it runs as. There is no system call that changes a
//! thread's user, so a process cannot promote itself, nor impersonate another.
//!
//! There is no superuser. User 0 is the system's own user: it owns what the
//! system creates, and it is held to the same permission bits as everyone else.
//! What the system can do beyond that comes from capabilities it was given, not
//! from a number that bypasses every check.

use alloc::collections::BTreeMap;

use crate::sched::{self, ThreadId};
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::SyscallResult;

pub type UserId = u32;

/// The system's own user. Owner of what the boot creates; not privileged.
pub const SYSTEM: UserId = 0;

/// Users of threads that are not the system's. Absent means `SYSTEM`, which is
/// every thread the kernel starts on its own account.
static USERS: Mutex<BTreeMap<usize, UserId>> = Mutex::new(BTreeMap::new());

/// The user a thread runs as.
pub fn of(thread: ThreadId) -> UserId {
    without_interrupts(|| USERS.lock().get(&thread.0).copied().unwrap_or(SYSTEM))
}

/// Run `thread` as `user`. Kernel-facing only; see the module notes. A thread
/// being started as someone should be started with `sched::spawn_as`, which
/// leaves no moment in which it runs as its spawner.
pub fn assign(thread: ThreadId, user: UserId) {
    without_interrupts(|| {
        let mut users = USERS.lock();
        if user == SYSTEM {
            users.remove(&thread.0);
        } else {
            users.insert(thread.0, user);
        }
    });
}

/// A new thread takes its spawner's user.
pub fn inherit(parent: Option<ThreadId>, child: ThreadId) {
    if let Some(parent) = parent {
        assign(child, of(parent));
    }
}

/// Forget a thread when it exits.
pub fn release_thread(thread: ThreadId) {
    without_interrupts(|| USERS.lock().remove(&thread.0));
}

/// The caller's user.
pub fn sys_current() -> SyscallResult {
    Ok(sched::current_id().map_or(SYSTEM, of) as i64)
}
