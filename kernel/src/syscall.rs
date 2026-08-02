//! System call dispatch.
//!
//! The kernel's entire Ring 3 surface. Everything a user thread can ask for goes
//! through this table, which is exactly why it stays small: the PRD's threat
//! model treats every argument here as attacker-controlled, and each one has to
//! be validated before it is believed.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::syscall::SyscallFrame;
use crate::{sched, userspace};

/// Call numbers, passed in RAX.
pub mod numbers {
    pub const EXIT: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const YIELD: u64 = 2;
    pub const GET_TID: u64 = 3;
    pub const IPC_CREATE: u64 = 4;
    pub const IPC_SEND: u64 = 5;
    pub const IPC_RECV: u64 = 6;
    pub const IPC_GRANT: u64 = 7;
    pub const BUF_CREATE: u64 = 8;
    pub const BUF_MAP: u64 = 9;
    pub const BUF_SHARE: u64 = 10;
    pub const BUF_INFO: u64 = 11;
    pub const BUF_SCANOUT: u64 = 12;
    pub const READ: u64 = 13;
}

/// Returned in RAX as a negative value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Error {
    UnknownCall = -1,
    /// The pointer was outside user space, unmapped, or lacked the permission
    /// the access needed.
    BadPointer = -2,
    /// The caller holds no capability for that endpoint, or not the right one.
    NoCapability = -3,
    /// The endpoint's queue is full.
    QueueFull = -4,
    NoSuchEndpoint = -5,
    InvalidArgument = -6,
    /// No physical memory, or no room left in the caller's address space.
    OutOfMemory = -7,
    /// The caller is already holding as much of this resource as it may.
    ///
    /// Distinct from `OutOfMemory` on purpose: one says the machine is full, the
    /// other says this process has had its share. A caller that cannot tell them
    /// apart cannot decide whether retrying later is worth anything.
    QuotaExceeded = -8,
}

pub type SyscallResult = Result<i64, Error>;

/// Largest buffer a single `write` may present. Bounds how long the kernel can
/// be made to spend inside one call.
const MAX_WRITE: u64 = 4096;

/// Bytes successfully written by user space since boot.
///
/// Diagnostic, and the only way a test running in Ring 0 can observe that a
/// Ring 3 program actually reached the kernel.
static USER_BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

pub fn user_bytes_written() -> u64 {
    USER_BYTES_WRITTEN.load(Ordering::Relaxed)
}

pub fn dispatch(frame: &mut SyscallFrame) {
    // `exit` is the one call that does not come back, so it cannot go through
    // the result path below.
    if frame.rax == numbers::EXIT {
        sched::exit_current();
    }

    let result = match frame.rax {
        numbers::WRITE => sys_write(frame.rdi, frame.rsi, frame.rdx),
        numbers::YIELD => {
            sched::yield_now();
            Ok(0)
        }
        numbers::GET_TID => Ok(sched::current_id().map_or(-1, |id| id.0 as i64)),
        numbers::IPC_CREATE => crate::ipc::sys_create(frame.rdi),
        numbers::IPC_SEND => crate::ipc::sys_send(frame.rdi, frame.rsi),
        numbers::IPC_RECV => crate::ipc::sys_recv(frame.rdi, frame.rsi),
        numbers::IPC_GRANT => crate::ipc::sys_grant(frame.rdi, frame.rsi, frame.rdx),
        numbers::BUF_CREATE => crate::gbm::sys_create(frame.rdi, frame.rsi),
        numbers::BUF_MAP => crate::gbm::sys_map(frame.rdi),
        numbers::BUF_SHARE => crate::gbm::sys_share(frame.rdi, frame.rsi),
        numbers::BUF_INFO => crate::gbm::sys_info(frame.rdi, frame.rsi),
        numbers::BUF_SCANOUT => crate::gbm::sys_scanout(),
        numbers::READ => crate::console::input::sys_read(frame.rdi, frame.rsi, frame.rdx),
        _ => Err(Error::UnknownCall),
    };

    frame.rax = match result {
        Ok(value) => value as u64,
        Err(error) => (error as i64) as u64,
    };
}

fn sys_write(descriptor: u64, pointer: u64, length: u64) -> SyscallResult {
    // Only the console exists so far.
    if descriptor != 1 {
        return Err(Error::InvalidArgument);
    }
    if length > MAX_WRITE {
        return Err(Error::InvalidArgument);
    }
    if !userspace::validate_user_buffer(pointer, length, false) {
        return Err(Error::BadPointer);
    }

    // SAFETY: `validate_user_buffer` established that every page across
    // `length` bytes from `pointer` is present and user-readable, so this slice
    // refers to live memory for its whole extent.
    let bytes = unsafe { core::slice::from_raw_parts(pointer as *const u8, length as usize) };

    // Reject invalid UTF-8 rather than printing replacement characters: a user
    // program sending garbage should learn that it did.
    let text = core::str::from_utf8(bytes).map_err(|_| Error::InvalidArgument)?;
    crate::print!("{text}");

    USER_BYTES_WRITTEN.fetch_add(length, Ordering::Relaxed);
    Ok(length as i64)
}
