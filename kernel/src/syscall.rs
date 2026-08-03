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
    pub const FILE_READ: u64 = 14;
    pub const FILE_WRITE: u64 = 15;
    pub const FILE_CREATE: u64 = 16;
    pub const FILE_REMOVE: u64 = 17;
    pub const FILE_STAT: u64 = 18;
    pub const FILE_LIST: u64 = 19;
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
    /// No filesystem is mounted.
    NoFileSystem = -9,
    /// No such file or directory.
    NotFound = -10,
    /// Something of that name already exists.
    AlreadyExists = -11,
    /// The filesystem is out of space.
    NoSpace = -12,
    /// A directory was needed and a file was given, or the reverse.
    WrongType = -13,
    /// A directory that still holds entries cannot be removed.
    NotEmpty = -14,
}

impl From<crate::fs::FsError> for Error {
    fn from(error: crate::fs::FsError) -> Self {
        use crate::fs::FsError;
        match error {
            FsError::NotFound => Error::NotFound,
            FsError::Exists => Error::AlreadyExists,
            FsError::Full | FsError::TooLarge => Error::NoSpace,
            FsError::WrongType => Error::WrongType,
            FsError::NotEmpty => Error::NotEmpty,
            FsError::BadName => Error::InvalidArgument,
            // A device fault or a structure that does not make sense are not
            // things a program can act on differently, and reporting the
            // distinction would leak what the disk is doing to anyone who asks.
            FsError::Device(_)
            | FsError::Corrupt
            | FsError::NotFormatted
            | FsError::WrongVersion => Error::NoFileSystem,
        }
    }
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

/// System calls dispatched, and how many of those the timer could have
/// interrupted.
///
/// The two should be equal. They were not while the gate was an interrupt gate:
/// `IF` was cleared on entry, so a call ran to completion no matter how long it
/// took and the thread's quantum meant nothing. Counting both makes a
/// regression -- someone reaching for an interrupt gate again, or a handler
/// leaving interrupts off -- visible instead of merely slow.
static SYSCALLS: AtomicU64 = AtomicU64::new(0);
static PREEMPTIBLE_SYSCALLS: AtomicU64 = AtomicU64::new(0);

pub fn syscall_count() -> u64 {
    SYSCALLS.load(Ordering::Relaxed)
}

pub fn preemptible_syscall_count() -> u64 {
    PREEMPTIBLE_SYSCALLS.load(Ordering::Relaxed)
}

pub fn dispatch(frame: &mut SyscallFrame) {
    SYSCALLS.fetch_add(1, Ordering::Relaxed);
    if crate::sync::interrupts_enabled() {
        PREEMPTIBLE_SYSCALLS.fetch_add(1, Ordering::Relaxed);
    }

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
        numbers::FILE_READ => sys_file_read(frame.rdi, frame.rsi, frame.rdx, frame.r10),
        numbers::FILE_WRITE => sys_file_write(frame.rdi, frame.rsi, frame.rdx, frame.r10),
        numbers::FILE_CREATE => sys_file_create(frame.rdi, frame.rsi, frame.rdx),
        numbers::FILE_REMOVE => sys_file_remove(frame.rdi, frame.rsi),
        numbers::FILE_STAT => sys_file_stat(frame.rdi, frame.rsi, frame.rdx),
        numbers::FILE_LIST => sys_file_list(frame.rdi, frame.rsi, frame.rdx, frame.r10),
        _ => Err(Error::UnknownCall),
    };

    frame.rax = match result {
        Ok(value) => value as u64,
        Err(error) => (error as i64) as u64,
    };
}

/// Longest path a syscall may name.
///
/// Bounded so a caller cannot make the kernel copy an unbounded string out of
/// user memory, and so the stack buffer below is a known size.
const MAX_PATH: u64 = 255;

/// Largest single file transfer. Bounds how long one call holds the filesystem
/// lock, which is held across disk I/O.
const MAX_FILE_IO: u64 = 64 * 1024;

/// Copy a path out of user memory and check it is usable.
///
/// Everything here is attacker-controlled: the pointer, the length, and the
/// bytes. The pointer is validated against the caller's own mappings, the
/// length is capped, and the bytes have to be UTF-8 — a path that is not is
/// rejected rather than being lossily converted into one that names a different
/// file.
fn read_user_path(pointer: u64, length: u64) -> Result<alloc::string::String, Error> {
    if length == 0 || length > MAX_PATH {
        return Err(Error::InvalidArgument);
    }
    if !userspace::validate_user_buffer(pointer, length, false) {
        return Err(Error::BadPointer);
    }

    let mut bytes = [0u8; MAX_PATH as usize];
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: the range was validated as present and user-readable for its
        // whole extent, and the guard lets Ring 0 reach it. `length` is capped
        // at the size of the destination.
        unsafe {
            core::ptr::copy_nonoverlapping(
                pointer as *const u8,
                bytes.as_mut_ptr(),
                length as usize,
            );
        }
    });

    let text = core::str::from_utf8(&bytes[..length as usize])
        .map_err(|_| Error::InvalidArgument)?;
    Ok(alloc::string::String::from(text))
}

fn filesystem() -> Result<alloc::sync::Arc<crate::fs::FileSystem>, Error> {
    crate::fs::root().ok_or(Error::NoFileSystem)
}

/// Read a whole file into a user buffer. Returns the bytes written.
fn sys_file_read(path: u64, path_len: u64, buffer: u64, capacity: u64) -> SyscallResult {
    if capacity > MAX_FILE_IO {
        return Err(Error::InvalidArgument);
    }
    let path = read_user_path(path, path_len)?;
    if !userspace::validate_user_buffer(buffer, capacity, true) {
        return Err(Error::BadPointer);
    }

    let fs = filesystem()?;
    let contents = fs.read_file(&path)?;

    // The file is read into kernel memory first and only then copied out, so
    // the disk read does not happen with the SMAP window open.
    let take = (contents.len() as u64).min(capacity) as usize;
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: validated above as present, user-accessible and writable for
        // `capacity` bytes, and `take` never exceeds it.
        unsafe {
            core::ptr::copy_nonoverlapping(contents.as_ptr(), buffer as *mut u8, take);
        }
    });

    Ok(take as i64)
}

/// Replace a file's contents.
fn sys_file_write(path: u64, path_len: u64, buffer: u64, length: u64) -> SyscallResult {
    if length > MAX_FILE_IO {
        return Err(Error::InvalidArgument);
    }
    let path = read_user_path(path, path_len)?;
    if !userspace::validate_user_buffer(buffer, length, false) {
        return Err(Error::BadPointer);
    }

    let mut data = alloc::vec![0u8; length as usize];
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: validated as present and user-readable for `length` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(buffer as *const u8, data.as_mut_ptr(), length as usize);
        }
    });

    filesystem()?.write_file(&path, &data)?;
    Ok(length as i64)
}

/// Create a file, or a directory when `directory` is non-zero.
fn sys_file_create(path: u64, path_len: u64, directory: u64) -> SyscallResult {
    let path = read_user_path(path, path_len)?;
    let kind = if directory != 0 {
        crate::fs::NodeKind::Directory
    } else {
        crate::fs::NodeKind::File
    };
    filesystem()?.create(&path, kind)?;
    Ok(0)
}

fn sys_file_remove(path: u64, path_len: u64) -> SyscallResult {
    let path = read_user_path(path, path_len)?;
    filesystem()?.remove(&path)?;
    Ok(0)
}

/// Write a file's size into `out`, returning 1 for a directory and 0 for a file.
fn sys_file_stat(path: u64, path_len: u64, out: u64) -> SyscallResult {
    let path = read_user_path(path, path_len)?;
    if !userspace::validate_user_buffer(out, 8, true) {
        return Err(Error::BadPointer);
    }

    let (kind, size) = filesystem()?.stat(&path)?;
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: eight bytes validated as present, user-accessible and
        // writable. Unaligned because nothing obliges user space to align it.
        unsafe { core::ptr::write_unaligned(out as *mut u64, size) };
    });

    Ok(if kind == crate::fs::NodeKind::Directory { 1 } else { 0 })
}

/// Write a directory's names into a user buffer, newline separated.
///
/// Returns the bytes written. A caller whose buffer is too small gets as much
/// as fits rather than an error, because the alternative is asking it to guess
/// a size before it knows what is there.
fn sys_file_list(path: u64, path_len: u64, buffer: u64, capacity: u64) -> SyscallResult {
    if capacity > MAX_FILE_IO {
        return Err(Error::InvalidArgument);
    }
    let path = read_user_path(path, path_len)?;
    if !userspace::validate_user_buffer(buffer, capacity, true) {
        return Err(Error::BadPointer);
    }

    let names = filesystem()?.list(&path)?;
    let mut out = alloc::vec::Vec::new();
    for name in names {
        out.extend_from_slice(name.as_bytes());
        out.push(b'\n');
    }

    let take = (out.len() as u64).min(capacity) as usize;
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: validated as writable for `capacity` bytes; `take` fits.
        unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), buffer as *mut u8, take) };
    });

    Ok(take as i64)
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

    // The whole access, validation through print, happens inside one SMAP
    // window. Printing from inside it is deliberate: the guard masks interrupts,
    // so nothing else runs on this processor while AC is set, and copying the
    // buffer out first would cost `MAX_WRITE` bytes of a 32 KiB kernel stack.
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: `validate_user_buffer` established that every page across
        // `length` bytes from `pointer` is present and user-readable, so this
        // slice refers to live memory for its whole extent, and the guard makes
        // it reachable from Ring 0.
        let bytes = unsafe { core::slice::from_raw_parts(pointer as *const u8, length as usize) };

        // Reject invalid UTF-8 rather than printing replacement characters: a
        // user program sending garbage should learn that it did.
        let text = core::str::from_utf8(bytes).map_err(|_| Error::InvalidArgument)?;
        crate::print!("{text}");

        USER_BYTES_WRITTEN.fetch_add(length, Ordering::Relaxed);
        Ok(length as i64)
    })
}
