//! The Ring 3 runtime for Kernel Panda.
//!
//! Thin wrappers over the syscall ABI, an entry-point macro, and a panic
//! handler. Deliberately tiny: everything here runs unprivileged, and the more
//! there is of it the more there is to get wrong in a process the kernel is
//! supposed to be able to distrust.

#![no_std]

use core::arch::asm;

/// Syscall numbers. Must match `kernel/src/syscall.rs`.
pub mod nr {
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

/// Message layout shared with the kernel. Changing either side alone breaks IPC
/// silently.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Message {
    pub tag: u64,
    pub words: [u64; 4],
    /// Written by the kernel; whatever a sender puts here is discarded.
    pub sender: u64,
}

/// Buffer geometry, shared with the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BufferInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bytes_per_pixel: u32,
    pub size: u64,
}

/// Entry is a software interrupt, so RCX and R11 survive -- unlike `syscall`,
/// which clobbers both. Only RAX is modified by the kernel; everything else is
/// restored, which is why nothing else is listed as clobbered.
///
/// `nostack` is accurate: `int` pushes onto the *kernel* stack, not this one.
#[inline(always)]
pub fn syscall(number: u64, a: u64, b: u64, c: u64) -> i64 {
    let result: i64;
    // SAFETY: the kernel's syscall entry saves and restores every general
    // purpose register except RAX, which carries the return value.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            options(nostack),
        );
    }
    result
}

/// As [`syscall`], with a fourth argument.
///
/// R10 rather than RCX, matching the kernel's table. The Linux convention this
/// borrows from uses R10 for the fourth argument because `syscall` clobbers RCX
/// -- entry here is `int 0x80`, which does not, but keeping the register
/// assignment means the ABI does not have to change if the mechanism ever does.
#[inline(always)]
pub fn syscall4(number: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let result: i64;
    // SAFETY: as `syscall`; the kernel restores every register but RAX.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => result,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            options(nostack),
        );
    }
    result
}

pub fn exit(code: u64) -> ! {
    syscall(nr::EXIT, code, 0, 0);
    unreachable!()
}

pub fn write(text: &str) -> i64 {
    syscall(nr::WRITE, 1, text.as_ptr() as u64, text.len() as u64)
}

/// Read up to `buffer.len()` bytes, blocking until at least one arrives.
pub fn read(buffer: &mut [u8]) -> i64 {
    syscall(nr::READ, 0, buffer.as_mut_ptr() as u64, buffer.len() as u64)
}

pub fn yield_now() {
    syscall(nr::YIELD, 0, 0, 0);
}

pub fn thread_id() -> i64 {
    syscall(nr::GET_TID, 0, 0, 0)
}

pub fn ipc_send(endpoint: u64, message: &Message) -> i64 {
    syscall(nr::IPC_SEND, endpoint, message as *const Message as u64, 0)
}

pub fn ipc_receive(endpoint: u64, message: &mut Message) -> i64 {
    syscall(nr::IPC_RECV, endpoint, message as *mut Message as u64, 0)
}

pub fn buffer_create(width: u64, height: u64) -> i64 {
    syscall(nr::BUF_CREATE, width, height, 0)
}

pub fn buffer_map(buffer: u64) -> i64 {
    syscall(nr::BUF_MAP, buffer, 0, 0)
}

pub fn buffer_share(buffer: u64, target: u64) -> i64 {
    syscall(nr::BUF_SHARE, buffer, target, 0)
}

pub fn buffer_info(buffer: u64, info: &mut BufferInfo) -> i64 {
    syscall(nr::BUF_INFO, buffer, info as *mut BufferInfo as u64, 0)
}

pub fn scanout() -> i64 {
    syscall(nr::BUF_SCANOUT, 0, 0, 0)
}

// --- files -------------------------------------------------------------------

/// Read a whole file into `buffer`. Returns the bytes read.
pub fn file_read(path: &str, buffer: &mut [u8]) -> i64 {
    syscall4(
        nr::FILE_READ,
        path.as_ptr() as u64,
        path.len() as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    )
}

/// Replace a file's contents.
pub fn file_write(path: &str, data: &[u8]) -> i64 {
    syscall4(
        nr::FILE_WRITE,
        path.as_ptr() as u64,
        path.len() as u64,
        data.as_ptr() as u64,
        data.len() as u64,
    )
}

pub fn file_create(path: &str) -> i64 {
    syscall(nr::FILE_CREATE, path.as_ptr() as u64, path.len() as u64, 0)
}

pub fn dir_create(path: &str) -> i64 {
    syscall(nr::FILE_CREATE, path.as_ptr() as u64, path.len() as u64, 1)
}

pub fn file_remove(path: &str) -> i64 {
    syscall(nr::FILE_REMOVE, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Size into `size`; returns 1 for a directory, 0 for a file.
pub fn file_stat(path: &str, size: &mut u64) -> i64 {
    syscall(
        nr::FILE_STAT,
        path.as_ptr() as u64,
        path.len() as u64,
        size as *mut u64 as u64,
    )
}

/// Newline-separated names into `buffer`. Returns the bytes written.
pub fn dir_list(path: &str, buffer: &mut [u8]) -> i64 {
    syscall4(
        nr::FILE_LIST,
        path.as_ptr() as u64,
        path.len() as u64,
        buffer.as_mut_ptr() as u64,
        buffer.len() as u64,
    )
}

/// Write a decimal number to the console.
///
/// Formatting belongs in user space, not behind a syscall -- the kernel's job is
/// to move bytes, not to know what a number looks like.
pub fn write_number(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut index = digits.len();

    if value == 0 {
        write("0");
        return;
    }
    while value > 0 {
        index -= 1;
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    // SAFETY: every byte written above is an ASCII digit.
    write(unsafe { core::str::from_utf8_unchecked(&digits[index..]) });
}

/// Define a program's entry point.
///
/// The kernel enters at the ELF entry with the start-up argument in R15, so the
/// first thing that must happen is moving it somewhere the ABI can see, before
/// the compiler emits anything that might clobber it. A naked function is the
/// only way to be certain of that.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "C" fn _start() -> ! {
            ::core::arch::naked_asm!(
                "mov rdi, r15",
                "call {main}",
                // Returning from main is the same as exiting cleanly.
                "mov rax, 0",
                "xor rdi, rdi",
                "int 0x80",
                "ud2",
                main = sym $main,
            )
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    write("  [ring 3] panic: ");
    if let Some(message) = info.message().as_str() {
        write(message);
    } else {
        write("(unprintable)");
    }
    write("\n");
    exit(1)
}
