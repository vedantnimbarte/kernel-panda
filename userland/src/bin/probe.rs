//! Test programs, selected by the argument the kernel passes in.
//!
//! One binary rather than four, because each costs an entry in the kernel image
//! and these differ by a handful of instructions. The kernel picks a mode; the
//! program does exactly that and exits.

#![no_std]
#![no_main]

use panda_user as user;

user::entry!(main);

/// Modes. Must match `kernel/src/userspace.rs`.
pub const MODE_DEMO: u64 = 0;
pub const MODE_TRESPASS: u64 = 1;
pub const MODE_IPC: u64 = 2;
pub const MODE_PEEK: u64 = 3;

/// Parameters for the modes that need more than a mode number.
#[repr(C)]
struct Parameters {
    mode: u64,
    /// Address to read, for TRESPASS and PEEK.
    address: u64,
    /// Endpoint to send on, for IPC.
    endpoint: u64,
}

extern "C" fn main(parameters: u64) {
    // SAFETY: the kernel fills this page in before entry.
    let parameters = unsafe { &*(parameters as *const Parameters) };

    match parameters.mode {
        MODE_DEMO => {
            user::write("  [ring 3] hello from user space\n");
            user::yield_now();
            user::write("  [ring 3] still running after a yield\n");
        }

        // Both of these must fault. Reaching the write means the boundary they
        // are testing did not hold, so they say so loudly rather than exiting
        // quietly and letting a test pass for the wrong reason.
        MODE_TRESPASS => {
            // SAFETY: deliberately not safe. The address is kernel memory and
            // this must fault; the kernel kills the thread before the read
            // completes.
            let value = unsafe { core::ptr::read_volatile(parameters.address as *const u64) };
            user::write("  [ring 3] READ KERNEL MEMORY -- boundary broken: ");
            user::write_number(value);
            user::write("\n");
        }
        MODE_PEEK => {
            // SAFETY: as above, for an address belonging to another process.
            let value = unsafe { core::ptr::read_volatile(parameters.address as *const u64) };
            user::write("  [ring 3] READ ANOTHER ADDRESS SPACE -- isolation broken: ");
            user::write_number(value);
            user::write("\n");
        }

        MODE_IPC => {
            let message = user::Message {
                tag: 0xCAFE,
                words: [0xBEEF, 0, 0, 0],
                // A lie, so the kernel can be seen to overwrite it.
                sender: 999,
            };
            let result = user::ipc_send(parameters.endpoint, &message);
            user::exit(result as u64);
        }

        _ => {
            user::write("  [ring 3] unknown probe mode\n");
        }
    }
}
