//! The QEMU `isa-debug-exit` device.
//!
//! This is how a test kernel reports its verdict to the host: QEMU turns a write
//! of `v` to the device port into process exit code `(v << 1) | 1`, which
//! `xtask runner` inspects.

use x86_64::instructions::port::PortWriteOnly;

/// I/O port the device is bound to. Must match the `iobase=` value xtask passes
/// to QEMU.
const DEBUG_EXIT_PORT: u16 = 0xf4;

/// Values chosen so the resulting QEMU exit codes (33 and 35) cannot be confused
/// with the codes QEMU produces on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ExitCode {
    Success = 0x10,
    Failed = 0x11,
}

/// Terminate the virtual machine.
pub fn exit(code: ExitCode) -> ! {
    // SAFETY: 0xf4 is the isa-debug-exit device wired up on the QEMU command
    // line by xtask; writing to it tears the VM down immediately, so nothing
    // after this executes. On real hardware the port is unclaimed and the write
    // is discarded, in which case we fall through to the halt loop below.
    unsafe {
        PortWriteOnly::new(DEBUG_EXIT_PORT).write(code as u32);
    }
    super::halt_loop()
}
