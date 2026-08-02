//! x86_64 platform support.

use x86_64::instructions::hlt;

/// Park the CPU forever, waking only to service interrupts.
///
/// `hlt` rather than a spin loop: a bare `loop {}` pins a core at 100% and makes
/// the host fans audible during every debugging session.
pub fn halt_loop() -> ! {
    loop {
        hlt();
    }
}
