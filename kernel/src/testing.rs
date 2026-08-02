//! Support for the custom test framework.
//!
//! There is no `std`, so there is no libtest. Each file under `tests/` compiles
//! into a complete, standalone kernel that boots under QEMU, runs its cases, and
//! reports the verdict through the `isa-debug-exit` device. `xtask runner` turns
//! that into a process exit code cargo understands.

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::x86_64::qemu::{self, ExitCode};
use crate::sched::ThreadId;
use crate::{serial_print, serial_println};

/// The thread that has declared it is about to fault on purpose, plus one so
/// that zero can mean "nobody".
///
/// A kernel-mode page fault normally panics, which is right: it means the kernel
/// dereferenced something it had no business dereferencing. But some protections
/// can only be demonstrated by provoking exactly that, and a protection nobody
/// has watched fail is a protection nobody has tested. Arming this turns the
/// fault into a thread death instead, the same treatment a Ring 3 fault gets.
///
/// Deliberately a single slot rather than a per-CPU array: it is only ever armed
/// by one thread at a time in a test, and one slot makes a stray arm impossible
/// to miss.
static EXPECTING_FAULT: AtomicUsize = AtomicUsize::new(0);

/// Whether the armed fault actually happened.
static FAULT_OBSERVED: AtomicUsize = AtomicUsize::new(0);

/// Declare that this thread is about to touch memory it should not be able to.
///
/// The next kernel-mode page fault on this thread kills it rather than panicking
/// the system. Nothing disarms it except the fault, so a thread that arms this
/// and then does *not* fault leaves it set -- which is what makes the absence of
/// the fault visible to the test.
pub fn expect_page_fault(thread: ThreadId) {
    FAULT_OBSERVED.store(0, Ordering::Release);
    EXPECTING_FAULT.store(thread.0 + 1, Ordering::Release);
}

/// Whether the fault armed by [`expect_page_fault`] has been taken.
pub fn page_fault_observed() -> bool {
    FAULT_OBSERVED.load(Ordering::Acquire) != 0
}

/// Consulted by the page-fault handler. Consumes the arming, so a second fault
/// on the same thread panics normally.
pub(crate) fn take_expected_fault(thread: Option<ThreadId>) -> bool {
    let Some(thread) = thread else {
        return false;
    };
    // Compare-and-clear rather than an unconditional swap: a fault on some other
    // thread must not silently disarm the one the test is waiting for.
    if EXPECTING_FAULT
        .compare_exchange(thread.0 + 1, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    FAULT_OBSERVED.store(1, Ordering::Release);
    true
}

pub trait Testable {
    fn run(&self);
}

impl<T: Fn()> Testable for T {
    fn run(&self) {
        // `type_name` gives the fully-qualified function path, which is the most
        // useful label available without a heap or a test-name registry.
        serial_print!("{} ... ", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

/// Entry point named by `#![test_runner(...)]` in each test kernel.
pub fn runner(tests: &[&dyn Testable]) {
    serial_println!("running {} test(s)", tests.len());
    for test in tests {
        test.run();
    }
    qemu::exit(ExitCode::Success);
}

/// Panic handler for test kernels: report and fail the run immediately, rather
/// than halting and letting the host time out.
pub fn panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[FAILED]");
    serial_println!("{info}");
    qemu::exit(ExitCode::Failed)
}
