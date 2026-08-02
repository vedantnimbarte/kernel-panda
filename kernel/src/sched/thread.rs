//! Thread control blocks.

use alloc::boxed::Box;
use alloc::vec;

use super::context;

/// 32 KiB. Generous for a kernel thread that does not recurse, and small enough
/// that the 1 MiB heap can hold a useful number of them. Kernel stacks will move
/// off the heap and onto guard-paged mappings of their own once there is a
/// reason to care about stack overflow per thread.
pub const DEFAULT_STACK_SIZE: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Runnable, waiting for the CPU.
    Ready,
    /// Currently on the CPU.
    Running,
    /// Waiting for something -- today, a message on an IPC endpoint. Not in the
    /// ready queue, and only `sched::unblock` puts it back.
    Blocked,
    /// Returned from its entry point. Its stack is freed by the next
    /// `schedule()` that runs after it has been switched away from.
    Finished,
}

pub struct Thread {
    pub id: ThreadId,
    pub name: &'static str,
    pub state: State,

    /// Where this thread's registers are parked while it is off the CPU.
    ///
    /// Meaningless while the thread is `Running` -- the values are live in the
    /// CPU then, and this field is only written by `context_switch` on the way
    /// out.
    pub stack_pointer: u64,

    /// What the thread runs. Read once by the trampoline.
    pub entry: Option<fn()>,

    /// This thread's own page tables, if it has any.
    ///
    /// `None` means it runs in the kernel's space, which is every thread that
    /// has not loaded a user program.
    pub address_space: Option<crate::memory::paging::AddressSpace>,

    /// Top of this thread's kernel stack, or 0 for the boot thread.
    ///
    /// Loaded into `TSS.privilege_stack_table[0]` whenever this thread is
    /// scheduled, because that is the stack the CPU switches to if it takes an
    /// interrupt while the thread is running in Ring 3. Pointing it at the wrong
    /// thread's stack corrupts that thread silently.
    pub kernel_stack_top: u64,

    /// The owned kernel stack. `None` for the boot thread, which runs on the
    /// stack the bootloader set up and does not own it.
    ///
    /// Never read directly -- the CPU reaches it through `stack_pointer`. It is
    /// held here so that dropping the thread frees the stack.
    #[allow(dead_code)]
    stack: Option<Box<[u8]>>,
}

impl Thread {
    /// Create a thread that has never run, with a stack fabricated so that the
    /// first switch into it lands on `trampoline`.
    pub fn new(
        id: ThreadId,
        name: &'static str,
        entry: fn(),
        stack_size: usize,
        trampoline: unsafe extern "C" fn() -> !,
    ) -> Self {
        let mut stack = vec![0u8; stack_size].into_boxed_slice();

        // Round down rather than up: rounding up would put the top past the end
        // of the allocation.
        let top = (stack.as_mut_ptr() as u64 + stack_size as u64) & !0xF;

        // SAFETY: `top` is 16-byte aligned and sits at (or just below) the end of
        // an allocation of `stack_size` bytes, which is far larger than the
        // fabricated frame. The stack is not yet reachable from anywhere else.
        let stack_pointer = unsafe { context::init_stack(top, trampoline) };

        Self {
            id,
            name,
            state: State::Ready,
            stack_pointer,
            entry: Some(entry),
            address_space: None,
            kernel_stack_top: top,
            stack: Some(stack),
        }
    }

    /// Wrap the context that is already executing.
    ///
    /// Used once, for the boot thread. It has no fabricated frame and no owned
    /// stack: `stack_pointer` stays meaningless until the first time this thread
    /// is switched away from, which is what fills it in.
    pub fn adopt_running(id: ThreadId, name: &'static str) -> Self {
        Self {
            id,
            name,
            state: State::Running,
            stack_pointer: 0,
            entry: None,
            address_space: None,
            // The boot thread never drops to Ring 3, so no Ring 0 stack has to
            // be published for it.
            kernel_stack_top: 0,
            stack: None,
        }
    }
}
