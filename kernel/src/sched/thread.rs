//! Thread control blocks.

use super::context;
use crate::memory::kstack::{self, KernelStack};

/// Kept for callers that still name it; the real size is fixed by the stack
/// region's slot layout.
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

    /// Some processor is executing on this thread's stack.
    ///
    /// True from the moment a CPU commits to switching *to* the thread until the
    /// switch *away* from it has actually completed -- which is later than the
    /// point where it stops being that CPU's `current`, because the scheduler
    /// lock is released before `context_switch` runs.
    ///
    /// While it is set the thread must not be given to another processor and
    /// must not be freed: its saved `stack_pointer` is stale and its stack is
    /// live. Two things would otherwise get this wrong -- `unblock`, which can
    /// arrive from another core at any moment, and `reap`.
    pub on_cpu: bool,

    /// The owned kernel stack. `None` for the boot thread, which runs on the
    /// stack the bootloader set up and does not own it.
    ///
    /// Never read directly -- the CPU reaches it through `stack_pointer`. It is
    /// held here so that dropping the thread unmaps the stack and returns both
    /// its frames and its guard page's address space.
    stack: Option<KernelStack>,
}

impl Thread {
    /// The unmapped page below this thread's stack, if it owns one.
    pub fn guard_page(&self) -> Option<u64> {
        self.stack.as_ref().map(|stack| stack.guard_page())
    }

    /// Lowest mapped address of this thread's stack, if it owns one.
    pub fn stack_bottom(&self) -> Option<u64> {
        self.stack.as_ref().map(|stack| stack.bottom())
    }

    /// Create a thread that has never run, with a stack fabricated so that the
    /// first switch into it lands on `trampoline`.
    pub fn new(
        id: ThreadId,
        name: &'static str,
        entry: fn(),
        _stack_size: usize,
        trampoline: unsafe extern "C" fn() -> !,
    ) -> Self {
        let stack = kstack::allocate().expect("out of kernel stack address space");

        // Page aligned already, so also 16-byte aligned.
        let top = stack.top();

        // SAFETY: `top` is 16-byte aligned and sits at the top of a freshly
        // mapped stack far larger than the fabricated frame. Nothing else
        // references it yet.
        let stack_pointer = unsafe { context::init_stack(top, trampoline) };

        Self {
            id,
            name,
            state: State::Ready,
            stack_pointer,
            entry: Some(entry),
            address_space: None,
            kernel_stack_top: top,
            on_cpu: false,
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
            // It is running: that is the whole point of adopting it.
            on_cpu: true,
            stack: None,
        }
    }
}
