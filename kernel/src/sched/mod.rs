//! Preemptive round-robin thread scheduler.
//!
//! Threads are kernel threads: they share one address space and differ only in
//! their stacks and saved registers. User-space threads, and the page-table
//! switching they need, arrive with Ring 3 in Milestone 3.
//!
//! Preemption is driven by the APIC timer. The handler decrements the current
//! thread's slice and, when it runs out, calls [`schedule`] -- so the switch
//! happens *inside* the interrupt handler, on the interrupted thread's stack.
//! That is why it works: each thread's stack carries its own interrupt frame, so
//! when a thread is resumed it returns out of its own handler and `iret`s back
//! to whatever it was doing.
//!
//! Everything here runs with interrupts disabled. On a single core that makes
//! the whole scheduler a critical section, which is what allows the lock to be
//! released before the context switch -- holding a spinlock across a switch
//! would leave it locked by a thread that is no longer running.

pub mod context;
pub mod thread;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::sync::{without_interrupts, Mutex};

pub use thread::{State, Thread, ThreadId, DEFAULT_STACK_SIZE};

/// Ticks a thread gets before it is preempted. At the timer's 100 Hz that makes
/// a 10 ms quantum -- short enough to feel responsive, long enough that the
/// switch cost stays in the noise.
const TIME_SLICE_TICKS: u32 = 1;

const BOOT_THREAD: ThreadId = ThreadId(0);
const IDLE_THREAD: ThreadId = ThreadId(1);

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

struct Scheduler {
    /// Indexed by `ThreadId`. A `None` slot is a thread that has finished and
    /// been reaped; ids are never reused, so a stale id reads as `None` rather
    /// than silently addressing someone else.
    threads: Vec<Option<Box<Thread>>>,
    /// Runnable threads, oldest first. The idle thread is deliberately never in
    /// here -- it is the fallback, not a participant.
    ready: VecDeque<ThreadId>,
    current: ThreadId,
    slice_remaining: u32,
}

impl Scheduler {
    fn thread(&self, id: ThreadId) -> &Thread {
        self.threads[id.0]
            .as_deref()
            .expect("scheduler referenced a reaped thread")
    }

    fn thread_mut(&mut self, id: ThreadId) -> &mut Thread {
        self.threads[id.0]
            .as_deref_mut()
            .expect("scheduler referenced a reaped thread")
    }

    fn thread_opt(&self, id: ThreadId) -> Option<&Thread> {
        self.threads.get(id.0).and_then(|slot| slot.as_deref())
    }

    /// Free threads that have run to completion.
    ///
    /// Never the current thread: it is still executing on the very stack that
    /// dropping it would free. By the time a finished thread is no longer
    /// current, the switch away from it has completed and its stack is idle.
    fn reap(&mut self) {
        let current = self.current;
        for slot in self.threads.iter_mut() {
            let finished = matches!(
                slot.as_deref(),
                Some(t) if t.state == State::Finished && t.id != current
            );
            if finished {
                *slot = None;
            }
        }
    }

    /// Take the next genuinely runnable thread off the queue, discarding
    /// entries for threads that have since finished or been reaped.
    fn pop_runnable(&mut self) -> Option<ThreadId> {
        while let Some(id) = self.ready.pop_front() {
            if matches!(self.thread_opt(id), Some(t) if t.state == State::Ready) {
                return Some(id);
            }
        }
        None
    }

    /// Decide who runs next, and return what the switch needs: where to save the
    /// outgoing stack pointer, the incoming one to load, and the incoming
    /// thread's Ring 0 stack for the TSS. `None` means stay where we are.
    fn prepare_switch(&mut self) -> Option<(*mut u64, u64, u64)> {
        let current = self.current;

        let next = match self.pop_runnable() {
            Some(id) => id,
            None => {
                // Nobody else wants the CPU. Keep running rather than bouncing
                // to idle and straight back, which would burn half the machine
                // on context switches.
                if current != IDLE_THREAD && self.thread(current).state == State::Running {
                    self.slice_remaining = TIME_SLICE_TICKS;
                    return None;
                }
                IDLE_THREAD
            }
        };

        if next == current {
            self.slice_remaining = TIME_SLICE_TICKS;
            return None;
        }

        // Retire the outgoing thread. A thread that finished or blocked keeps
        // that state; only a still-running one goes back in the queue.
        let outgoing = self.thread_mut(current);
        if outgoing.state == State::Running {
            outgoing.state = State::Ready;
        }
        if current != IDLE_THREAD && self.thread(current).state == State::Ready {
            self.ready.push_back(current);
        }

        let save_to: *mut u64 = &mut self.thread_mut(current).stack_pointer;

        let incoming = self.thread_mut(next);
        incoming.state = State::Running;
        let load_from = incoming.stack_pointer;
        let kernel_stack_top = incoming.kernel_stack_top;

        self.current = next;
        self.slice_remaining = TIME_SLICE_TICKS;

        Some((save_to, load_from, kernel_stack_top))
    }
}

/// Set up the scheduler around the context that is already running.
///
/// Must be called after the heap is up (threads and their stacks are heap
/// allocated) and before interrupts are enabled, so that no tick can arrive
/// mid-construction.
pub fn init() {
    without_interrupts(|| {
        let mut guard = SCHEDULER.lock();
        if guard.is_some() {
            return;
        }

        // Thread 0 is whatever is executing right now. It is an ordinary
        // participant in the rotation.
        let boot = Box::new(Thread::adopt_running(BOOT_THREAD, "boot"));

        // Thread 1 only runs when nothing else can. It must be a separate thread
        // rather than a role the boot thread plays: if the boot thread were the
        // idle thread, any CPU-bound worker would starve it permanently, because
        // idle is by definition the last choice.
        let idle = Box::new(Thread::new(
            IDLE_THREAD,
            "idle",
            idle_loop,
            DEFAULT_STACK_SIZE,
            trampoline,
        ));

        *guard = Some(Scheduler {
            threads: alloc::vec![Some(boot), Some(idle)],
            ready: VecDeque::new(),
            current: BOOT_THREAD,
            slice_remaining: TIME_SLICE_TICKS,
        });
    });
}

/// Create a runnable thread. Returns its id, or `None` if the scheduler is not
/// up yet.
pub fn spawn(name: &'static str, entry: fn()) -> Option<ThreadId> {
    without_interrupts(|| {
        let mut guard = SCHEDULER.lock();
        let scheduler = guard.as_mut()?;

        let id = ThreadId(scheduler.threads.len());
        let thread = Box::new(Thread::new(id, name, entry, DEFAULT_STACK_SIZE, trampoline));

        scheduler.threads.push(Some(thread));
        scheduler.ready.push_back(id);
        Some(id)
    })
}

/// Hand the CPU to the next runnable thread, if there is one.
pub fn schedule() {
    without_interrupts(|| {
        let switch = {
            let mut guard = SCHEDULER.lock();
            let Some(scheduler) = guard.as_mut() else {
                return;
            };
            scheduler.reap();
            scheduler.prepare_switch()
        };

        let Some((save_to, load_from, kernel_stack_top)) = switch else {
            return;
        };

        // Publish the incoming thread's Ring 0 stack before it can be
        // interrupted. If this thread ever runs in Ring 3, the very next
        // interrupt reads this field to find a stack to land on.
        if kernel_stack_top != 0 {
            crate::arch::x86_64::gdt::set_kernel_stack(x86_64::VirtAddr::new(kernel_stack_top));
        }

        // SAFETY: `save_to` points into a `Box<Thread>`, whose address is stable
        // for as long as the box lives, and nothing can free it here: the only
        // thing that frees threads is `reap`, which runs under the lock we just
        // released, and interrupts are disabled on the only core, so no other
        // code can run between the unlock and this call. `load_from` came either
        // from `init_stack` or from a previous save through this same function.
        unsafe { context::context_switch(save_to, load_from) };
    });
}

/// Give up the rest of this thread's time slice voluntarily.
pub fn yield_now() {
    schedule();
}

/// Park the current thread until something calls [`unblock`] on it.
///
/// The caller is responsible for having registered itself somewhere a waker can
/// find it *before* calling this -- with interrupts disabled on a single core
/// there is no window between the two, but that stops being true the moment
/// there is a second CPU.
pub fn block_current() {
    with(|scheduler| {
        let id = scheduler.current;
        scheduler.thread_mut(id).state = State::Blocked;
    });
    schedule();
}

/// Return a blocked thread to the ready queue. Does nothing if it is not
/// blocked, so a duplicate wake is harmless.
pub fn unblock(id: ThreadId) {
    with(|scheduler| {
        let woken = match scheduler
            .threads
            .get_mut(id.0)
            .and_then(|slot| slot.as_deref_mut())
        {
            Some(thread) if thread.state == State::Blocked => {
                thread.state = State::Ready;
                true
            }
            _ => false,
        };
        if woken {
            scheduler.ready.push_back(id);
        }
    });
}

/// Top of the current thread's kernel stack, or 0 for the boot thread.
pub fn current_kernel_stack_top() -> u64 {
    with(|scheduler| scheduler.thread(scheduler.current).kernel_stack_top).unwrap_or(0)
}

/// Whether a thread still exists. False once it has finished and been reaped.
pub fn is_alive(id: ThreadId) -> bool {
    with(|scheduler| scheduler.thread_opt(id).is_some()).unwrap_or(false)
}

/// Whether a thread is currently blocked. Diagnostic, and used by tests.
pub fn is_blocked(id: ThreadId) -> bool {
    with(|scheduler| {
        matches!(
            scheduler.thread_opt(id),
            Some(thread) if thread.state == State::Blocked
        )
    })
    .unwrap_or(false)
}

/// End the current thread. Its stack is freed by a later `schedule()`, once the
/// switch away from it has completed.
pub fn exit_current() -> ! {
    let id = current_id().expect("exit_current outside a thread");

    // Release resources while the thread is still running and holds no
    // scheduler lock. `reap` cannot do this: it runs inside the timer interrupt
    // with the scheduler locked, and freeing memory there would deadlock
    // against a thread already inside the allocator.
    crate::release_thread_resources(id);

    with(|scheduler| {
        scheduler.thread_mut(id).state = State::Finished;
    });

    schedule();

    unreachable!("a finished thread was scheduled again")
}

/// Called from the timer interrupt. Charges the current thread a tick and
/// preempts it when its slice runs out.
pub fn on_timer_tick() {
    // Already inside an interrupt gate, so interrupts are off and this lock
    // cannot be contended by a nested tick.
    let expired = {
        let mut guard = SCHEDULER.lock();
        match guard.as_mut() {
            Some(scheduler) => {
                scheduler.slice_remaining = scheduler.slice_remaining.saturating_sub(1);
                scheduler.slice_remaining == 0
            }
            None => false,
        }
    };

    if expired {
        schedule();
    }
}

pub fn is_initialised() -> bool {
    without_interrupts(|| SCHEDULER.lock().is_some())
}

pub fn current_id() -> Option<ThreadId> {
    with(|scheduler| scheduler.current)
}

pub fn current_name() -> Option<&'static str> {
    with(|scheduler| scheduler.thread(scheduler.current).name)
}

/// Threads that exist and have not been reaped, including boot and idle.
pub fn live_thread_count() -> usize {
    with(|scheduler| scheduler.threads.iter().filter(|slot| slot.is_some()).count()).unwrap_or(0)
}

fn with<R>(f: impl FnOnce(&mut Scheduler) -> R) -> Option<R> {
    without_interrupts(|| SCHEDULER.lock().as_mut().map(f))
}

/// Where every new thread begins.
///
/// Reached by the `ret` at the end of `context_switch`, not by a call, which is
/// why it takes no arguments -- the switch zeroes the register file on the way
/// in. The entry point is fetched from the thread control block instead.
unsafe extern "C" fn trampoline() -> ! {
    // Interrupts are still disabled here, inherited from the switch. Read the
    // entry point first, so the scheduler lock is never held with interrupts on.
    let entry = with(|scheduler| scheduler.thread(scheduler.current).entry).flatten();

    // Now let the timer reach this thread, or it would run to completion
    // un-preemptible.
    x86_64::instructions::interrupts::enable();

    match entry {
        Some(entry) => entry(),
        None => panic!("thread was started with no entry point"),
    }

    exit_current()
}

/// The idle thread. `hlt` rather than a spin so an idle machine draws no power
/// and the host does not spin a core at 100%.
fn idle_loop() {
    loop {
        x86_64::instructions::hlt();
    }
}
