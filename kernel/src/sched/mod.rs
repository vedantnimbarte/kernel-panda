//! Preemptive round-robin thread scheduler, across every processor.
//!
//! Threads are kernel threads until one loads a user program; they share the
//! kernel's page tables and differ only in their stacks and saved registers.
//!
//! Preemption is driven by each CPU's own APIC timer. The handler decrements
//! that CPU's slice and, when it runs out, calls [`schedule`] -- so the switch
//! happens *inside* the interrupt handler, on the interrupted thread's stack.
//! That is why it works: each thread's stack carries its own interrupt frame, so
//! when a thread is resumed it returns out of its own handler and `iret`s back
//! to whatever it was doing.
//!
//! ## What is per-CPU and what is shared
//!
//! One ready queue, one lock, one thread table. Which thread is *running* is
//! per-CPU, as is its remaining slice and its idle thread -- two processors
//! cannot share an idle thread any more than they can share a stack.
//!
//! The lock is released before the context switch, because holding a spinlock
//! across one leaves it held by a thread that is no longer running. On a single
//! core that was safe by accident: nothing else could observe the gap. With more
//! than one it is not, so an outgoing thread is deliberately *not* returned to
//! the ready queue until its registers are saved -- otherwise another CPU could
//! pick it up and start running a thread whose context is still in our
//! registers. The incoming context does that enqueue, once the switch is done.

pub mod context;
pub mod thread;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::smp::{cpu_index, MAX_CPUS};
use crate::sync::{without_interrupts, IrqMutex};

pub use thread::{State, Thread, ThreadId, DEFAULT_STACK_SIZE};

/// Ticks a thread gets before it is preempted. At the timer's 100 Hz that makes
/// a 10 ms quantum -- short enough to feel responsive, long enough that the
/// switch cost stays in the noise.
const TIME_SLICE_TICKS: u32 = 1;

const BOOT_THREAD: ThreadId = ThreadId(0);

/// Interrupt-masking, because the timer handler schedules: a plain spinlock
/// would let a tick land on the CPU already holding it.
static SCHEDULER: IrqMutex<Option<Scheduler>> = IrqMutex::new(None);

/// What a context switch needs, decided under the lock and acted on after it is
/// released.
struct Switch {
    save_to: *mut u64,
    load_from: u64,
    kernel_stack_top: u64,
    space: Option<crate::memory::paging::AddressSpace>,
}

struct Scheduler {
    /// Indexed by `ThreadId`. A `None` slot is a thread that has finished and
    /// been reaped; ids are never reused, so a stale id reads as `None` rather
    /// than silently addressing someone else.
    threads: Vec<Option<Box<Thread>>>,
    /// Runnable threads, oldest first. Idle threads are deliberately never in
    /// here -- they are each CPU's fallback, not participants.
    ready: VecDeque<ThreadId>,

    /// Which thread each processor is running.
    current: [Option<ThreadId>; MAX_CPUS],
    /// Each processor's fallback when nothing else is runnable.
    idle: [Option<ThreadId>; MAX_CPUS],
    /// Ticks left in the current slice, per processor.
    slice: [u32; MAX_CPUS],
    /// A thread switched away from on this CPU whose registers are now saved and
    /// which may therefore safely be offered to another processor.
    pending: [Option<ThreadId>; MAX_CPUS],
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
    /// Never one that is current on *any* processor: it is still executing on
    /// the very stack that dropping it would free. Checking only this CPU was
    /// correct while there was only one.
    fn reap(&mut self) {
        let running = self.current;
        for slot in self.threads.iter_mut() {
            let finished = matches!(
                slot.as_deref(),
                Some(t) if t.state == State::Finished && !running.contains(&Some(t.id))
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

    /// Return a thread another CPU finished switching away from to the queue.
    fn flush_pending(&mut self, cpu: usize) {
        if let Some(id) = self.pending[cpu].take() {
            if matches!(self.thread_opt(id), Some(t) if t.state == State::Ready) {
                self.ready.push_back(id);
            }
        }
    }

    fn prepare_switch(&mut self, cpu: usize) -> Option<Switch> {
        let current = self.current[cpu]?;
        let idle = self.idle[cpu]?;

        let next = match self.pop_runnable() {
            Some(id) => id,
            None => {
                // Nobody else wants the CPU. Keep running rather than bouncing
                // to idle and straight back.
                if current != idle && self.thread(current).state == State::Running {
                    self.slice[cpu] = TIME_SLICE_TICKS;
                    return None;
                }
                idle
            }
        };

        if next == current {
            self.slice[cpu] = TIME_SLICE_TICKS;
            return None;
        }

        // Retire the outgoing thread. A thread that finished or blocked keeps
        // that state; only a still-running one becomes runnable again.
        let outgoing = self.thread_mut(current);
        if outgoing.state == State::Running {
            outgoing.state = State::Ready;
        }

        // Deliberately not pushed to the ready queue yet. Its registers are
        // still live in this CPU; another processor picking it up now would
        // resume a thread whose context has not been saved. The incoming
        // context enqueues it once the switch has completed.
        self.pending[cpu] = if current != idle && self.thread(current).state == State::Ready {
            Some(current)
        } else {
            None
        };

        let save_to: *mut u64 = &mut self.thread_mut(current).stack_pointer;

        let incoming = self.thread_mut(next);
        incoming.state = State::Running;
        let load_from = incoming.stack_pointer;
        let kernel_stack_top = incoming.kernel_stack_top;
        let space = incoming.address_space;

        self.current[cpu] = Some(next);
        self.slice[cpu] = TIME_SLICE_TICKS;

        Some(Switch {
            save_to,
            load_from,
            kernel_stack_top,
            space,
        })
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

        // Thread 0 is whatever is executing right now, on the boot processor.
        let boot = Box::new(Thread::adopt_running(BOOT_THREAD, "boot"));

        // The boot processor's idle thread. It has to be separate from the boot
        // thread: idle is by definition the last choice, so if the boot thread
        // were also idle, any CPU-bound worker would starve it permanently.
        let idle = Box::new(Thread::new(
            ThreadId(1),
            "idle",
            idle_loop,
            DEFAULT_STACK_SIZE,
            trampoline,
        ));

        let mut scheduler = Scheduler {
            threads: alloc::vec![Some(boot), Some(idle)],
            ready: VecDeque::new(),
            current: [None; MAX_CPUS],
            idle: [None; MAX_CPUS],
            slice: [TIME_SLICE_TICKS; MAX_CPUS],
            pending: [None; MAX_CPUS],
        };
        scheduler.current[0] = Some(BOOT_THREAD);
        scheduler.idle[0] = Some(ThreadId(1));

        *guard = Some(scheduler);
    });
}

/// Register a processor that has just come up.
///
/// The context it is already running on becomes that CPU's idle thread, the
/// same way the boot thread was adopted rather than created.
pub fn adopt_secondary_cpu() {
    let cpu = cpu_index();
    with(|scheduler| {
        if scheduler.idle[cpu].is_some() {
            return;
        }
        let id = ThreadId(scheduler.threads.len());
        let idle = Box::new(Thread::adopt_running(id, "idle-ap"));
        scheduler.threads.push(Some(idle));
        scheduler.idle[cpu] = Some(id);
        scheduler.current[cpu] = Some(id);
        scheduler.slice[cpu] = TIME_SLICE_TICKS;
    });
}

/// Create a runnable thread. Returns its id, or `None` if the scheduler is not
/// up yet.
pub fn spawn(name: &'static str, entry: fn()) -> Option<ThreadId> {
    with(|scheduler| {
        let id = ThreadId(scheduler.threads.len());
        let thread = Box::new(Thread::new(id, name, entry, DEFAULT_STACK_SIZE, trampoline));

        scheduler.threads.push(Some(thread));
        scheduler.ready.push_back(id);
        id
    })
}

/// Hand the CPU to the next runnable thread, if there is one.
pub fn schedule() {
    without_interrupts(|| {
        let cpu = cpu_index();

        let switch = {
            let mut guard = SCHEDULER.lock();
            let Some(scheduler) = guard.as_mut() else {
                return;
            };
            scheduler.flush_pending(cpu);
            scheduler.reap();
            scheduler.prepare_switch(cpu)
        };

        let Some(switch) = switch else {
            return;
        };

        // Publish the incoming thread's Ring 0 stack before it can be
        // interrupted. If this thread ever runs in Ring 3, the very next
        // interrupt reads this field to find a stack to land on.
        if switch.kernel_stack_top != 0 {
            crate::arch::x86_64::gdt::set_kernel_stack(x86_64::VirtAddr::new(
                switch.kernel_stack_top,
            ));
        }

        // Swap page tables before the stack switch. Safe at any point inside the
        // kernel because every space carries the same kernel mappings.
        let target = switch
            .space
            .unwrap_or_else(crate::memory::paging::kernel_space);
        // SAFETY: `target` is either cloned from the kernel space -- and so
        // contains every kernel mapping -- or the kernel's own.
        unsafe { target.activate() };

        // SAFETY: `save_to` points into a `Box<Thread>` whose address is stable,
        // and nothing can free it here: `reap` runs under the lock just
        // released, and it refuses to free a thread current on any CPU.
        unsafe { context::context_switch(switch.save_to, switch.load_from) };

        // Reached as the *incoming* thread. The thread this processor switched
        // away from now has its registers saved, so it can safely be offered to
        // another CPU.
        let cpu = cpu_index();
        with(|scheduler| scheduler.flush_pending(cpu));
    });
}

/// Give up the rest of this thread's time slice voluntarily.
pub fn yield_now() {
    schedule();
}

/// Park the current thread until something calls [`unblock`] on it.
///
/// The caller must have registered itself somewhere a waker can find it, with
/// interrupts still disabled, *before* calling this -- otherwise a waker running
/// in the gap finds a thread that is not yet blocked and the wake is lost.
pub fn block_current() {
    with(|scheduler| {
        let cpu = cpu_index();
        if let Some(id) = scheduler.current[cpu] {
            scheduler.thread_mut(id).state = State::Blocked;
        }
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

/// Called from the timer interrupt. Charges this CPU's thread a tick and
/// preempts it when its slice runs out.
pub fn on_timer_tick() {
    let expired = {
        let cpu = cpu_index();
        let mut guard = SCHEDULER.lock();
        match guard.as_mut() {
            Some(scheduler) => {
                scheduler.slice[cpu] = scheduler.slice[cpu].saturating_sub(1);
                scheduler.slice[cpu] == 0
            }
            None => false,
        }
    };

    if expired {
        schedule();
    }
}

pub fn is_initialised() -> bool {
    SCHEDULER.lock().is_some()
}

pub fn current_id() -> Option<ThreadId> {
    with(|scheduler| scheduler.current[cpu_index()]).flatten()
}

pub fn current_name() -> Option<&'static str> {
    with(|scheduler| {
        scheduler.current[cpu_index()].map(|id| scheduler.thread(id).name)
    })
    .flatten()
}

/// Threads that exist and have not been reaped.
pub fn live_thread_count() -> usize {
    with(|scheduler| scheduler.threads.iter().filter(|slot| slot.is_some()).count()).unwrap_or(0)
}

/// Give a thread its own page tables.
pub fn set_address_space(id: ThreadId, space: crate::memory::paging::AddressSpace) {
    with(|scheduler| {
        scheduler.thread_mut(id).address_space = Some(space);
    });
}

/// A thread's page tables, if it has its own.
pub fn address_space_of(id: ThreadId) -> Option<crate::memory::paging::AddressSpace> {
    with(|scheduler| scheduler.thread_opt(id).and_then(|thread| thread.address_space)).flatten()
}

/// Top of the current thread's kernel stack, or 0 for a thread that owns none.
pub fn current_kernel_stack_top() -> u64 {
    with(|scheduler| {
        scheduler.current[cpu_index()]
            .map(|id| scheduler.thread(id).kernel_stack_top)
            .unwrap_or(0)
    })
    .unwrap_or(0)
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

fn with<R>(f: impl FnOnce(&mut Scheduler) -> R) -> Option<R> {
    without_interrupts(|| SCHEDULER.lock().as_mut().map(f))
}

/// Where every new thread begins.
///
/// Reached by the `ret` at the end of `context_switch`, not by a call, which is
/// why it takes no arguments -- the switch zeroes the register file on the way
/// in. The entry point is fetched from the thread control block instead.
unsafe extern "C" fn trampoline() -> ! {
    // Whatever this processor switched away from can now be handed on.
    let cpu = cpu_index();
    with(|scheduler| scheduler.flush_pending(cpu));

    // Interrupts are still disabled here, inherited from the switch. Read the
    // entry point first, so the scheduler lock is never held with interrupts on.
    let entry = with(|scheduler| {
        scheduler.current[cpu_index()].and_then(|id| scheduler.thread(id).entry)
    })
    .flatten();

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
