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

pub use thread::{Priority, State, Thread, ThreadId};

/// Ticks a thread gets before it is preempted. At the timer's 100 Hz that makes
/// a 10 ms quantum -- short enough to feel responsive, long enough that the
/// switch cost stays in the noise.
const TIME_SLICE_TICKS: u32 = 1;

/// How many consecutive switches may be served by priority before the lowest
/// occupied queue is given one.
const STARVATION_GUARD: u32 = 8;

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
    /// Runnable threads, oldest first, one queue per priority. Idle threads are
    /// deliberately never in here -- they are each CPU's fallback, not
    /// participants.
    ready: [VecDeque<ThreadId>; Priority::COUNT],

    /// Switches served from the highest occupied queue since the last time the
    /// lowest one got a turn.
    ///
    /// Strict priority starves: a `High` thread that never blocks means nothing
    /// below it ever runs again. Every `STARVATION_GUARD` switches, the choice
    /// deliberately comes from the *lowest* occupied queue instead. It is not a
    /// fair-share scheduler and does not pretend to be -- it is the minimum that
    /// keeps "low priority" from meaning "never".
    priority_streak: u32,

    /// Sleeping threads and the tick each is due to wake on.
    ///
    /// Unsorted, because it is scanned only when `next_wake` says something is
    /// due, and it is short. A timer wheel would be the answer at a thousand
    /// sleepers; at a handful it would be machinery for its own sake.
    sleepers: Vec<(ThreadId, u64)>,

    /// The earliest deadline in `sleepers`, or `u64::MAX` when none.
    ///
    /// This is the whole point of the design: the timer handler runs on every
    /// core on every tick, and all it does in the common case is compare two
    /// integers.
    next_wake: u64,

    /// Which thread each processor is running.
    current: [Option<ThreadId>; MAX_CPUS],
    /// Each processor's fallback when nothing else is runnable.
    idle: [Option<ThreadId>; MAX_CPUS],
    /// Ticks left in the current slice, per processor.
    slice: [u32; MAX_CPUS],
    /// The thread this CPU most recently switched away from, cleared by the
    /// incoming context once the switch has actually completed.
    ///
    /// It serves two purposes at once. A still-runnable thread may not be
    /// offered to another processor until its registers are saved, and a
    /// *finished* one may not be freed until this CPU has left its stack --
    /// between releasing the scheduler lock and the `mov rsp` inside
    /// `context_switch`, the outgoing thread is no longer `current` anywhere but
    /// is still the stack this CPU is standing on.
    pending: [Option<ThreadId>; MAX_CPUS],

    /// Finished threads waiting to be dropped.
    ///
    /// Dropping one unmaps its stack, which takes the page-table and frame
    /// locks and broadcasts a TLB shootdown. None of that can happen here --
    /// `reap` runs inside the timer interrupt with this lock held, so it would
    /// be taking the paging locks underneath the scheduler lock in one path and
    /// above it in another. They are handed out and dropped after the lock is
    /// released instead.
    ///
    /// The `Box` is not redundant: `prepare_switch` hands out a raw pointer into
    /// the live thread's `stack_pointer`, so a thread's address has to stay put.
    /// Unboxing into the vector would move it.
    #[allow(clippy::vec_box)]
    graveyard: Vec<Box<Thread>>,
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
    /// Never one that any processor is still standing on. `on_cpu` covers both
    /// "running right now" and "being switched away from", and it is the second
    /// that matters: a thread stops being `current` under the lock, but the CPU
    /// does not leave its stack until `context_switch` runs, well after the lock
    /// is released. Freeing it in that window unmaps the stack out from under a
    /// live processor. Checking only this CPU's `current` was correct while
    /// there was only one CPU.
    fn reap(&mut self) {
        for slot in self.threads.iter_mut() {
            let finished = matches!(
                slot.as_deref(),
                Some(t) if t.state == State::Finished && !t.on_cpu
            );
            if finished {
                if let Some(thread) = slot.take() {
                    self.graveyard.push(thread);
                }
            }
        }
    }

    /// Hand over the finished threads so the caller can drop them once the
    /// scheduler lock is released.
    #[allow(clippy::vec_box)]
    fn take_graveyard(&mut self) -> Vec<Box<Thread>> {
        core::mem::take(&mut self.graveyard)
    }

    /// Put a runnable thread on the queue its priority names.
    fn enqueue(&mut self, id: ThreadId) {
        let level = self.thread(id).priority.index();
        self.ready[level].push_back(id);
    }

    /// Take the next genuinely runnable thread, discarding entries for threads
    /// that have since finished or been reaped.
    ///
    /// A queued thread that is still `on_cpu` is dropped rather than returned.
    /// The invariant is that this cannot happen -- nothing enqueues a thread a
    /// processor is standing on -- but if it ever did, running it would put two
    /// CPUs on one stack. Dropping the entry is safe because `flush_pending`
    /// enqueues the thread again when the switch away from it completes.
    fn pop_runnable(&mut self) -> Option<ThreadId> {
        // Normally highest first; every so often lowest first, so that a busy
        // high-priority thread cannot lock everything below it out forever.
        let starving = self.priority_streak >= STARVATION_GUARD;
        let order: [usize; Priority::COUNT] = if starving { [0, 1, 2] } else { [2, 1, 0] };

        for level in order {
            while let Some(id) = self.ready[level].pop_front() {
                if matches!(self.thread_opt(id), Some(t) if t.state == State::Ready && !t.on_cpu) {
                    self.priority_streak = if starving {
                        0
                    } else {
                        self.priority_streak.saturating_add(1)
                    };
                    return Some(id);
                }
            }
        }
        None
    }

    /// Make a blocked thread runnable again.
    ///
    /// Shared by every wake path -- IPC, a lapsed sleep, a thread being joined
    /// finishing -- because the `on_cpu` rule is easy to get right once and easy
    /// to forget everywhere else.
    fn wake(&mut self, id: ThreadId) {
        let Some(thread) = self.threads.get_mut(id.0).and_then(|slot| slot.as_deref_mut()) else {
            return;
        };
        if thread.state != State::Blocked {
            return;
        }
        thread.state = State::Ready;

        // A wake can land while the thread is still leaving its processor: it
        // set itself Blocked, and the CPU running it has released the scheduler
        // lock but not yet reached `context_switch`. Queueing it here would let
        // another core resume it from a saved stack pointer that has not been
        // written yet -- a second CPU on a live stack, which reads as a wild
        // jump or a fault on a null rsp. `flush_pending` queues it once the
        // switch is genuinely done.
        if !thread.on_cpu {
            self.enqueue(id);
        }
    }

    /// Wake every sleeper whose deadline has passed, and recompute the next one.
    fn wake_due_sleepers(&mut self, now: u64) {
        let mut due = Vec::new();
        let mut earliest = u64::MAX;

        self.sleepers.retain(|&(id, deadline)| {
            if deadline <= now {
                due.push(id);
                false
            } else {
                earliest = earliest.min(deadline);
                true
            }
        });

        self.next_wake = earliest;
        for id in due {
            self.wake(id);
        }
    }

    /// Release the thread this CPU switched away from: the switch is complete,
    /// so it is safe both to run elsewhere and to free.
    ///
    /// Only a runnable, non-idle thread rejoins the queue. Idle threads belong
    /// to their processor and are never queued; finished ones are left for
    /// `reap`, which can now see them.
    fn flush_pending(&mut self, cpu: usize) {
        let Some(id) = self.pending[cpu].take() else {
            return;
        };
        let Some(thread) = self.threads.get_mut(id.0).and_then(|s| s.as_deref_mut()) else {
            return;
        };
        thread.on_cpu = false;
        let state = thread.state;

        if state == State::Ready && !self.idle.contains(&Some(id)) {
            self.enqueue(id);
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

        // Held back, whatever its state. A runnable thread must not be picked up
        // elsewhere while its registers are still live in this CPU, and a
        // finished one must not be freed while this CPU is still on its stack.
        // The incoming context releases it once the switch has completed.
        self.pending[cpu] = Some(current);

        let save_to: *mut u64 = &mut self.thread_mut(current).stack_pointer;

        let incoming = self.thread_mut(next);
        incoming.state = State::Running;
        // This CPU is committed to it from here, even though it does not
        // actually arrive until `context_switch`.
        incoming.on_cpu = true;
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
            Priority::Low,
            trampoline,
        ));

        let mut scheduler = Scheduler {
            threads: alloc::vec![Some(boot), Some(idle)],
            ready: [const { VecDeque::new() }; Priority::COUNT],
            priority_streak: 0,
            sleepers: Vec::new(),
            next_wake: u64::MAX,
            current: [None; MAX_CPUS],
            idle: [None; MAX_CPUS],
            slice: [TIME_SLICE_TICKS; MAX_CPUS],
            pending: [None; MAX_CPUS],
            graveyard: Vec::new(),
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

/// Create a runnable thread at [`Priority::Normal`]. Returns its id, or `None`
/// if the scheduler is not up yet.
pub fn spawn(name: &'static str, entry: fn()) -> Option<ThreadId> {
    spawn_with_priority(name, entry, Priority::Normal)
}

/// Create a runnable thread at a chosen priority.
pub fn spawn_with_priority(
    name: &'static str,
    entry: fn(),
    priority: Priority,
) -> Option<ThreadId> {
    with(|scheduler| {
        let id = ThreadId(scheduler.threads.len());
        let thread = Box::new(Thread::new(id, name, entry, priority, trampoline));

        scheduler.threads.push(Some(thread));
        scheduler.enqueue(id);
        id
    })
}

/// Change a thread's priority.
///
/// Takes effect at its next switch: a thread already in a queue stays there
/// until it is picked up, and is filed by its new priority when it next goes
/// back. Re-filing it immediately would mean finding and removing it from a
/// queue, and the delay is at most one quantum.
pub fn set_priority(id: ThreadId, priority: Priority) {
    with(|scheduler| {
        if let Some(thread) = scheduler.threads.get_mut(id.0).and_then(|s| s.as_deref_mut()) {
            thread.priority = priority;
        }
    });
}

/// A thread's priority, if it still exists.
pub fn priority_of(id: ThreadId) -> Option<Priority> {
    with(|scheduler| scheduler.thread_opt(id).map(|thread| thread.priority)).flatten()
}

/// Hand the CPU to the next runnable thread, if there is one.
pub fn schedule() {
    without_interrupts(|| {
        let cpu = cpu_index();

        let (switch, dead) = {
            let mut guard = SCHEDULER.lock();
            let Some(scheduler) = guard.as_mut() else {
                return;
            };
            scheduler.flush_pending(cpu);
            scheduler.reap();
            (scheduler.prepare_switch(cpu), scheduler.take_graveyard())
        };

        // Outside the scheduler lock: this unmaps stacks, returns frames and
        // may broadcast a shootdown, none of which may happen underneath it.
        drop(dead);

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
    with(|scheduler| scheduler.wake(id));
}

/// Park the current thread for at least `ticks` timer interrupts.
///
/// "At least": the thread becomes runnable at the deadline and runs when a
/// processor gets to it. A sleep is a floor, never a promise.
///
/// Sleeping zero ticks yields instead of parking, so a caller computing a
/// duration that rounds to nothing does not lose its wake-up.
pub fn sleep_ticks(ticks: u64) {
    if ticks == 0 {
        yield_now();
        return;
    }

    let parked = with(|scheduler| {
        let cpu = cpu_index();
        let Some(id) = scheduler.current[cpu] else {
            return false;
        };

        let deadline = crate::time::ticks().saturating_add(ticks);
        scheduler.thread_mut(id).state = State::Blocked;
        scheduler.sleepers.push((id, deadline));
        scheduler.next_wake = scheduler.next_wake.min(deadline);
        true
    })
    .unwrap_or(false);

    if parked {
        schedule();
    }
}

/// Park the current thread for at least `ms` milliseconds.
///
/// Rounds *up* to whole ticks: a caller asking for 1 ms at a 100 Hz timer wants
/// a short pause, not a busy yield.
pub fn sleep_ms(ms: u64) {
    let hz = crate::time::frequency_hz();
    if hz == 0 {
        // No timer, so no deadline can ever come due. Yielding is the honest
        // answer -- parking would be a hang.
        yield_now();
        return;
    }
    sleep_ticks(ms.saturating_mul(hz).div_ceil(1000));
}

/// Wait until `id` has finished. Returns immediately if it already has, or if
/// no such thread exists.
///
/// The registration and the block happen under one acquisition of the scheduler
/// lock, which is what makes this safe against the thread finishing in between:
/// `exit_current` takes the joiner list under the same lock, so it either sees
/// this waiter and wakes it, or has already finished and this returns without
/// parking.
///
/// Joining oneself would park forever and is refused.
pub fn join(id: ThreadId) {
    let parked = with(|scheduler| {
        let cpu = cpu_index();
        let Some(me) = scheduler.current[cpu] else {
            return false;
        };
        if me == id {
            return false;
        }

        // Gone, or on its way out with its joiner list already taken.
        match scheduler.thread_opt(id) {
            None => return false,
            Some(thread) if thread.state == State::Finished => return false,
            _ => {}
        }

        scheduler.thread_mut(id).joiners.push(me);
        scheduler.thread_mut(me).state = State::Blocked;
        true
    })
    .unwrap_or(false);

    if parked {
        schedule();
    }
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

        // Take the list before waking anyone: this thread is about to be
        // reaped, and the list goes with it. Waking under the same lock that
        // set `Finished` is what closes the race with a `join` arriving now --
        // it either got in before this and is on the list, or it sees
        // `Finished` and does not park at all.
        let joiners = core::mem::take(&mut scheduler.thread_mut(id).joiners);
        for joiner in joiners {
            scheduler.wake(joiner);
        }
    });

    schedule();

    unreachable!("a finished thread was scheduled again")
}

/// Called from the timer interrupt. Charges this CPU's thread a tick and
/// preempts it when its slice runs out.
pub fn on_timer_tick() {
    let expired = {
        let cpu = cpu_index();
        let now = crate::time::ticks();
        let mut guard = SCHEDULER.lock();
        match guard.as_mut() {
            Some(scheduler) => {
                // One comparison in the common case. Every core runs this on
                // every tick, so the sleeper list is only walked when something
                // in it is actually due.
                if now >= scheduler.next_wake {
                    scheduler.wake_due_sleepers(now);
                }

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

/// The unmapped page below a thread's stack, and its lowest mapped address.
///
/// Diagnostic, and used by the test that checks the guard is really there.
pub fn stack_bounds_of(id: ThreadId) -> Option<(u64, u64)> {
    with(|scheduler| {
        scheduler.thread_opt(id).and_then(|thread| {
            Some((thread.guard_page()?, thread.stack_bottom()?))
        })
    })
    .flatten()
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
