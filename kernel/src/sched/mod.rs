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
//! One lock and one thread table. Everything about *where* a thread runs is
//! per-CPU: its ready queues, which thread is current, the remaining slice, the
//! idle thread -- two processors cannot share an idle thread any more than they
//! can share a stack.
//!
//! A thread goes back on the queue of the processor that last ran it, so it
//! tends to return to a core whose caches still know about it. A core with
//! nothing of its own to run steals from the busiest queue rather than idling
//! next to a backlog, which is what keeps the split from turning into four
//! independent schedulers with wildly different amounts of work.
//!
//! The timer handler is deliberately kept out of the lock. It runs on every core
//! on every tick, and in the common case all it does is decrement a per-CPU
//! atomic and compare a deadline -- it only takes the lock when a slice actually
//! expires or a sleeper is actually due. Before that, every core queued on the
//! same lock a hundred times a second for the privilege of subtracting one.
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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

/// Ticks left in each processor's slice.
///
/// Outside the lock on purpose. Every core reaches the timer handler on every
/// tick, and this is all the handler needs to know in the overwhelming majority
/// of them; taking the scheduler lock to subtract one put four cores in a queue
/// a hundred times a second for no reason. It is advisory -- the authoritative
/// reset happens under the lock at the switch -- so a lost race costs at most one
/// early or late preemption, which round-robin cannot tell from a normal one.
static SLICE: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(TIME_SLICE_TICKS) }; MAX_CPUS];

/// The earliest deadline any sleeper is waiting for, or `u64::MAX` when none.
///
/// Also outside the lock, and for the same reason: this is the other question
/// the timer handler asks every core every tick. Only ever moved *earlier*
/// without the lock (by a thread adding a sleeper), so a stale read is a read
/// that is too late by a tick at worst, never one that misses a wake-up
/// permanently.
static NEXT_WAKE: AtomicU64 = AtomicU64::new(u64::MAX);

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
    /// Runnable threads, oldest first: one set of priority queues per processor.
    ///
    /// A thread is filed on the queue of the core that last ran it, so it tends
    /// to come back to caches that still know about it. Idle threads are
    /// deliberately never in here -- they are each CPU's fallback, not
    /// participants.
    ready: [[VecDeque<ThreadId>; Priority::COUNT]; MAX_CPUS],

    /// Switches served strictly by priority since the last time a lower queue
    /// was given a turn, per processor.
    ///
    /// Strict priority starves: a `High` thread that never blocks means nothing
    /// below it ever runs again. Every `STARVATION_GUARD` switches, the choice
    /// deliberately comes from somewhere other than the top.
    priority_streak: [u32; MAX_CPUS],

    /// Which of the lower queues gets the next turn, per processor.
    ///
    /// Alternates rather than always picking the lowest. "Lowest occupied"
    /// looks like the obvious answer and quietly skips the middle: with `High`
    /// and `Low` both busy, every guarded turn went to `Low` and a `Normal`
    /// thread never ran again. Alternating means each of the two is tried first
    /// every other turn, so no level waits longer than `2 * STARVATION_GUARD`
    /// switches.
    ///
    /// It is not a fair-share scheduler and does not pretend to be -- it is the
    /// minimum that keeps a priority from meaning "never".
    boost_level: [usize; MAX_CPUS],

    /// Sleeping threads and the tick each is due to wake on.
    ///
    /// Unsorted, because it is scanned only when `NEXT_WAKE` says something is
    /// due, and it is short. A timer wheel would be the answer at a thousand
    /// sleepers; at a handful it would be machinery for its own sake.
    sleepers: Vec<(ThreadId, u64)>,

    /// Which thread each processor is running.
    current: [Option<ThreadId>; MAX_CPUS],
    /// Each processor's fallback when nothing else is runnable.
    idle: [Option<ThreadId>; MAX_CPUS],
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

    /// Threads that have set themselves `Finished` and are waiting to be freed.
    ///
    /// `reap` used to scan the whole thread table looking for them, on every
    /// context switch, with the lock held. That is an O(threads) walk on the
    /// hottest path in the kernel to find, almost always, nothing. Exits are
    /// rare, so the exiting thread records itself here and reaping becomes
    /// proportional to the number of threads that actually died.
    finished: Vec<ThreadId>,
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
        if self.finished.is_empty() {
            return;
        }

        let candidates = core::mem::take(&mut self.finished);
        for id in candidates {
            let ready_to_free = matches!(
                self.thread_opt(id),
                Some(t) if t.state == State::Finished && !t.on_cpu
            );

            if !ready_to_free {
                // Still being switched away from. Put it back and look again
                // next time; the CPU leaving its stack is a handful of
                // instructions away.
                if matches!(self.thread_opt(id), Some(t) if t.state == State::Finished) {
                    self.finished.push(id);
                }
                continue;
            }

            if let Some(thread) = self.threads[id.0].take() {
                self.graveyard.push(thread);
            }
        }
    }

    /// Hand over the finished threads so the caller can drop them once the
    /// scheduler lock is released.
    #[allow(clippy::vec_box)]
    fn take_graveyard(&mut self) -> Vec<Box<Thread>> {
        core::mem::take(&mut self.graveyard)
    }

    /// Put a runnable thread on `cpu`'s queue for its priority.
    fn enqueue_on(&mut self, cpu: usize, id: ThreadId) {
        let level = self.thread(id).priority.index();
        self.ready[cpu.min(MAX_CPUS - 1)][level].push_back(id);
    }

    /// Whether a queued id still names something worth running.
    ///
    /// A queued thread that is still `on_cpu` fails this and is discarded rather
    /// than returned. The invariant is that this cannot happen -- nothing
    /// enqueues a thread a processor is standing on -- but if it ever did,
    /// running it would put two CPUs on one stack. Discarding is safe because
    /// `flush_pending` enqueues the thread again when the switch completes.
    fn is_runnable(&self, id: ThreadId) -> bool {
        matches!(self.thread_opt(id), Some(t) if t.state == State::Ready && !t.on_cpu)
    }

    /// Take the next runnable thread from one processor's queues, trying the
    /// priority levels in `order`.
    fn pop_from(&mut self, cpu: usize, order: [usize; Priority::COUNT]) -> Option<ThreadId> {
        for level in order {
            while let Some(id) = self.ready[cpu][level].pop_front() {
                if self.is_runnable(id) {
                    return Some(id);
                }
            }
        }
        None
    }

    /// Runnable threads waiting on one processor's queues.
    ///
    /// Counts entries, not verified threads: an id belonging to a thread that
    /// has since finished inflates it slightly, and the only cost of that is
    /// picking a marginally wrong victim to steal from.
    fn queued_on(&self, cpu: usize) -> usize {
        self.ready[cpu].iter().map(|queue| queue.len()).sum()
    }

    /// Take the next genuinely runnable thread for `cpu`: its own queues first,
    /// then the busiest other processor's.
    ///
    /// Stealing is what keeps per-CPU queues from becoming four independent
    /// schedulers. Without it a core that happens to have emptied its own queue
    /// runs its idle thread next to another core's backlog, and the split makes
    /// throughput worse rather than better.
    fn pop_runnable(&mut self, cpu: usize) -> Option<ThreadId> {
        let boosting = self.priority_streak[cpu] >= STARVATION_GUARD;

        // Normally highest first. On a guarded turn the boosted level goes
        // first, with the rest behind it so the CPU is never left idle because
        // one queue happened to be empty.
        let order: [usize; Priority::COUNT] = match (boosting, self.boost_level[cpu]) {
            (false, _) => [2, 1, 0],
            (true, 0) => [0, 1, 2],
            (true, _) => [1, 0, 2],
        };

        let found = self.pop_from(cpu, order).or_else(|| {
            // Steal from whoever has the most, so one busy core is drained
            // rather than a queue of one being passed around.
            let victim = (0..MAX_CPUS)
                .filter(|&other| other != cpu)
                .max_by_key(|&other| self.queued_on(other))
                .filter(|&other| self.queued_on(other) > 0)?;
            self.pop_from(victim, order)
        })?;

        if boosting {
            self.priority_streak[cpu] = 0;
            // Alternate, so `Low` and `Normal` take it in turns. Always picking
            // the lowest occupied queue is what let the middle one starve.
            self.boost_level[cpu] ^= 1;
        } else {
            self.priority_streak[cpu] = self.priority_streak[cpu].saturating_add(1);
        }
        Some(found)
    }

    /// Make a blocked thread runnable again.
    ///
    /// Shared by every wake path -- IPC, a lapsed sleep, a thread being joined
    /// finishing -- because the `on_cpu` rule is easy to get right once and easy
    /// to forget everywhere else.
    ///
    /// The woken thread is filed on the queue of whichever processor is doing
    /// the waking. That is usually the one it will talk to next, and a wrong
    /// guess costs nothing: a core with an empty queue steals.
    fn wake(&mut self, id: ThreadId) {
        let cpu = cpu_index();
        self.wake_onto(cpu, id);
    }

    fn wake_onto(&mut self, cpu: usize, id: ThreadId) {
        let Some(thread) = self.threads.get_mut(id.0).and_then(|slot| slot.as_deref_mut()) else {
            return;
        };
        if thread.state != State::Blocked {
            // Not parked yet. It registered with its waker, released that lock
            // and has not reached `block_current` -- a window this cannot close
            // by waiting, because the thread is on another processor. Leaving
            // now would drop the wake and park it forever, so it is recorded
            // and the thread's own attempt to block consumes it.
            //
            // Only meaningful for a live thread; a Finished one is not going to
            // block again.
            if thread.state != State::Finished {
                thread.wake_pending = true;
            }
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
            self.enqueue_on(cpu, id);
        }
    }

    /// Wake every sleeper whose deadline has passed, and republish the next one.
    fn wake_due_sleepers(&mut self, cpu: usize, now: u64) {
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

        // Only ever moved later from in here, and only with the lock held, so a
        // sleeper added concurrently cannot have its earlier deadline erased --
        // `sleep_ticks` publishes the minimum, and it took the lock to get on
        // the list in the first place.
        NEXT_WAKE.store(earliest, Ordering::Release);

        for id in due {
            self.wake_onto(cpu, id);
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

        // Back onto this processor's own queue: it just ran here, so this is the
        // core whose caches still hold its working set.
        if state == State::Ready && !self.idle.contains(&Some(id)) {
            self.enqueue_on(cpu, id);
        }
    }

    fn prepare_switch(&mut self, cpu: usize) -> Option<Switch> {
        let current = self.current[cpu]?;
        let idle = self.idle[cpu]?;

        let next = match self.pop_runnable(cpu) {
            Some(id) => id,
            None => {
                // Nobody else wants the CPU. Keep running rather than bouncing
                // to idle and straight back.
                if current != idle && self.thread(current).state == State::Running {
                    renew_slice(cpu);
                    return None;
                }
                idle
            }
        };

        if next == current {
            renew_slice(cpu);
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
        renew_slice(cpu);

        Some(Switch {
            save_to,
            load_from,
            kernel_stack_top,
            space,
        })
    }
}

/// Give a processor a fresh quantum.
fn renew_slice(cpu: usize) {
    if let Some(slice) = SLICE.get(cpu) {
        slice.store(TIME_SLICE_TICKS, Ordering::Relaxed);
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
            ready: [const { [const { VecDeque::new() }; Priority::COUNT] }; MAX_CPUS],
            priority_streak: [0; MAX_CPUS],
            boost_level: [0; MAX_CPUS],
            sleepers: Vec::new(),
            current: [None; MAX_CPUS],
            idle: [None; MAX_CPUS],
            pending: [None; MAX_CPUS],
            graveyard: Vec::new(),
            finished: Vec::new(),
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
        renew_slice(cpu);
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
        // On the spawner's queue. A new thread has no cache footprint anywhere
        // yet, and the core that made it is as good a guess as any -- an idle
        // core will steal it within a switch if this one is busy.
        scheduler.enqueue_on(cpu_index(), id);
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
/// The caller must have registered itself somewhere a waker can find it before
/// calling this. It need not hold that registration's lock -- a wake arriving in
/// the gap is recorded rather than lost, and consumed here.
///
/// Returns whether the thread actually parked. A `false` means a wake beat it
/// to the punch and there is something to collect, so the caller should go back
/// and look rather than assuming it was woken for nothing.
pub fn block_current() -> bool {
    let parked = with(|scheduler| {
        let cpu = cpu_index();
        let Some(id) = scheduler.current[cpu] else {
            return false;
        };

        let thread = scheduler.thread_mut(id);
        if core::mem::take(&mut thread.wake_pending) {
            // Woken between registering and getting here. Parking now would
            // wait for a wake that has already been delivered.
            return false;
        }
        thread.state = State::Blocked;
        true
    })
    .unwrap_or(false);

    if parked {
        schedule();
    }
    parked
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
        let thread = scheduler.thread_mut(id);
        // Registering and parking happen under one lock here, so there is no
        // gap for a wake to fall into. Any pending one is stale.
        thread.wake_pending = false;
        thread.state = State::Blocked;
        scheduler.sleepers.push((id, deadline));

        // Published under the lock, so it cannot race with the recomputation in
        // `wake_due_sleepers`. Only ever moved earlier here: an existing sooner
        // deadline must not be pushed back.
        NEXT_WAKE.fetch_min(deadline, Ordering::AcqRel);
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
        let waiter = scheduler.thread_mut(me);
        // As in `sleep_ticks`: registration and parking share one acquisition
        // of the lock, so nothing can slip between them.
        waiter.wake_pending = false;
        waiter.state = State::Blocked;
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
        // Recorded rather than searched for. `reap` runs on every switch, and
        // scanning the whole thread table each time to find the rare thread
        // that has died is the wrong shape entirely.
        scheduler.finished.push(id);

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
    let cpu = cpu_index();
    let now = crate::time::ticks();

    // Neither of these touches the scheduler lock. This runs on every core on
    // every tick, and both answers are almost always "no" -- queueing four cores
    // on one lock a hundred times a second to find that out was the single
    // busiest thing the scheduler did.
    let sleeper_due = now >= NEXT_WAKE.load(Ordering::Acquire);
    let slice_expired = match SLICE.get(cpu) {
        // A saturating update rather than a decrement, so a slice already at
        // zero is not wrapped by ticks arriving while a switch is in flight.
        Some(slice) => slice
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                Some(left.saturating_sub(1))
            })
            .is_ok_and(|previous| previous <= 1),
        None => false,
    };

    if sleeper_due {
        with(|scheduler| scheduler.wake_due_sleepers(cpu, now));
    }

    if slice_expired {
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
