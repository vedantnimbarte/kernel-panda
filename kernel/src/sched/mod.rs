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
//! ## Who owns what
//!
//! Every processor has its own lock, over its own ready queues, the thread it
//! is running, and the thread it is switching away from. Every thread is
//! *owned* by exactly one processor, recorded in the thread itself, and the
//! thread's scheduling state -- whether it is ready, running or blocked, its
//! saved stack pointer, whether a CPU is standing on its stack -- may only be
//! read or changed under its owner's lock.
//!
//! A context switch therefore takes one lock: this processor's. It used to take
//! one lock shared by every processor, so four cores switching a hundred times a
//! second each queued on the same word -- and under emulation, where a vCPU
//! spinning for a lock can be descheduled by the host while holding another,
//! that queue was where the machine spent its time.
//!
//! Ownership only moves while a thread is off every CPU, and only under the
//! locks of both processors involved, taken in index order so that two moves in
//! opposite directions cannot deadlock. That happens when a thread is woken
//! (it moves to the waker's processor, which is usually the one it will talk to
//! next) and when an idle processor steals from a busy one. Anything that finds
//! a thread by id takes the owner's lock and then checks the owner has not
//! changed underneath it, following the thread if it has.
//!
//! The thread table itself is a separate lock, consulted to turn an id into a
//! thread. Nothing on the switch path touches it.
//!
//! The lock is released before the context switch, because holding a spinlock
//! across one leaves it held by a thread that is no longer running. An outgoing
//! thread is deliberately *not* returned to the ready queue until its registers
//! are saved -- otherwise another CPU could pick it up and start running a
//! thread whose context is still in our registers. The incoming context does
//! that enqueue, once the switch is done.

pub mod context;
pub mod thread;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::memory::kstack::KernelStack;
use crate::smp::{cpu_index, MAX_CPUS};
use crate::sync::{without_interrupts, Mutex, MutexGuard};

pub use thread::{Priority, State, Thread, ThreadId};

/// Ticks a thread gets before it is preempted. At the timer's 100 Hz that makes
/// a 10 ms quantum -- short enough to feel responsive, long enough that the
/// switch cost stays in the noise.
const TIME_SLICE_TICKS: u32 = 1;

/// How many consecutive switches may be served by priority before the lowest
/// occupied queue is given one.
const STARVATION_GUARD: u32 = 8;

const BOOT_THREAD: ThreadId = ThreadId(0);

/// Ticks left in each processor's slice.
///
/// Outside every lock on purpose. Every core reaches the timer handler on every
/// tick, and this is all the handler needs to know in the overwhelming majority
/// of them. It is advisory -- the authoritative reset happens at the switch -- so
/// a lost race costs at most one early or late preemption, which round-robin
/// cannot tell from a normal one.
static SLICE: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(TIME_SLICE_TICKS) }; MAX_CPUS];

/// The earliest deadline any sleeper is waiting for, or `u64::MAX` when none.
///
/// Also outside the lock, and for the same reason: this is the other question
/// the timer handler asks every core every tick. Only ever moved *earlier*
/// without the lock (by a thread adding a sleeper), so a stale read is a read
/// that is too late by a tick at worst, never one that misses a wake-up
/// permanently.
static NEXT_WAKE: AtomicU64 = AtomicU64::new(u64::MAX);

/// The thread each processor is running, as its id plus one, or zero.
///
/// Lock-free because every system call and every IPC operation asks. It is
/// written under the processor's lock at each switch and only ever read by the
/// thread it names, with interrupts masked so it cannot migrate between reading
/// its processor index and reading this.
static CURRENT: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

/// Threads queued on each processor. A hint for stealing, which reads it
/// without the victim's lock to decide whether taking that lock is worth it.
static QUEUED: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

static INITIALISED: AtomicBool = AtomicBool::new(false);

/// A thread, as the scheduler holds it.
///
/// Shared by reference count, so a thread found by id stays valid while the
/// finder takes its owner's lock -- even if it finishes meanwhile. The kernel
/// stack is not freed by the last reference going away but taken out and freed
/// explicitly, away from every lock, once no processor is standing on it; what
/// outlives that is a small control block.
struct Slot {
    id: ThreadId,
    name: &'static str,
    /// The processor whose lock guards `thread`.
    owner: AtomicUsize,
    thread: UnsafeCell<Thread>,
}

// SAFETY: `thread` is only reached through `Slot::get`, whose contract is that
// the owner's lock is held -- so one processor at a time.
unsafe impl Send for Slot {}
// SAFETY: as above.
unsafe impl Sync for Slot {}

type ThreadRef = Arc<Slot>;

impl Slot {
    /// The thread's scheduling state.
    ///
    /// # Safety
    ///
    /// The caller holds the lock of the processor `owner` names, and keeps
    /// holding it for as long as the reference lives.
    #[allow(clippy::mut_from_ref)]
    unsafe fn get(&self) -> &mut Thread {
        // SAFETY: forwarded from this function's contract.
        unsafe { &mut *self.thread.get() }
    }
}

/// One processor's share of the scheduler.
struct Cpu {
    /// Runnable threads this processor owns, oldest first, one queue per
    /// priority.
    ready: [VecDeque<ThreadRef>; Priority::COUNT],
    current: Option<ThreadRef>,
    /// The fallback when nothing else is runnable. Never queued, never moved.
    idle: Option<ThreadRef>,
    /// The thread this processor most recently switched away from, released by
    /// the incoming context once the switch has actually completed.
    ///
    /// It serves two purposes at once. A still-runnable thread may not be
    /// offered to another processor until its registers are saved, and a
    /// *finished* one may not be freed until this CPU has left its stack --
    /// between releasing the lock and the `mov rsp` inside `context_switch`, the
    /// outgoing thread is no longer `current` but is still the stack this CPU is
    /// standing on.
    pending: Option<ThreadRef>,
    /// Switches served strictly by priority since the last time a lower queue
    /// was given a turn.
    ///
    /// Strict priority starves: a `High` thread that never blocks means nothing
    /// below it ever runs again. Every `STARVATION_GUARD` switches, the choice
    /// deliberately comes from somewhere other than the top.
    priority_streak: u32,
    /// Which of the lower queues gets the next turn. Alternates rather than
    /// always picking the lowest, which skipped the middle: with `High` and
    /// `Low` both busy, every guarded turn went to `Low` and a `Normal` thread
    /// never ran again.
    boost_level: usize,
    /// Stacks of finished threads, freed once this lock is released: freeing
    /// one unmaps it, takes the paging locks and broadcasts a shootdown.
    graveyard: Vec<KernelStack>,
    /// Finished threads to take out of the thread table, likewise once this
    /// lock is released.
    reaped: Vec<ThreadId>,
}

impl Cpu {
    const fn new() -> Self {
        Self {
            ready: [const { VecDeque::new() }; Priority::COUNT],
            current: None,
            idle: None,
            pending: None,
            priority_streak: 0,
            boost_level: 0,
            graveyard: Vec::new(),
            reaped: Vec::new(),
        }
    }
}

static CPUS: [Mutex<Cpu>; MAX_CPUS] = [const { Mutex::new(Cpu::new()) }; MAX_CPUS];

/// Every thread that has not been reaped, indexed by id. Ids are never reused,
/// so a stale id reads as `None` rather than silently addressing someone else.
static THREADS: Mutex<Vec<Option<ThreadRef>>> = Mutex::new(Vec::new());

/// Sleeping threads and the tick each is due to wake on.
///
/// Unsorted, because it is scanned only when `NEXT_WAKE` says something is
/// due, and it is short. Lock order: a processor's lock may be held when this
/// is taken, never the other way round.
static SLEEPERS: Mutex<Vec<(ThreadId, u64)>> = Mutex::new(Vec::new());

type CpuGuard = MutexGuard<'static, Cpu>;

fn lookup(id: ThreadId) -> Option<ThreadRef> {
    without_interrupts(|| THREADS.lock().get(id.0).cloned().flatten())
}

/// Lock the processor that owns `slot`, following the thread if it moves
/// while the lock is being taken. Interrupts must be masked.
fn lock_owner(slot: &Slot) -> CpuGuard {
    loop {
        let owner = slot.owner.load(Ordering::Acquire);
        let guard = CPUS[owner].lock();
        // Ownership only changes under the owner's lock, so having that lock and
        // still being named is final.
        if slot.owner.load(Ordering::Acquire) == owner {
            return guard;
        }
    }
}

/// Lock two processors, lower index first, whichever order they are named in.
/// Returns `a`'s guard and, if they differ, `b`'s. Interrupts must be masked,
/// so that neither guard re-enables them while the other is still held.
fn lock_pair(a: usize, b: usize) -> (CpuGuard, Option<CpuGuard>) {
    if a == b {
        (CPUS[a].lock(), None)
    } else if a < b {
        let first = CPUS[a].lock();
        (first, Some(CPUS[b].lock()))
    } else {
        let first = CPUS[b].lock();
        (CPUS[a].lock(), Some(first))
    }
}

fn renew_slice(cpu: usize) {
    if let Some(slice) = SLICE.get(cpu) {
        slice.store(TIME_SLICE_TICKS, Ordering::Relaxed);
    }
}

/// Put a thread `cpu` owns on its queue for its priority.
fn enqueue(me: &mut Cpu, cpu: usize, slot: ThreadRef) {
    // SAFETY: the caller holds `cpu`'s lock and `cpu` owns the thread.
    let level = unsafe { slot.get() }.priority.index();
    me.ready[level].push_back(slot);
    QUEUED[cpu].fetch_add(1, Ordering::Relaxed);
}

/// Take the next genuinely runnable thread from one processor's queues, trying
/// priority levels in `order`.
///
/// A queued thread that is not `Ready`, or that a processor is still standing
/// on, is discarded rather than returned. The invariant is that neither can
/// happen, but running such a thread would put two CPUs on one stack, and
/// `flush_pending` queues a thread again when its switch really completes.
fn pop_from(me: &mut Cpu, cpu: usize, order: [usize; Priority::COUNT]) -> Option<ThreadRef> {
    for level in order {
        while let Some(slot) = me.ready[level].pop_front() {
            QUEUED[cpu].fetch_sub(1, Ordering::Relaxed);
            // SAFETY: queued on `cpu`, so owned by it, and the caller holds its
            // lock.
            let thread = unsafe { slot.get() };
            if thread.state == State::Ready && !thread.on_cpu {
                return Some(slot);
            }
        }
    }
    None
}

/// The next thread for this processor, honouring the starvation guard.
fn pop_runnable(me: &mut Cpu, cpu: usize) -> Option<ThreadRef> {
    let boosting = me.priority_streak >= STARVATION_GUARD;

    // Normally highest first. On a guarded turn the boosted level goes first,
    // with the rest behind it so the CPU is never left idle because one queue
    // happened to be empty.
    let order: [usize; Priority::COUNT] = match (boosting, me.boost_level) {
        (false, _) => [2, 1, 0],
        (true, 0) => [0, 1, 2],
        (true, _) => [1, 0, 2],
    };

    let found = pop_from(me, cpu, order)?;
    if boosting {
        me.priority_streak = 0;
        me.boost_level ^= 1;
    } else {
        me.priority_streak = me.priority_streak.saturating_add(1);
    }
    Some(found)
}

/// Move one runnable thread from the busiest other processor to this one.
///
/// Stealing is what keeps per-CPU queues from becoming four independent
/// schedulers. Without it a core that has emptied its own queue runs its idle
/// thread next to another core's backlog. Interrupts must be masked.
fn steal(cpu: usize) {
    let Some(victim) = (0..MAX_CPUS)
        .filter(|&other| other != cpu)
        .max_by_key(|&other| QUEUED[other].load(Ordering::Relaxed))
        .filter(|&other| QUEUED[other].load(Ordering::Relaxed) > 0)
    else {
        return;
    };

    let (mut me, theirs) = lock_pair(cpu, victim);
    let Some(mut theirs) = theirs else {
        return;
    };
    // Someone else may have filled this queue or emptied theirs meanwhile.
    if QUEUED[cpu].load(Ordering::Relaxed) > 0 {
        return;
    }
    if let Some(slot) = pop_from(&mut theirs, victim, [2, 1, 0]) {
        // Both locks are held and the thread is on neither CPU.
        slot.owner.store(cpu, Ordering::Release);
        enqueue(&mut me, cpu, slot);
    }
}

/// Release the thread this processor switched away from: the switch is
/// complete, so it is safe both to run elsewhere and to free.
fn flush_pending(me: &mut Cpu, cpu: usize) {
    let Some(slot) = me.pending.take() else {
        return;
    };
    // SAFETY: the thread was `cpu`'s current, so `cpu` owns it; a thread that is
    // on a CPU is never moved. The caller holds `cpu`'s lock.
    let thread = unsafe { slot.get() };
    thread.on_cpu = false;

    let is_idle = me.idle.as_ref().is_some_and(|idle| Arc::ptr_eq(idle, &slot));
    match thread.state {
        // Back onto this processor's own queue: it just ran here, so this is the
        // core whose caches still hold its working set.
        State::Ready if !is_idle => enqueue(me, cpu, slot),
        State::Finished => {
            if let Some(stack) = thread.take_stack() {
                me.graveyard.push(stack);
            }
            me.reaped.push(slot.id);
        }
        _ => {}
    }
}

/// What a context switch needs, decided under the lock and acted on after it is
/// released.
struct Switch {
    save_to: *mut u64,
    load_from: u64,
    kernel_stack_top: u64,
    space: Option<crate::memory::paging::AddressSpace>,
}

fn prepare_switch(me: &mut Cpu, cpu: usize) -> Option<Switch> {
    let current = me.current.clone()?;
    let idle = me.idle.clone()?;

    let next = match pop_runnable(me, cpu) {
        Some(slot) => slot,
        None => {
            // Nobody else wants the CPU. Keep running rather than bouncing to
            // idle and straight back.
            // SAFETY: current on `cpu`, whose lock is held.
            let running = unsafe { current.get() }.state == State::Running;
            if !Arc::ptr_eq(&current, &idle) && running {
                renew_slice(cpu);
                return None;
            }
            idle
        }
    };

    if Arc::ptr_eq(&next, &current) {
        renew_slice(cpu);
        return None;
    }

    // Retire the outgoing thread. A thread that finished or blocked keeps that
    // state; only a still-running one becomes runnable again.
    // SAFETY: as above.
    let outgoing = unsafe { current.get() };
    if outgoing.state == State::Running {
        outgoing.state = State::Ready;
    }
    // The `Arc` in `pending` keeps this address alive through the switch.
    let save_to: *mut u64 = &mut outgoing.stack_pointer;

    // SAFETY: popped from `cpu`'s own queue, or its idle thread, so `cpu` owns it.
    let incoming = unsafe { next.get() };
    incoming.state = State::Running;
    // This CPU is committed to it from here, even though it does not actually
    // arrive until `context_switch`.
    incoming.on_cpu = true;
    let switch = Switch {
        save_to,
        load_from: incoming.stack_pointer,
        kernel_stack_top: incoming.kernel_stack_top,
        space: incoming.address_space,
    };

    // Held back, whatever its state; see `Cpu::pending`.
    me.pending = Some(current);
    CURRENT[cpu].store(next.id.0 + 1, Ordering::Release);
    me.current = Some(next);
    renew_slice(cpu);
    Some(switch)
}

/// Free what `flush_pending` set aside. Call with no scheduler lock held.
fn bury(stacks: Vec<KernelStack>, reaped: Vec<ThreadId>) {
    drop(stacks);
    if reaped.is_empty() {
        return;
    }
    let mut threads = THREADS.lock();
    for id in reaped {
        if let Some(entry) = threads.get_mut(id.0) {
            *entry = None;
        }
    }
}

/// Set up the scheduler around the context that is already running.
///
/// Must be called after the heap is up (thread control blocks and their stacks
/// are heap allocated) and before interrupts are enabled, so that no tick can
/// arrive mid-construction.
pub fn init() {
    without_interrupts(|| {
        if INITIALISED.load(Ordering::Acquire) {
            return;
        }

        // Thread 0 is whatever is executing right now, on the boot processor.
        let boot = new_slot(Thread::adopt_running(BOOT_THREAD, "boot"), 0);
        // The boot processor's idle thread. It has to be separate from the boot
        // thread: idle is by definition the last choice, so if the boot thread
        // were also idle, any CPU-bound worker would starve it permanently.
        let idle = new_slot(
            Thread::new(ThreadId(1), "idle", idle_loop, Priority::Low, trampoline),
            0,
        );

        *THREADS.lock() = alloc::vec![Some(boot.clone()), Some(idle.clone())];

        let mut me = CPUS[0].lock();
        me.current = Some(boot);
        me.idle = Some(idle);
        CURRENT[0].store(BOOT_THREAD.0 + 1, Ordering::Release);

        INITIALISED.store(true, Ordering::Release);
    });
}

fn new_slot(thread: Thread, owner: usize) -> ThreadRef {
    Arc::new(Slot {
        id: thread.id,
        name: thread.name,
        owner: AtomicUsize::new(owner),
        thread: UnsafeCell::new(thread),
    })
}

/// Register a processor that has just come up.
///
/// The context it is already running on becomes that CPU's idle thread, the
/// same way the boot thread was adopted rather than created.
pub fn adopt_secondary_cpu() {
    without_interrupts(|| {
        let cpu = cpu_index();
        if CPUS[cpu].lock().idle.is_some() {
            return;
        }

        let idle = {
            let mut threads = THREADS.lock();
            let id = ThreadId(threads.len());
            let slot = new_slot(Thread::adopt_running(id, "idle-ap"), cpu);
            threads.push(Some(slot.clone()));
            slot
        };

        let mut me = CPUS[cpu].lock();
        CURRENT[cpu].store(idle.id.0 + 1, Ordering::Release);
        me.current = Some(idle.clone());
        me.idle = Some(idle);
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
    if !INITIALISED.load(Ordering::Acquire) {
        return None;
    }

    without_interrupts(|| {
        // On the spawner's queue. A new thread has no cache footprint anywhere
        // yet, and the core that made it is as good a guess as any -- an idle
        // core will steal it within a switch if this one is busy.
        let cpu = cpu_index();
        let slot = {
            let mut threads = THREADS.lock();
            let id = ThreadId(threads.len());
            let slot = new_slot(Thread::new(id, name, entry, priority, trampoline), cpu);
            threads.push(Some(slot.clone()));
            slot
        };
        let id = slot.id;
        enqueue(&mut CPUS[cpu].lock(), cpu, slot);
        Some(id)
    })
}

/// Run `f` on a thread's scheduling state under its owner's lock, or return
/// `None` if the thread is gone.
fn with_thread<R>(id: ThreadId, f: impl FnOnce(&mut Thread) -> R) -> Option<R> {
    let slot = lookup(id)?;
    without_interrupts(|| {
        let _owner = lock_owner(&slot);
        // SAFETY: the owner's lock is held for the life of the reference.
        Some(f(unsafe { slot.get() }))
    })
}

/// Run `f` on the current thread under this processor's lock.
fn with_current<R>(f: impl FnOnce(&mut Thread, &ThreadRef) -> R) -> Option<R> {
    without_interrupts(|| {
        let cpu = cpu_index();
        let me = CPUS[cpu].lock();
        let current = me.current.clone()?;
        // SAFETY: the current thread is owned by this processor, whose lock is
        // held for the life of the reference.
        Some(f(unsafe { current.get() }, &current))
    })
}

/// Change a thread's priority.
///
/// Takes effect at its next switch: a thread already in a queue stays there
/// until it is picked up, and is filed by its new priority when it next goes
/// back. The delay is at most one quantum.
pub fn set_priority(id: ThreadId, priority: Priority) {
    with_thread(id, |thread| thread.priority = priority);
}

/// A thread's priority, if it still exists.
pub fn priority_of(id: ThreadId) -> Option<Priority> {
    with_thread(id, |thread| thread.priority)
}

/// Hand the CPU to the next runnable thread, if there is one.
pub fn schedule() {
    without_interrupts(|| {
        if !INITIALISED.load(Ordering::Acquire) {
            return;
        }
        let cpu = cpu_index();

        if QUEUED[cpu].load(Ordering::Relaxed) == 0 {
            steal(cpu);
        }

        let (switch, stacks, reaped) = {
            let mut me = CPUS[cpu].lock();
            flush_pending(&mut me, cpu);
            let switch = prepare_switch(&mut me, cpu);
            (
                switch,
                core::mem::take(&mut me.graveyard),
                core::mem::take(&mut me.reaped),
            )
        };

        // Outside the lock: this unmaps stacks, returns frames and may broadcast
        // a shootdown, none of which may happen underneath it.
        bury(stacks, reaped);

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

        // SAFETY: `save_to` points into the outgoing thread's control block,
        // which `pending` keeps alive, and nothing else writes it: the thread is
        // on this CPU, so no other processor may take it.
        unsafe { context::context_switch(switch.save_to, switch.load_from) };

        // Reached as the *incoming* thread. The thread this processor switched
        // away from now has its registers saved, so it can safely be offered to
        // another CPU.
        let cpu = cpu_index();
        flush_pending(&mut CPUS[cpu].lock(), cpu);
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
    let parked = with_current(|thread, _| {
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
///
/// The thread moves to the waker's processor, which is usually the one it will
/// talk to next -- unless a processor is still standing on its stack, in which
/// case it stays put and `flush_pending` queues it when the switch completes.
pub fn unblock(id: ThreadId) {
    let Some(slot) = lookup(id) else {
        return;
    };

    without_interrupts(|| {
        let waker = cpu_index();
        loop {
            let owner = slot.owner.load(Ordering::Acquire);
            let (mut here, there) = lock_pair(waker, owner);
            if slot.owner.load(Ordering::Acquire) != owner {
                continue;
            }

            // SAFETY: the owner's lock is one of the two held.
            let thread = unsafe { slot.get() };
            if thread.state != State::Blocked {
                // Not parked yet. It registered with its waker, released that
                // lock and has not reached `block_current` -- a window this
                // cannot close by waiting, because the thread is on another
                // processor. Leaving now would drop the wake and park it
                // forever, so it is recorded and the thread's own attempt to
                // block consumes it. A finished thread is not going to block.
                if thread.state != State::Finished {
                    thread.wake_pending = true;
                }
                return;
            }
            thread.state = State::Ready;

            // A wake can land while the thread is still leaving its processor:
            // it set itself Blocked, and the CPU running it has released the
            // lock but not yet reached `context_switch`. Queueing it here would
            // let another core resume it from a saved stack pointer that has not
            // been written yet. `flush_pending` queues it once the switch is
            // genuinely done.
            if !thread.on_cpu {
                slot.owner.store(waker, Ordering::Release);
                enqueue(&mut here, waker, slot.clone());
            }
            drop(there);
            return;
        }
    });
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

    let parked = with_current(|thread, slot| {
        let deadline = crate::time::ticks().saturating_add(ticks);
        // Parked before it is listed, both under this processor's lock, so a
        // wake cannot find it listed and still running.
        thread.wake_pending = false;
        thread.state = State::Blocked;
        SLEEPERS.lock().push((slot.id, deadline));

        // Only ever moved earlier here: an existing sooner deadline must not be
        // pushed back.
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

/// Wake every sleeper whose deadline has passed, and republish the next one.
fn wake_due_sleepers(now: u64) {
    let due = without_interrupts(|| {
        let mut sleepers = SLEEPERS.lock();
        let mut due = Vec::new();
        let mut earliest = u64::MAX;
        sleepers.retain(|&(id, deadline)| {
            if deadline <= now {
                due.push(id);
                false
            } else {
                earliest = earliest.min(deadline);
                true
            }
        });
        // Under the list's lock, which a sleeper adding itself also takes, so an
        // earlier deadline published concurrently cannot be erased.
        NEXT_WAKE.store(earliest, Ordering::Release);
        due
    });

    for id in due {
        unblock(id);
    }
}

/// Wait until `id` has finished. Returns immediately if it already has, or if
/// no such thread exists.
///
/// Registration and the block happen under the locks of both threads' owners,
/// which is what makes this safe against the thread finishing in between:
/// `exit_current` takes the joiner list under its own owner's lock, so it either
/// sees this waiter and wakes it, or has already finished and this returns
/// without parking.
///
/// Joining oneself would park forever and is refused.
pub fn join(id: ThreadId) {
    let Some(target) = lookup(id) else {
        return;
    };

    let parked = without_interrupts(|| {
        let cpu = cpu_index();
        let Some(me) = CPUS[cpu].lock().current.clone() else {
            return false;
        };
        if Arc::ptr_eq(&me, &target) {
            return false;
        }

        loop {
            let owner = target.owner.load(Ordering::Acquire);
            let _locks = lock_pair(cpu, owner);
            if target.owner.load(Ordering::Acquire) != owner {
                continue;
            }

            // SAFETY: the target's owner's lock is held.
            let waited_for = unsafe { target.get() };
            if waited_for.state == State::Finished {
                return false;
            }
            waited_for.joiners.push(me.id);

            // SAFETY: `me` is current here, so owned by `cpu`, whose lock is held.
            let waiter = unsafe { me.get() };
            waiter.wake_pending = false;
            waiter.state = State::Blocked;
            return true;
        }
    });

    if parked {
        schedule();
    }
}

/// End the current thread. Its stack is freed by a later `schedule()`, once the
/// switch away from it has completed.
pub fn exit_current() -> ! {
    let id = current_id().expect("exit_current outside a thread");

    // Release resources while the thread is still running and holds no
    // scheduler lock. Freeing memory from inside the scheduler would take the
    // allocator's lock underneath a processor's.
    crate::release_thread_resources(id);

    without_interrupts(|| {
        // Finished and the joiner list taken in one acquisition, so a `join`
        // either got onto the list first or sees `Finished` and does not park.
        let joiners = with_current(|thread, _| {
            thread.state = State::Finished;
            core::mem::take(&mut thread.joiners)
        })
        .unwrap_or_default();

        // After the lock, because waking takes other processors' locks -- but
        // with interrupts still masked. A tick in between would switch this
        // thread away for good, and the wakes would never be sent.
        for joiner in joiners {
            unblock(joiner);
        }

        schedule();
    });

    unreachable!("a finished thread was scheduled again")
}

/// Called from the timer interrupt. Charges this CPU's thread a tick and
/// preempts it when its slice runs out.
pub fn on_timer_tick() {
    let cpu = cpu_index();
    let now = crate::time::ticks();

    // Neither of these touches a lock. This runs on every core on every tick,
    // and both answers are almost always "no".
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
        wake_due_sleepers(now);
    }

    if slice_expired {
        schedule();
    }
}

pub fn is_initialised() -> bool {
    INITIALISED.load(Ordering::Acquire)
}

pub fn current_id() -> Option<ThreadId> {
    without_interrupts(|| match CURRENT[cpu_index()].load(Ordering::Acquire) {
        0 => None,
        biased => Some(ThreadId(biased - 1)),
    })
}

pub fn current_name() -> Option<&'static str> {
    with_current(|_, slot| slot.name)
}

/// [`current_name`], but `None` rather than waiting for this processor's lock.
/// For the panic path, which may have been reached from inside the scheduler.
pub fn try_current_name() -> Option<&'static str> {
    let me = CPUS[cpu_index()].try_lock()?;
    me.current.as_ref().map(|slot| slot.name)
}

/// Threads that exist and have not been reaped.
pub fn live_thread_count() -> usize {
    without_interrupts(|| THREADS.lock().iter().filter(|slot| slot.is_some()).count())
}

/// Give a thread its own page tables.
pub fn set_address_space(id: ThreadId, space: crate::memory::paging::AddressSpace) {
    with_thread(id, |thread| thread.address_space = Some(space));
}

/// Detach a thread's page tables from it, so no later switch to the thread
/// loads them. The first step in freeing them.
pub fn take_address_space(id: ThreadId) -> Option<crate::memory::paging::AddressSpace> {
    with_thread(id, |thread| thread.address_space.take()).flatten()
}

/// A thread's page tables, if it has its own.
pub fn address_space_of(id: ThreadId) -> Option<crate::memory::paging::AddressSpace> {
    with_thread(id, |thread| thread.address_space).flatten()
}

/// Top of the current thread's kernel stack, or 0 for a thread that owns none.
pub fn current_kernel_stack_top() -> u64 {
    with_current(|thread, _| thread.kernel_stack_top).unwrap_or(0)
}

/// The unmapped page below a thread's stack, and its lowest mapped address.
///
/// Diagnostic, and used by the test that checks the guard is really there.
pub fn stack_bounds_of(id: ThreadId) -> Option<(u64, u64)> {
    with_thread(id, |thread| Some((thread.guard_page()?, thread.stack_bottom()?))).flatten()
}

/// Whether a thread still exists. False once it has finished and been reaped.
pub fn is_alive(id: ThreadId) -> bool {
    lookup(id).is_some()
}

/// Whether a thread is currently blocked. Diagnostic, and used by tests.
pub fn is_blocked(id: ThreadId) -> bool {
    with_thread(id, |thread| thread.state == State::Blocked).unwrap_or(false)
}

/// Where every new thread begins.
///
/// Reached by the `ret` at the end of `context_switch`, not by a call, which is
/// why it takes no arguments -- the switch zeroes the register file on the way
/// in. The entry point is fetched from the thread control block instead.
unsafe extern "C" fn trampoline() -> ! {
    // Whatever this processor switched away from can now be handed on. The
    // entry point is read under the same lock, with interrupts still disabled
    // from the switch.
    let entry = {
        let cpu = cpu_index();
        let mut me = CPUS[cpu].lock();
        flush_pending(&mut me, cpu);
        // SAFETY: the current thread is owned by this processor, whose lock is
        // held.
        me.current.as_ref().and_then(|slot| unsafe { slot.get() }.entry)
    };

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
