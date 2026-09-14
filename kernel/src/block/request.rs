//! How many requests a disk has in flight, and what each one waits on.
//!
//! A disk has a fixed number of request slots, each with DMA memory of its own,
//! so requests on different slots go to the device together. A request takes a
//! slot, hands the device its command, and waits for the answer: asleep until
//! the device's interrupt says it is done, where the caller may sleep, and
//! polling where it may not -- during boot, with a spinning lock held, and on
//! the panic path. See [`crate::sync::can_sleep`].

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};

use super::BlockError;
use crate::sched::{self, ThreadId};
use crate::sync::{can_sleep, without_interrupts, Mutex};

/// Bound on a polled wait. Long enough for a real disk to answer a flush.
const TIMEOUT_SPINS: u64 = 200_000_000;

const IDLE: u8 = 0;
const IN_FLIGHT: u8 = 1;
const DONE: u8 = 2;
const FAULT: u8 = 3;

/// One slot's answer.
pub struct Completion {
    state: AtomicU8,
    /// The thread asleep on it, plus one; zero for none.
    waiter: AtomicUsize,
}

impl Default for Completion {
    fn default() -> Self {
        Self { state: AtomicU8::new(IDLE), waiter: AtomicUsize::new(0) }
    }
}

impl Completion {
    /// About to hand the device a command on this slot.
    pub fn arm(&self) {
        self.state.store(IN_FLIGHT, Ordering::Release);
    }

    /// The device has answered. Called by whoever drains its completions: the
    /// interrupt handler, or a polling waiter.
    pub fn finish(&self, ok: bool) {
        self.state.store(if ok { DONE } else { FAULT }, Ordering::Release);
        let waiter = self.waiter.swap(0, Ordering::AcqRel);
        if waiter != 0 {
            sched::unblock(ThreadId(waiter - 1));
        }
    }

    /// Handed to the device and not yet answered.
    pub fn in_flight(&self) -> bool {
        self.state.load(Ordering::Acquire) == IN_FLIGHT
    }

    fn outcome(&self) -> Option<Result<(), BlockError>> {
        match self.state.load(Ordering::Acquire) {
            DONE => Some(Ok(())),
            FAULT => Some(Err(BlockError::DeviceFault)),
            _ => None,
        }
    }

    /// Wait for the answer. `interrupts` says whether the device will announce
    /// it; `service` drains the device's completions by hand.
    ///
    /// A polled wait that times out returns `DeviceFault` with the command still
    /// in the device's hands, and the caller must not reuse the slot: its memory
    /// may yet be written.
    pub fn wait(&self, interrupts: bool, service: &dyn Fn()) -> Result<(), BlockError> {
        if interrupts && can_sleep() {
            if let Some(me) = sched::current_id() {
                loop {
                    if let Some(outcome) = self.outcome() {
                        return outcome;
                    }
                    // Registered, then checked again: an answer landing in
                    // between is seen here, and one landing after finds the
                    // waiter and wakes it -- early, if it has not parked yet,
                    // which `block_current` records rather than loses.
                    self.waiter.store(me.0 + 1, Ordering::Release);
                    if let Some(outcome) = self.outcome() {
                        self.waiter.store(0, Ordering::Release);
                        return outcome;
                    }
                    sched::block_current();
                }
            }
        }

        for _ in 0..TIMEOUT_SPINS {
            service();
            if let Some(outcome) = self.outcome() {
                return outcome;
            }
            core::hint::spin_loop();
        }
        Err(BlockError::DeviceFault)
    }
}

struct Taken {
    busy: u32,
    /// Callers waiting to take every slot. While there are any, single slots
    /// are not handed out, or a steady stream of requests would keep an
    /// exclusive one waiting forever.
    exclusive_waiting: usize,
    waiters: Vec<ThreadId>,
}

/// A disk's request slots.
pub struct Slots {
    count: usize,
    taken: Mutex<Taken>,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    /// Completions the interrupt delivered.
    pub interrupt_completions: AtomicU64,
}

impl Slots {
    pub fn new(count: usize) -> Self {
        assert!((1..=32).contains(&count));
        Self {
            count,
            taken: Mutex::new(Taken { busy: 0, exclusive_waiting: 0, waiters: Vec::new() }),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            interrupt_completions: AtomicU64::new(0),
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }

    fn all(&self) -> u32 {
        (u64::MAX >> (64 - self.count)) as u32
    }

    /// A free slot, waiting for one if need be. `None` only when waiting is
    /// not allowed: on the panic path, with every slot taken.
    pub fn take(&self, service: &dyn Fn()) -> Option<usize> {
        self.acquire(false, service).map(|busy| busy.trailing_zeros() as usize)
    }

    /// Every slot at once, for a command the device runs only alone.
    pub fn take_all(&self, service: &dyn Fn()) -> Option<()> {
        self.acquire(true, service).map(|_| ())
    }

    /// Returns the bits it took.
    fn acquire(&self, exclusive: bool, service: &dyn Fn()) -> Option<u32> {
        let mut queued_exclusive = false;
        loop {
            let sleep = can_sleep().then(sched::current_id).flatten();
            let claimed = without_interrupts(|| {
                let mut taken = self.taken.lock();
                let claim = if exclusive {
                    (taken.busy == 0).then(|| self.all())
                } else {
                    let free = !taken.busy & self.all();
                    (free != 0 && taken.exclusive_waiting == 0).then(|| free & free.wrapping_neg())
                };
                if let Some(bits) = claim {
                    taken.busy |= bits;
                    if queued_exclusive {
                        taken.exclusive_waiting -= 1;
                    }
                    return Some(bits);
                }
                if let Some(me) = sleep {
                    if exclusive && !queued_exclusive {
                        taken.exclusive_waiting += 1;
                        queued_exclusive = true;
                    }
                    taken.waiters.push(me);
                }
                None
            });
            if let Some(bits) = claimed {
                // Requests, not slots: a command that takes every slot is one.
                let now = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                self.peak.fetch_max(now, Ordering::AcqRel);
                return Some(bits);
            }
            match sleep {
                Some(_) => {
                    sched::block_current();
                }
                None if crate::crash::is_panicking() => return None,
                // Nobody to wake this, so make the progress that would.
                None => {
                    service();
                    core::hint::spin_loop();
                }
            }
        }
    }

    pub fn give(&self, slot: usize) {
        self.release(1 << slot);
    }

    pub fn give_all(&self) {
        self.release(self.all());
    }

    fn release(&self, bits: u32) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        let waiters = without_interrupts(|| {
            let mut taken = self.taken.lock();
            taken.busy &= !bits;
            core::mem::take(&mut taken.waiters)
        });
        // Everyone waiting tries again; there are never more than a handful.
        for waiter in waiters {
            sched::unblock(waiter);
        }
    }

    /// The most requests that have been in flight at once.
    ///
    /// A slot whose completion never arrives (a polled wait timing out) is
    /// never given back -- reusing it would hand the device a buffer it might
    /// still be writing -- so it stays counted here too. That is not drift:
    /// the request truly never resolved, and the count can never exceed
    /// [`Self::count`], since a stuck slot can never be acquired again either.
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Acquire)
    }
}
