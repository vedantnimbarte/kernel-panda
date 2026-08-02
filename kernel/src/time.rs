//! Wall-clock-ish time, counted in timer interrupts.
//!
//! This is the kernel's only sense of elapsed time until Phase 3 brings a
//! scheduler. It is deliberately just a counter: no calendar, no wall clock, no
//! RTC. Those need hardware the microkernel should be talking to from Ring 3.

use core::sync::atomic::{AtomicU64, Ordering};

static TICKS: AtomicU64 = AtomicU64::new(0);
static FREQUENCY_HZ: AtomicU64 = AtomicU64::new(0);

/// Timer interrupts each processor has taken.
///
/// Every core has its own APIC timer, so this is the honest per-CPU count --
/// [`TICKS`] is the clock, and only one processor is allowed to advance it.
/// Keeping both makes the difference between them visible instead of implicit.
static CPU_TICKS: [AtomicU64; crate::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::smp::MAX_CPUS];

/// Record a timer interrupt on `cpu`, advancing the clock if it is the one
/// keeping it. Called from the timer interrupt handler and nowhere else.
///
/// `Relaxed` is sufficient: nothing orders other memory against these counters,
/// readers only ever want a recent value, and the handler must stay cheap
/// because it runs on every tick.
pub fn tick(cpu: usize) {
    if let Some(counter) = CPU_TICKS.get(cpu) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    // One processor keeps the clock. Counting on all of them would make "ticks
    // since boot" mean "ticks since boot, times the number of cores": uptime ran
    // at four times real speed on a four-core machine, and any duration measured
    // in ticks was short by the same factor.
    if cpu == 0 {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Timer interrupts taken by one processor.
pub fn cpu_ticks(cpu: usize) -> u64 {
    CPU_TICKS
        .get(cpu)
        .map_or(0, |counter| counter.load(Ordering::Relaxed))
}

/// Timer interrupts since boot.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Record the measured tick rate. Called once, after the APIC timer is
/// calibrated.
pub fn set_frequency(hz: u64) {
    FREQUENCY_HZ.store(hz, Ordering::Relaxed);
}

/// Timer interrupts per second, or 0 before the timer is running.
pub fn frequency_hz() -> u64 {
    FREQUENCY_HZ.load(Ordering::Relaxed)
}

/// Milliseconds since boot, or 0 if the timer has not started.
pub fn uptime_ms() -> u64 {
    match frequency_hz() {
        0 => 0,
        hz => ticks().saturating_mul(1000) / hz,
    }
}
