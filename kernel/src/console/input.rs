//! Serial input, and the `read` syscall on top of it.
//!
//! Bytes are drained from the UART by the timer handler rather than by a
//! receive interrupt. Routing IRQ 4 to the CPU would mean programming the
//! IOAPIC, and finding the IOAPIC properly means parsing ACPI -- a lot of
//! machinery for a console. Polling at the 100 Hz tick adds up to 10 ms of
//! latency, which is imperceptible against a human typing and well inside the
//! UART's 16-byte FIFO at 38400 baud.
//!
//! It is the wrong answer for a serial line carrying data at speed, and the
//! right one for the only thing using it today.

use alloc::collections::VecDeque;

use crate::sched::{self, ThreadId};
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::Error;
use crate::userspace;

/// Bytes buffered before input is dropped. Far more than a person can type
/// between two timer ticks.
const CAPACITY: usize = 256;

struct Input {
    bytes: VecDeque<u8>,
    /// Threads parked in `read`, oldest first.
    waiting: VecDeque<ThreadId>,
    /// Bytes lost to a full buffer, so the loss is at least visible.
    dropped: u64,
}

static INPUT: Mutex<Option<Input>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Input) -> R) -> R {
    without_interrupts(|| {
        let mut guard = INPUT.lock();
        f(guard.get_or_insert_with(|| Input {
            bytes: VecDeque::new(),
            waiting: VecDeque::new(),
            dropped: 0,
        }))
    })
}

/// Move anything the UART has received into the buffer and wake one reader.
///
/// Called from the timer interrupt, so it must not block or allocate
/// unboundedly -- the queue is capped and overflow is counted rather than grown.
pub fn poll() {
    let mut received = 0;

    with(|input| {
        received = super::uart::drain_input(|byte| {
            if input.bytes.len() >= CAPACITY {
                input.dropped += 1;
            } else {
                input.bytes.push_back(byte);
            }
        });
    });

    if received == 0 {
        return;
    }

    // Wake outside the input lock: unblocking takes the scheduler lock, and
    // taking the two in opposite orders in different places is how deadlocks
    // are built.
    let woken = with(|input| input.waiting.pop_front());
    if let Some(thread) = woken {
        sched::unblock(thread);
    }
}

/// Bytes waiting to be read.
pub fn available() -> usize {
    with(|input| input.bytes.len())
}

/// Bytes lost to buffer overflow since boot.
pub fn dropped() -> u64 {
    with(|input| input.dropped)
}

/// Push a byte as though the UART had received it. Test support.
pub fn inject(byte: u8) {
    with(|input| {
        if input.bytes.len() < CAPACITY {
            input.bytes.push_back(byte);
        }
    });

    let woken = with(|input| input.waiting.pop_front());
    if let Some(thread) = woken {
        sched::unblock(thread);
    }
}

/// Read up to `limit` bytes, blocking until at least one is available.
pub fn read(reader: ThreadId, limit: usize, mut sink: impl FnMut(u8)) -> usize {
    loop {
        let taken = with(|input| {
            let count = input.bytes.len().min(limit);
            for _ in 0..count {
                if let Some(byte) = input.bytes.pop_front() {
                    sink(byte);
                }
            }
            if count == 0 {
                // Register before dropping the lock, so a byte arriving
                // immediately afterwards cannot find an empty waiter list.
                input.waiting.push_back(reader);
            }
            count
        });

        if taken > 0 {
            return taken;
        }
        sched::block_current();
    }
}

pub fn sys_read(descriptor: u64, pointer: u64, length: u64) -> Result<i64, Error> {
    // Only the console exists.
    if descriptor != 0 {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Ok(0);
    }
    if length > 4096 {
        return Err(Error::InvalidArgument);
    }
    if !userspace::validate_user_buffer(pointer, length, true) {
        return Err(Error::BadPointer);
    }

    let reader = sched::current_id().ok_or(Error::InvalidArgument)?;
    let mut offset = 0u64;

    let count = read(reader, length as usize, |byte| {
        // SAFETY: the whole range was validated as present, user-accessible and
        // writable, and `offset` never exceeds `length` because `read` is
        // capped at the same limit.
        unsafe { core::ptr::write_volatile((pointer + offset) as *mut u8, byte) };
        offset += 1;
    });

    // No re-validation after the fact: the writes have already happened, so a
    // check here would prove nothing. The pre-check is the real one, and it
    // holds because user mappings are never torn down while their thread lives.
    // That stops being true the moment buffers become unmappable, and this
    // becomes a validate-inside-the-loop.
    Ok(count as i64)
}
