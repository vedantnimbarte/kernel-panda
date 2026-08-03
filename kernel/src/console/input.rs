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

impl Input {
    fn new() -> Self {
        Self {
            bytes: VecDeque::new(),
            waiting: VecDeque::new(),
            dropped: 0,
        }
    }
}

static INPUT: Mutex<Option<Input>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Input) -> R) -> R {
    without_interrupts(|| {
        let mut guard = INPUT.lock();
        f(guard.get_or_insert_with(Input::new))
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
        // Masking interrupts closes this window on one processor and not on
        // four: a byte arriving on another core pops this thread off the waiter
        // list and calls `unblock` while it is still `Running`. That used to
        // drop the wake and leave the thread parked with nothing left to wake
        // it -- roughly one console read in five, which presented as a shell
        // that stopped responding. `block_current` now records such a wake and
        // returns `false` instead of parking, and the loop goes back to look.
        let taken = without_interrupts(|| {
            let count = {
                let mut guard = INPUT.lock();
                let input = guard.get_or_insert_with(Input::new);

                let count = input.bytes.len().min(limit);
                for _ in 0..count {
                    if let Some(byte) = input.bytes.pop_front() {
                        sink(byte);
                    }
                }
                if count == 0 && !input.waiting.contains(&reader) {
                    input.waiting.push_back(reader);
                }
                count
            };

            if count == 0 {
                let _ = sched::block_current();
            }
            count
        });

        if taken > 0 {
            return taken;
        }
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

    // Bytes land in a kernel buffer first and are handed over in one copy
    // afterwards. Writing straight into user memory from the sink would put a
    // fallible access inside the `INPUT` lock, where a fault has nowhere to go,
    // and it would have to open an SMAP window per byte. A short call returning
    // fewer bytes than asked for is exactly what `read` already means.
    const CHUNK: usize = 256;
    let mut buffer = [0u8; CHUNK];
    let mut filled = 0usize;

    let count = read(reader, (length as usize).min(CHUNK), |byte| {
        buffer[filled] = byte;
        filled += 1;
    });

    // No re-validation after the fact: the pre-check is the real one, and it
    // holds because user mappings are never torn down while their thread lives.
    // That stops being true the moment buffers become unmappable, and this
    // becomes a validate-inside-the-loop.
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: the whole range was validated as present, user-accessible and
        // writable; `count` is at most `CHUNK` and at most `length`; and the
        // guard lets Ring 0 reach the destination.
        unsafe { core::ptr::copy_nonoverlapping(buffer.as_ptr(), pointer as *mut u8, count) };
    });

    Ok(count as i64)
}
