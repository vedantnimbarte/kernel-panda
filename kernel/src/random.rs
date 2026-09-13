//! Random bytes, for what must not be guessed: password salts, TCP sequence
//! numbers, DNS query ids.
//!
//! The processor's own generator seeds a SHA-256 construction, and is mixed in
//! again on every request. Each request ends by replacing the key with a hash
//! of itself, so the state left behind cannot recompute what was handed out.
//!
//! Without RDRAND or RDSEED the seed comes from timing jitter instead, which is
//! better than nothing and much worse than hardware. Boot says so.

use core::arch::x86_64::{__cpuid, __cpuid_count, _rdrand64_step, _rdseed64_step, _rdtsc};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sha256::Sha256;
use crate::sync::{without_interrupts, Mutex, Once};
use crate::syscall::{Error, SyscallResult};

struct Generator {
    key: [u8; 32],
    counter: u64,
}

static GENERATOR: Once<Mutex<Generator>> = Once::new();
static WARNED: AtomicBool = AtomicBool::new(false);

/// Largest single request from Ring 3.
const MAX_REQUEST: u64 = 4096;

/// Whether the processor has a generator of its own.
pub fn has_hardware_source() -> bool {
    has_rdrand() || has_rdseed()
}

fn has_rdrand() -> bool {
    __cpuid(1).ecx & (1 << 30) != 0
}

fn has_rdseed() -> bool {
    // Leaf 0 reports the highest leaf, so leaf 7 is only read if it exists.
    __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0
}

/// One word from the processor, if it has a generator and it delivers. Both
/// instructions may come back empty-handed briefly; Intel's guidance is ten
/// tries before concluding something is wrong.
fn hardware_word() -> Option<u64> {
    let (seed, rand) = (has_rdseed(), has_rdrand());
    let mut word = 0;
    for _ in 0..10 {
        // SAFETY: each instruction is used only where CPUID reports it.
        let got = unsafe { (seed && rdseed(&mut word)) || (rand && rdrand(&mut word)) };
        if got {
            return Some(word);
        }
    }
    None
}

#[target_feature(enable = "rdseed")]
unsafe fn rdseed(word: &mut u64) -> bool {
    _rdseed64_step(word) == 1
}

#[target_feature(enable = "rdrand")]
unsafe fn rdrand(word: &mut u64) -> bool {
    _rdrand64_step(word) == 1
}

fn seed() -> [u8; 32] {
    let mut hash = Sha256::default();
    let words = (0..32).filter_map(|_| hardware_word()).inspect(|word| hash.update(&word.to_le_bytes())).count();
    if words < 32 {
        if !WARNED.swap(true, Ordering::AcqRel) {
            crate::println!("random: no hardware generator; seeding from timing, which is guessable");
        }
        // How long a little work takes wobbles with caches, interrupts and the
        // host underneath. Some of that wobble is unpredictable; hash plenty.
        for round in 0..4096u64 {
            // SAFETY: RDTSC is available on every x86_64 processor.
            let before = unsafe { _rdtsc() };
            let mut spin = before ^ round;
            for _ in 0..(before & 0xFF) {
                spin = spin.rotate_left(7) ^ round;
            }
            // SAFETY: as above.
            hash.update(&(unsafe { _rdtsc() }.wrapping_sub(before) ^ spin).to_le_bytes());
        }
    }
    hash.update(&crate::time::ticks().to_le_bytes());
    hash.finish()
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::default();
    for part in parts {
        hash.update(part);
    }
    hash.finish()
}

/// Fill `out` with random bytes.
pub fn fill(out: &mut [u8]) {
    let generator = GENERATOR.call_once(|| Mutex::new(Generator { key: seed(), counter: 0 }));
    without_interrupts(|| {
        let mut state = generator.lock();
        // Fresh input every time, so that even a key read out of memory stops
        // predicting what comes next.
        if let Some(word) = hardware_word() {
            state.key = hash_parts(&[&state.key, b"mix", &word.to_le_bytes()]);
        }
        for chunk in out.chunks_mut(32) {
            let block = hash_parts(&[&state.key, b"out", &state.counter.to_le_bytes()]);
            state.counter += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        state.key = hash_parts(&[&state.key, b"key", &state.counter.to_le_bytes()]);
    });
}

pub fn u64() -> u64 {
    let mut bytes = [0u8; 8];
    fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// Fill a user buffer with random bytes.
pub fn sys_fill(buffer: u64, length: u64) -> SyscallResult {
    if length > MAX_REQUEST {
        return Err(Error::InvalidArgument);
    }
    if !crate::userspace::validate_user_buffer(buffer, length, true) {
        return Err(Error::BadPointer);
    }
    let mut bytes = [0u8; MAX_REQUEST as usize];
    let bytes = &mut bytes[..length as usize];
    fill(bytes);
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: validated as present, user-accessible and writable for
        // `length` bytes, and the guard lets Ring 0 reach it.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len()) };
    });
    Ok(length as i64)
}
