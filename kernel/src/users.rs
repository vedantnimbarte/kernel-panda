//! Who a process is.
//!
//! Capabilities decide what a process can reach; this decides who it is, so that
//! things a process leaves behind -- files, above all -- can say who made them
//! and who else may touch them.
//!
//! A user is a number. A thread starts as the user of whoever spawned it, and
//! only two things say otherwise: kernel code starting a program as someone, and
//! logging in, which takes the account's password. Nothing else changes a
//! thread's user, so a process cannot promote itself, nor impersonate another
//! without knowing what that user knows.
//!
//! There is no superuser. User 0 is the system's own user: it owns what the
//! system creates, and it is held to the same permission bits as everyone else.
//! What the system can do beyond that comes from capabilities it was given, not
//! from a number that bypasses every check.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::fs::{FsError, NodeKind};
use crate::sched::{self, ThreadId};
use crate::sha256;
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::SyscallResult;

pub type UserId = u32;

/// The system's own user. Owner of what the boot creates; not privileged.
pub const SYSTEM: UserId = 0;

/// Users of threads that are not the system's. Absent means `SYSTEM`, which is
/// every thread the kernel starts on its own account.
static USERS: Mutex<BTreeMap<usize, UserId>> = Mutex::new(BTreeMap::new());

/// The user a thread runs as.
pub fn of(thread: ThreadId) -> UserId {
    without_interrupts(|| USERS.lock().get(&thread.0).copied().unwrap_or(SYSTEM))
}

/// Run `thread` as `user`. Kernel-facing only; see the module notes. A thread
/// being started as someone should be started with `sched::spawn_as`, which
/// leaves no moment in which it runs as its spawner.
pub fn assign(thread: ThreadId, user: UserId) {
    without_interrupts(|| {
        let mut users = USERS.lock();
        if user == SYSTEM {
            users.remove(&thread.0);
        } else {
            users.insert(thread.0, user);
        }
    });
}

/// A new thread takes its spawner's user.
pub fn inherit(parent: Option<ThreadId>, child: ThreadId) {
    if let Some(parent) = parent {
        assign(child, of(parent));
    }
}

/// Forget a thread when it exits.
pub fn release_thread(thread: ThreadId) {
    without_interrupts(|| USERS.lock().remove(&thread.0));
}

/// The caller's user.
pub fn sys_current() -> SyscallResult {
    Ok(sched::current_id().map_or(SYSTEM, of) as i64)
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

/// The account database: a line per account, `name:user:salt:hash`, the last
/// two in hex. The hash is PBKDF2-HMAC-SHA-256 of the password.
pub const DATABASE: &str = "/users";

/// Owns the database, which it keeps with every permission bit clear. No thread
/// runs as this user and no account may be it, so no process reads the hashes
/// or changes the bits; the kernel reads it on its own account.
pub const ACCOUNTS: UserId = UserId::MAX;

/// PBKDF2 rounds per password: what each guess costs someone holding a copy of
/// the database.
const ITERATIONS: u32 = 10_000;

/// What each wrong guess costs someone who does not.
const FAILURE_DELAY_MS: u64 = 500;

pub const MAX_NAME: usize = 32;
pub const MAX_PASSWORD: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    NoFileSystem,
    /// Empty, too long, or not letters, digits, `_` and `-`.
    BadName,
    /// Empty or too long.
    BadPassword,
    /// The name or the user already has an account, or the user is `ACCOUNTS`.
    Exists,
    /// The name, the password, or both are wrong. Which is not said.
    Incorrect,
    Fs(FsError),
}

impl From<FsError> for AccountError {
    fn from(error: FsError) -> Self {
        AccountError::Fs(error)
    }
}

struct Account<'a> {
    name: &'a str,
    user: UserId,
    salt: [u8; 16],
    hash: [u8; 32],
}

fn accounts(database: &[u8]) -> impl Iterator<Item = Account<'_>> {
    core::str::from_utf8(database).unwrap_or("").lines().filter_map(|line| {
        let mut fields = line.split(':');
        let account = Account {
            name: fields.next()?,
            user: fields.next()?.parse().ok()?,
            salt: unhex(fields.next()?)?,
            hash: unhex(fields.next()?)?,
        };
        fields.next().is_none().then_some(account)
    })
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    if text.len() != 2 * N {
        return None;
    }
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// Unique per account, which is all a salt has to be. There is no entropy
/// source to make it unpredictable as well; uniqueness is what stops one
/// precomputed table from serving every account.
fn new_salt(name: &str) -> [u8; 16] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hash = sha256::Sha256::default();
    // SAFETY: RDTSC is available on every x86_64 processor.
    hash.update(&unsafe { core::arch::x86_64::_rdtsc() }.to_le_bytes());
    hash.update(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hash.update(name.as_bytes());
    hash.finish()[..16].try_into().unwrap()
}

/// Add an account to the root filesystem's database, creating the database if
/// this is the first.
///
/// Kernel-facing: there is no system call for it. Read, append, write back --
/// ponytail: two adds at once can lose one; serialise them if accounts are ever
/// created by more than one thread.
pub fn add_account(name: &str, user: UserId, password: &str) -> Result<(), AccountError> {
    let valid_name = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    if name.is_empty() || name.len() > MAX_NAME || !name.chars().all(valid_name) {
        return Err(AccountError::BadName);
    }
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err(AccountError::BadPassword);
    }
    if user == ACCOUNTS {
        return Err(AccountError::Exists);
    }

    let fs = crate::fs::root().ok_or(AccountError::NoFileSystem)?;
    let mut database = match fs.read_file(DATABASE) {
        Ok(database) => database,
        Err(FsError::NotFound) => {
            fs.create_owned_by(DATABASE, NodeKind::File, ACCOUNTS)?;
            fs.set_mode_as(DATABASE, 0, None)?;
            Vec::new()
        }
        Err(error) => return Err(error.into()),
    };
    if accounts(&database).any(|account| account.name == name || account.user == user) {
        return Err(AccountError::Exists);
    }

    let salt = new_salt(name);
    let hash = sha256::pbkdf2(password.as_bytes(), &salt, ITERATIONS);
    let mut line = alloc::string::String::new();
    let _ = write!(line, "{name}:{user}:");
    for byte in salt {
        let _ = write!(line, "{byte:02x}");
    }
    line.push(':');
    for byte in hash {
        let _ = write!(line, "{byte:02x}");
    }
    line.push('\n');
    database.extend_from_slice(line.as_bytes());
    fs.write_file(DATABASE, &database)?;
    Ok(())
}

/// Check a name and password against the database, and on a match make
/// `thread` that account's user.
///
/// Costs the same whether or not the name exists, so the time taken does not
/// say which accounts do; and a failure then waits, so guessing is slow.
pub fn login(thread: ThreadId, name: &str, password: &str) -> Result<UserId, AccountError> {
    let fs = crate::fs::root().ok_or(AccountError::NoFileSystem)?;
    let database = match fs.read_file(DATABASE) {
        Ok(database) => database,
        Err(FsError::NotFound) => Vec::new(),
        Err(error) => return Err(error.into()),
    };

    let account = accounts(&database).find(|account| account.name == name);
    let (salt, expected) = account.as_ref().map_or(([0; 16], [0; 32]), |a| (a.salt, a.hash));
    let hash = sha256::pbkdf2(password.as_bytes(), &salt, ITERATIONS);

    match account {
        Some(account) if password.len() <= MAX_PASSWORD && sha256::same(&hash, &expected) => {
            assign(thread, account.user);
            Ok(account.user)
        }
        _ => {
            sched::sleep_ms(FAILURE_DELAY_MS);
            Err(AccountError::Incorrect)
        }
    }
}
