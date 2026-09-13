//! What the kernel leaves behind when it dies.
//!
//! A panic used to print one line and halt. On a machine nobody was watching,
//! that line was the entire record, and it did not survive the power cycle
//! that followed.
//!
//! Now a panic stops the other processors, reports where it was and how it got
//! there, and writes the report to a partition reserved for it. The next boot
//! prints what it finds there and clears it.
//!
//! Everything on this path fails open. Locks are tried, never waited on: the
//! holder may be a processor that was just stopped, or the very code that
//! panicked. Whatever cannot be had without waiting is left out.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

use crate::block::partition::{self, PartitionDevice};
use crate::block::{self, BlockDevice, BlockError, SECTOR_SIZE};
use crate::sync::Once;

/// GPT type GUID of a crash partition. ASCII, so it is obvious in a hex dump
/// and nowhere near the random bytes of a registered type.
pub const PARTITION_TYPE: [u8; 16] = *b"KernelPandaCrash";

/// Starts the header sector of a record that is present.
const MAGIC: &[u8; 8] = b"PANDCRSH";

/// Report text, in sectors after the header. Beyond this it is truncated; the
/// console still gets all of it.
const RECORD_SECTORS: usize = 8;
const REPORT_BYTES: usize = RECORD_SECTORS * SECTOR_SIZE;

/// Frames walked before giving up. A corrupted chain can loop without ever
/// failing a check.
const MAX_FRAMES: usize = 32;

static PANICKING: AtomicBool = AtomicBool::new(false);

/// Where records go, if a crash partition was found.
static AREA: Once<Arc<dyn BlockDevice>> = Once::new();

/// The report being written. Static rather than on the stack, which on a double
/// fault is the 20 KiB IST stack and may already be most of the way down.
struct Report {
    bytes: [u8; REPORT_BYTES],
    length: usize,
}

struct ReportCell(UnsafeCell<Report>);

// SAFETY: only reached by whoever won `PANICKING`, and that happens once.
unsafe impl Sync for ReportCell {}

static REPORT: ReportCell = ReportCell(UnsafeCell::new(Report {
    bytes: [0; REPORT_BYTES],
    length: 0,
}));

/// Formatting goes straight to the console as it is produced, so a report too
/// long for the record is truncated on disk and nowhere else.
impl Write for Report {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::console::uart::_print_unlocked(format_args!("{s}"));
        crate::console::framebuffer::_try_print(format_args!("{s}"));

        let take = s.len().min(REPORT_BYTES - self.length);
        self.bytes[self.length..self.length + take].copy_from_slice(&s.as_bytes()[..take]);
        self.length += take;
        Ok(())
    }
}

/// Whether some processor has panicked.
pub fn is_panicking() -> bool {
    PANICKING.load(Ordering::Acquire)
}

/// The kernel's panic handler.
pub fn panic(info: &PanicInfo) -> ! {
    report(info);
    halt()
}

/// Stop the world, report, and save the record. Returns `false` without doing
/// anything if a panic is already being reported.
///
/// Separate from [`panic`] so a test can watch it happen and then look.
pub fn report(info: &PanicInfo) -> bool {
    x86_64::instructions::interrupts::disable();

    // Either another processor got here first, and its NMI is on the way, or
    // this is a panic inside the report. The first report is the one worth
    // having either way.
    if PANICKING.swap(true, Ordering::AcqRel) {
        return false;
    }

    crate::smp::for_each_other_online_processor(|_, apic_id| {
        // SAFETY: an online processor has loaded the kernel's IDT, which
        // handles NMI.
        unsafe { crate::arch::x86_64::apic::send_nmi(apic_id) };
    });

    // SAFETY: this caller won `PANICKING`, so nothing else holds a reference.
    let report = unsafe { &mut *REPORT.0.get() };

    let _ = writeln!(
        report,
        "\nKERNEL PANIC on cpu {} in thread '{}'",
        crate::smp::cpu_index(),
        crate::sched::try_current_name().unwrap_or("?")
    );
    let _ = writeln!(report, "{info}");
    let _ = writeln!(report, "backtrace (return addresses; addr2line against the kernel ELF):");
    backtrace(report);

    match save(report) {
        Ok(()) => print_unlocked(format_args!("crash record saved\n")),
        Err(BlockError::NotPresent) => {
            print_unlocked(format_args!("no crash partition; the record was not saved\n"))
        }
        Err(error) => print_unlocked(format_args!("crash record not saved: {error:?}\n")),
    }
    true
}

fn print_unlocked(args: fmt::Arguments) {
    crate::console::uart::_print_unlocked(args);
    crate::console::framebuffer::_try_print(args);
}

/// Follow the frame-pointer chain up from here.
///
/// Every frame is checked before it is read: mapped, kernel-only, and above the
/// one before. Reading an unmapped frame would fault inside the panic handler,
/// and a user-accessible one would fault on SMAP -- a panic inside a system call
/// has the user's stack at the top of the chain.
fn backtrace(report: &mut Report) {
    let mut rbp: u64;
    // SAFETY: copies a register.
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags));
    }

    for _ in 0..MAX_FRAMES {
        if !rbp.is_multiple_of(8) || !kernel_readable(rbp) || !kernel_readable(rbp + 8) {
            return;
        }
        // SAFETY: both words were just found mapped and kernel-only.
        let (caller_rbp, return_address) =
            unsafe { (*(rbp as *const u64), *((rbp + 8) as *const u64)) };
        if return_address == 0 {
            return;
        }
        let _ = writeln!(report, "  {return_address:#018x}");

        // Stacks grow down, so a caller's frame is always higher.
        if caller_rbp <= rbp {
            return;
        }
        rbp = caller_rbp;
    }
}

/// `false` for unmapped, user-accessible, or unknown because the page tables
/// were locked.
fn kernel_readable(address: u64) -> bool {
    let Ok(address) = VirtAddr::try_new(address) else {
        return false;
    };
    crate::memory::paging::try_flags(address)
        .is_some_and(|flags| !flags.contains(PageTableFlags::USER_ACCESSIBLE))
}

/// Text first, header last, so a panic partway through leaves either the old
/// state or a whole record -- never a header describing half-written text.
fn save(report: &Report) -> Result<(), BlockError> {
    let area = AREA.get().ok_or(BlockError::NotPresent)?;
    area.write_now(1, &report.bytes)?;

    let mut header = [0u8; SECTOR_SIZE];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&(report.length as u32).to_le_bytes());
    header[12..16].copy_from_slice(&fnv1a(&report.bytes[..report.length]).to_le_bytes());
    area.write_now(0, &header)
}

/// Find the crash partition, and report and clear anything a previous boot
/// left in it.
///
/// Runs after storage is up. Harmless to call again -- a test does, after
/// creating the partition.
pub fn init() {
    if AREA.get().is_some() {
        return;
    }

    for index in 0..block::count() {
        let Some(disk) = block::device(index) else {
            continue;
        };
        let Ok(partitions) = partition::read(&*disk) else {
            continue;
        };

        for entry in partitions.iter().filter(|p| p.type_guid == PARTITION_TYPE) {
            let Ok(view) = PartitionDevice::new(disk.clone(), entry) else {
                continue;
            };
            if view.sector_count() < 1 + RECORD_SECTORS as u64 {
                continue;
            }

            AREA.call_once(|| Arc::new(view));
            crate::println!("crash: record area on disk {index}");
            if let Some(previous) = take_previous() {
                crate::println!("the previous boot panicked:{previous}");
            }
            return;
        }
    }
}

/// Read the saved record, if there is one, and clear it.
pub fn take_previous() -> Option<String> {
    let area = AREA.get()?;

    let mut header = [0u8; SECTOR_SIZE];
    area.read(0, &mut header).ok()?;
    if &header[..8] != MAGIC {
        return None;
    }

    let mut text = vec![0u8; REPORT_BYTES];
    area.read(1, &mut text).ok()?;

    // Cleared whether or not it verifies. A record that fails now fails on
    // every boot, and reporting it every time helps nobody.
    let _ = area.write(0, &[0u8; SECTOR_SIZE]);
    let _ = area.flush();

    let length = u32::from_le_bytes(header[8..12].try_into().ok()?) as usize;
    let checksum = u32::from_le_bytes(header[12..16].try_into().ok()?);
    if length > REPORT_BYTES || fnv1a(&text[..length]) != checksum {
        return Some(String::from("\n(a crash record was found, but it did not verify)"));
    }
    Some(String::from_utf8_lossy(&text[..length]).into_owned())
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811C_9DC5, |hash, byte| {
        (hash ^ *byte as u32).wrapping_mul(0x0100_0193)
    })
}

fn halt() -> ! {
    x86_64::instructions::interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}
