//! Handing hardware to Ring 3: I/O ports and interrupt lines.
//!
//! A driver that does no DMA can be genuinely isolated in user space, provided
//! it reaches exactly its own ports, hears exactly its own interrupts, and
//! nothing else. That is what this module grants. (A DMA-capable device is
//! another matter -- see [`crate::block`] for why the disk driver stays in the
//! kernel.)
//!
//! Grants are given by whoever spawns the driver, never asked for, in the same
//! way [`crate::gbm::allow_display_server`] is: Ring 3 must not be able to
//! promote itself to owning a device.
//!
//! **Ports go through a system call, not the TSS I/O bitmap.** The bitmap would
//! let a driver use `in` and `out` directly, but it is per processor, so every
//! context switch between two processes with different grants would have to
//! rewrite it on whichever processor the switch happened. The system call checks
//! the same grant in one place. Its cost is a trap per byte, which for a keyboard
//! controller is nothing.
//!
//! **An interrupt becomes a message.** The kernel does not touch the device: it
//! sends a notification to the endpoint the driver bound, stamped with
//! [`crate::ipc::KERNEL_SENDER`] so no process can forge one, and acknowledges
//! the APIC. The driver drains the device when it gets round to it. A
//! notification lost to a full queue loses nothing, because a full queue means
//! the driver already has notifications it has not acted on, and each one sends
//! it to drain everything.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use x86_64::instructions::port::Port;

use crate::ipc::{self, EndpointId, Message, Rights};
use crate::sched::{self, ThreadId};
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::{Error, SyscallResult};

/// Legacy ISA interrupt lines. Everything a PS/2 controller raises is here.
pub const ISA_IRQS: usize = 16;

/// Vector ISA line `n` is delivered on.
pub const IRQ_VECTOR_BASE: u8 = 0x40;

/// Tag of an interrupt notification. `words[0]` is the line.
pub const TAG_IRQ: u64 = 0x1_0000;

/// No endpoint. Endpoint ids start at 1.
const UNBOUND: u64 = 0;

struct Grants {
    ports: Vec<(ThreadId, u16)>,
    irqs: Vec<(ThreadId, u8)>,
}

static GRANTS: Mutex<Grants> = Mutex::new(Grants {
    ports: Vec::new(),
    irqs: Vec::new(),
});

/// The endpoint each line notifies. Atomic, because the interrupt handler reads
/// it and must not wait on a lock to do so.
static BOUND: [AtomicU64; ISA_IRQS] = [const { AtomicU64::new(UNBOUND) }; ISA_IRQS];
/// Who bound each line, so the binding goes when they do.
static BOUND_BY: [AtomicUsize; ISA_IRQS] = [const { AtomicUsize::new(usize::MAX) }; ISA_IRQS];

/// Let `thread` read and write one I/O port.
pub fn grant_port(thread: ThreadId, port: u16) {
    without_interrupts(|| {
        let mut grants = GRANTS.lock();
        if !grants.ports.contains(&(thread, port)) {
            grants.ports.push((thread, port));
        }
    });
}

/// Let `thread` bind one ISA interrupt line. Refused for lines the kernel
/// itself uses, which today is the serial port's.
pub fn grant_irq(thread: ThreadId, irq: u8) -> Result<(), Error> {
    if irq as usize >= ISA_IRQS || irq == crate::console::uart::COM1_IRQ {
        return Err(Error::InvalidArgument);
    }
    without_interrupts(|| {
        let mut grants = GRANTS.lock();
        if !grants.irqs.contains(&(thread, irq)) {
            grants.irqs.push((thread, irq));
        }
    });
    Ok(())
}

/// Everything the PS/2 controller's driver needs: its data and command ports,
/// and the keyboard and mouse lines.
pub fn grant_ps2_controller(thread: ThreadId) {
    grant_port(thread, 0x60);
    grant_port(thread, 0x64);
    // Neither line is the serial port's, so neither grant can be refused.
    let _ = grant_irq(thread, 1);
    let _ = grant_irq(thread, 12);
}

fn holds_port(thread: ThreadId, port: u16) -> bool {
    without_interrupts(|| GRANTS.lock().ports.contains(&(thread, port)))
}

fn holds_irq(thread: ThreadId, irq: u8) -> bool {
    without_interrupts(|| GRANTS.lock().irqs.contains(&(thread, irq)))
}

/// Forget a thread's grants and bindings. Called when it exits.
///
/// The line is left routed. Every ISA line is edge-triggered, so an interrupt
/// nobody is bound to arrives once, is found unbound, and is acknowledged.
pub fn release_thread(thread: ThreadId) {
    without_interrupts(|| {
        let mut grants = GRANTS.lock();
        grants.ports.retain(|(holder, _)| *holder != thread);
        grants.irqs.retain(|(holder, _)| *holder != thread);
    });

    for irq in 0..ISA_IRQS {
        if BOUND_BY[irq].load(Ordering::Acquire) == thread.0 {
            BOUND[irq].store(UNBOUND, Ordering::Release);
            BOUND_BY[irq].store(usize::MAX, Ordering::Release);
        }
    }
}

/// Called by the interrupt handler for ISA line `irq`.
pub fn on_interrupt(irq: u8) {
    let endpoint = BOUND[irq as usize].load(Ordering::Acquire);
    if endpoint == UNBOUND {
        return;
    }
    let notification = Message {
        tag: TAG_IRQ,
        words: [irq as u64, 0, 0, 0],
        sender: 0,
    };
    // A full queue is not a lost interrupt; see the module notes.
    let _ = ipc::notify(EndpointId(endpoint), notification);
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

fn current() -> Result<ThreadId, Error> {
    sched::current_id().ok_or(Error::InvalidArgument)
}

fn granted_port(port: u64) -> Result<u16, Error> {
    let port = u16::try_from(port).map_err(|_| Error::InvalidArgument)?;
    if !holds_port(current()?, port) {
        return Err(Error::NoCapability);
    }
    Ok(port)
}

pub fn sys_port_read(port: u64) -> SyscallResult {
    let port = granted_port(port)?;
    // SAFETY: the caller was granted this port by whoever spawned it, which is
    // the statement that reading it cannot harm anything but that device.
    let value: u8 = unsafe { Port::new(port).read() };
    Ok(value as i64)
}

pub fn sys_port_write(port: u64, value: u64) -> SyscallResult {
    let port = granted_port(port)?;
    let value = u8::try_from(value).map_err(|_| Error::InvalidArgument)?;
    // SAFETY: as in `sys_port_read`.
    unsafe { Port::new(port).write(value) };
    Ok(0)
}

/// Deliver interrupts on `irq` to `endpoint` as notifications.
///
/// The caller needs the line's grant, and `SEND` on the endpoint -- otherwise a
/// driver could point its interrupts at a queue belonging to someone it has no
/// business talking to.
pub fn sys_irq_bind(irq: u64, endpoint: u64) -> SyscallResult {
    let irq = u8::try_from(irq).map_err(|_| Error::InvalidArgument)?;
    let caller = current()?;
    if !holds_irq(caller, irq) {
        return Err(Error::NoCapability);
    }
    if !ipc::rights_of(caller, EndpointId(endpoint)).contains(Rights::SEND) {
        return Err(Error::NoCapability);
    }

    // Bound before routed, so the first interrupt finds somewhere to go.
    BOUND_BY[irq as usize].store(caller.0, Ordering::Release);
    BOUND[irq as usize].store(endpoint, Ordering::Release);

    let topology = crate::smp::topology().ok_or(Error::InvalidArgument)?;
    crate::arch::x86_64::ioapic::route_isa(
        &topology,
        irq,
        IRQ_VECTOR_BASE + irq,
        crate::arch::x86_64::apic::id(),
    )
    .map_err(|_| Error::InvalidArgument)?;
    Ok(0)
}
