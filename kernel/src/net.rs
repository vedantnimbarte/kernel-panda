//! The network card: a virtio-net driver, and the Ring 3 surface over it.
//!
//! The kernel moves Ethernet frames and nothing else. ARP, IP, ICMP and UDP are
//! the network daemon's business, in Ring 3, so a parsing bug in any of them is
//! a bug in one unprivileged process. The driver itself stays in the kernel for
//! the reason the disk driver does: the card is a DMA engine, and without an
//! IOMMU a Ring 3 driver handed one is not isolated, only apparently so.
//!
//! ## The device
//!
//! Virtio is the interface QEMU and most hypervisors expose, and its *legacy*
//! form -- a block of I/O-port registers in BAR 0 -- is what this speaks. The
//! modern form describes the same registers through a chain of PCI capabilities
//! and memory BARs; it is the one to move to for hardware that offers nothing
//! else, and it buys nothing here.
//!
//! Frames travel through two virtqueues, each a ring the driver and the device
//! share by DMA: a table of buffer descriptors, an "available" ring the driver
//! appends to, and a "used" ring the device appends to. Receive keeps every
//! buffer on offer and takes back whichever the device has filled; transmit
//! offers one buffer at a time.
//!
//! Arrivals are announced by MSI-X, straight to a Local APIC vector. The
//! device's legacy interrupt pin would need the firmware's AML to find its way
//! to the I/O APIC, and there is no AML interpreter.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use x86_64::instructions::port::Port;

use crate::ipc::{self, EndpointId, Message, Rights};
use crate::memory::dma::DmaRegion;
use crate::virtio::{
    Queue, DESCRIPTOR_WRITE, NO_VECTOR, REG_CONFIG_VECTOR, REG_CONFIG_WITH_MSIX, REG_DEVICE_FEATURES,
    REG_GUEST_FEATURES, REG_QUEUE_NOTIFY, REG_QUEUE_VECTOR, REG_STATUS, STATUS_ACKNOWLEDGE,
    STATUS_DRIVER, STATUS_DRIVER_OK, VENDOR as VENDOR_VIRTIO,
};
use crate::pci::{self, Bar};
use crate::sched::{self, ThreadId};
use crate::sync::{without_interrupts, Mutex};
use crate::syscall::{Error, SyscallResult};
use crate::userspace;

/// A transitional network device: modern and legacy interfaces both.
const DEVICE_NET_TRANSITIONAL: u16 = 0x1000;

/// The device has a MAC address in its configuration space.
const FEATURE_MAC: u32 = 1 << 5;

const RECEIVE_QUEUE: u16 = 0;
const TRANSMIT_QUEUE: u16 = 1;

/// Every frame is preceded by this header. Ten bytes in the legacy layout,
/// without the merged-buffers feature; all zero means "no offloads".
const HEADER_BYTES: usize = 10;

/// Largest Ethernet frame without the frame check sequence: 1500 bytes of
/// payload and a 14-byte header.
pub const MAX_FRAME: usize = 1514;

/// Buffer per descriptor: room for the header and a maximum frame, rounded to a
/// size that packs neatly into pages.
const BUFFER_BYTES: u64 = 2048;

/// Receive buffers kept on offer.
const RECEIVE_BUFFERS: u16 = 32;

/// Where the queues and buffers are mapped.
const NET_VIRT_BASE: u64 = 0x0000_7400_0000_0000;

/// Waits on the device are bounded, so a card that stops answering is an error
/// rather than a hang.
const TIMEOUT_SPINS: u64 = 50_000_000;

/// Tag of the notification sent when frames have arrived.
pub const TAG_RECEIVED: u64 = 0x2_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// No network card was found.
    NotPresent,
    /// The frame is empty or larger than [`MAX_FRAME`].
    BadLength,
    /// The previous frame was never taken by the device.
    Timeout,
}

struct VirtioNet {
    port: u16,
    receive: Queue,
    transmit: Queue,
    receive_buffers: DmaRegion,
    transmit_buffer: DmaRegion,
    mac: [u8; 6],
    /// A frame is with the device and has not come back.
    transmitting: bool,
}

// SAFETY: every access goes through `NIC`, and the regions are owned for good.
unsafe impl Send for VirtioNet {}

static NIC: Mutex<Option<VirtioNet>> = Mutex::new(None);

/// Where arrivals are announced, or zero.
static BOUND: AtomicU64 = AtomicU64::new(0);

/// The one thread allowed to use the card, plus one, or zero.
static STACK: AtomicUsize = AtomicUsize::new(0);

impl VirtioNet {
    fn notify(&self, queue: u16) {
        // SAFETY: the legacy register block of this device.
        unsafe { Port::<u16>::new(self.port + REG_QUEUE_NOTIFY).write(queue) };
    }
}

/// Find a virtio network card and bring it up. Nothing found is not an error.
pub fn init() {
    let Some(device) = pci::enumerate().into_iter().find(|device| {
        device.vendor_id == VENDOR_VIRTIO && device.device_id == DEVICE_NET_TRANSITIONAL
    }) else {
        return;
    };

    match bring_up(device.address) {
        Some(nic) => {
            let mac = nic.mac;
            without_interrupts(|| *NIC.lock() = Some(nic));
            crate::println!(
                "net: virtio-net at {:02x}:{:02x}.{}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                device.address.bus,
                device.address.device,
                device.address.function,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
        }
        None => crate::println!("warning: a virtio-net card was found but would not start"),
    }
}

fn bring_up(address: pci::Address) -> Option<VirtioNet> {
    let Some(Bar::Io { port, .. }) = pci::read_bar(address, 0) else {
        return None;
    };
    let register = |offset: u16| port + offset;

    // SAFETY: the legacy register block of the card being claimed. Reset, then
    // the two status bits that say a driver has noticed it and knows what it is.
    unsafe {
        Port::<u8>::new(register(REG_STATUS)).write(0);
        Port::<u8>::new(register(REG_STATUS)).write(STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        let offered = Port::<u32>::new(register(REG_DEVICE_FEATURES)).read();
        // The MAC and nothing else. No offloads means every frame is exactly
        // what is on the wire, which is what a small stack wants to parse.
        Port::<u32>::new(register(REG_GUEST_FEATURES)).write(offered & FEATURE_MAC);
    }

    // MSI-X before the queues: enabling it moves the device configuration and
    // adds the vector registers the queues are configured through.
    pci::route_msix(address, 0, on_receive).ok()?;

    let receive = Queue::new(port, RECEIVE_QUEUE, NET_VIRT_BASE)?;
    // SAFETY: as above; the receive queue is still selected.
    unsafe { Port::<u16>::new(register(REG_QUEUE_VECTOR)).write(0) };
    let transmit = Queue::new(port, TRANSMIT_QUEUE, NET_VIRT_BASE + 16 * 4096)?;
    // SAFETY: as above. Transmit completion is polled, so no interrupt.
    unsafe {
        Port::<u16>::new(register(REG_QUEUE_VECTOR)).write(NO_VECTOR);
        Port::<u16>::new(register(REG_CONFIG_VECTOR)).write(NO_VECTOR);
    }

    let buffers = RECEIVE_BUFFERS.min(receive.size);
    let receive_buffers = DmaRegion::new(
        (buffers as u64 * BUFFER_BYTES).div_ceil(4096),
        NET_VIRT_BASE + 32 * 4096,
    )?;
    let transmit_buffer = DmaRegion::new(1, NET_VIRT_BASE + 64 * 4096)?;

    let mut mac = [0u8; 6];
    for (index, byte) in mac.iter_mut().enumerate() {
        // SAFETY: the MAC, at the start of the device configuration.
        *byte = unsafe { Port::<u8>::new(register(REG_CONFIG_WITH_MSIX) + index as u16).read() };
    }

    let mut nic = VirtioNet {
        port,
        receive,
        transmit,
        receive_buffers,
        transmit_buffer,
        mac,
        transmitting: false,
    };

    for index in 0..buffers {
        let physical = nic.receive_buffers.physical_at(index as u64 * BUFFER_BYTES);
        nic.receive.describe(index, physical, BUFFER_BYTES as u32, DESCRIPTOR_WRITE, 0);
        nic.receive.offer(index);
    }

    // SAFETY: as above. The device may start using the queues from here.
    unsafe { Port::<u8>::new(register(REG_STATUS)).write(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) };
    nic.notify(RECEIVE_QUEUE);
    Some(nic)
}

/// The receive queue's MSI-X vector. Interrupt context: it only tells whoever
/// is bound, who takes the frames at their own pace.
fn on_receive() {
    let endpoint = BOUND.load(Ordering::Acquire);
    if endpoint != 0 {
        let notification = Message {
            tag: TAG_RECEIVED,
            words: [0; 4],
            sender: 0,
            sender_user: 0,
        };
        // A full queue already holds a notification, and each sends the stack
        // to take every frame there is.
        let _ = ipc::notify(EndpointId(endpoint), notification);
    }
}

/// The card's MAC address.
pub fn mac() -> Option<[u8; 6]> {
    without_interrupts(|| NIC.lock().as_ref().map(|nic| nic.mac))
}

/// Put one Ethernet frame on the wire.
pub fn send(frame: &[u8]) -> Result<(), NetError> {
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err(NetError::BadLength);
    }

    without_interrupts(|| {
        let mut guard = NIC.lock();
        let nic = guard.as_mut().ok_or(NetError::NotPresent)?;

        // One buffer, so the last frame has to have come back first. The device
        // takes a frame as soon as it is told about it; this is a formality that
        // a stuck device turns into an error.
        let mut spins = 0;
        while nic.transmitting {
            if nic.transmit.take_used().is_some() {
                nic.transmitting = false;
                break;
            }
            spins += 1;
            if spins > TIMEOUT_SPINS {
                return Err(NetError::Timeout);
            }
            core::hint::spin_loop();
        }

        let buffer = nic.transmit_buffer.virtual_at(0) as *mut u8;
        // SAFETY: the transmit buffer is a whole page, and the header plus the
        // longest frame is well inside it.
        unsafe {
            core::ptr::write_bytes(buffer, 0, HEADER_BYTES);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer.add(HEADER_BYTES), frame.len());
        }
        let physical = nic.transmit_buffer.physical_at(0);
        nic.transmit.describe(0, physical, (HEADER_BYTES + frame.len()) as u32, 0, 0);
        nic.transmit.offer(0);
        nic.transmitting = true;
        nic.notify(TRANSMIT_QUEUE);
        Ok(())
    })
}

/// Take one received frame into `out`, returning its length -- or `None` if
/// nothing is waiting. A frame longer than `out` is truncated.
pub fn receive(out: &mut [u8]) -> Result<Option<usize>, NetError> {
    without_interrupts(|| {
        let mut guard = NIC.lock();
        let nic = guard.as_mut().ok_or(NetError::NotPresent)?;

        let Some((index, written)) = nic.receive.take_used() else {
            return Ok(None);
        };
        let frame_length = (written as usize).saturating_sub(HEADER_BYTES);
        let take = frame_length.min(out.len());
        let buffer = nic.receive_buffers.virtual_at(index as u64 * BUFFER_BYTES);
        // SAFETY: descriptor `index` is one of this driver's receive buffers,
        // `BUFFER_BYTES` long, and the device wrote `written` bytes of it.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (buffer as *const u8).add(HEADER_BYTES),
                out.as_mut_ptr(),
                take,
            );
        }

        // Straight back on offer: the descriptor still describes its buffer.
        nic.receive.offer(index);
        nic.notify(RECEIVE_QUEUE);
        Ok(Some(take))
    })
}

/// Have arrivals announced on `endpoint`. Kernel-facing; Ring 3 goes through
/// [`sys_bind`], which checks the caller may.
pub fn bind(endpoint: EndpointId) {
    BOUND.store(endpoint.0, Ordering::Release);
}

/// Designate the thread that runs the network stack.
///
/// Not a syscall, for the same reason `gbm::allow_display_server` is not: a
/// process must not be able to make itself the one that sees every frame.
pub fn allow_stack(thread: ThreadId) {
    STACK.store(thread.0 + 1, Ordering::Release);
}

/// Forget the stack's grant and binding when it exits.
pub fn release_thread(thread: ThreadId) {
    if STACK
        .compare_exchange(thread.0 + 1, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        BOUND.store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

fn stack_caller() -> Result<ThreadId, Error> {
    let caller = sched::current_id().ok_or(Error::InvalidArgument)?;
    if STACK.load(Ordering::Acquire) != caller.0 + 1 {
        return Err(Error::NoCapability);
    }
    Ok(caller)
}

impl From<NetError> for Error {
    fn from(error: NetError) -> Self {
        match error {
            NetError::NotPresent => Error::NoSuchEndpoint,
            NetError::BadLength => Error::InvalidArgument,
            NetError::Timeout => Error::QueueFull,
        }
    }
}

/// Write the MAC address into six bytes at `out`.
pub fn sys_info(out: u64) -> SyscallResult {
    stack_caller()?;
    let mac = mac().ok_or(NetError::NotPresent)?;
    if !userspace::validate_user_buffer(out, 6, true) {
        return Err(Error::BadPointer);
    }
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: six bytes validated as present, user-accessible and writable.
        unsafe { core::ptr::copy_nonoverlapping(mac.as_ptr(), out as *mut u8, 6) };
    });
    Ok(0)
}

pub fn sys_send(pointer: u64, length: u64) -> SyscallResult {
    stack_caller()?;
    if length == 0 || length > MAX_FRAME as u64 {
        return Err(Error::InvalidArgument);
    }
    if !userspace::validate_user_buffer(pointer, length, false) {
        return Err(Error::BadPointer);
    }

    // Copied out first, so the device lock is never held with the SMAP window
    // open over user memory that could fault.
    let mut frame = [0u8; MAX_FRAME];
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: validated as present and user-readable for `length` bytes,
        // which is at most the size of `frame`.
        unsafe {
            core::ptr::copy_nonoverlapping(pointer as *const u8, frame.as_mut_ptr(), length as usize)
        };
    });
    send(&frame[..length as usize])?;
    Ok(0)
}

/// Take one frame. Returns its length, or zero if nothing was waiting.
pub fn sys_receive(pointer: u64, capacity: u64) -> SyscallResult {
    stack_caller()?;
    if !userspace::validate_user_buffer(pointer, capacity, true) {
        return Err(Error::BadPointer);
    }

    let mut frame = [0u8; MAX_FRAME];
    let Some(length) = receive(&mut frame)? else {
        return Ok(0);
    };
    let take = length.min(capacity as usize);
    crate::arch::x86_64::with_user_access(|| {
        // SAFETY: validated as writable for `capacity` bytes; `take` fits.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), pointer as *mut u8, take) };
    });
    Ok(take as i64)
}

/// Announce arrivals on `endpoint`, which the caller must hold `SEND` on.
pub fn sys_bind(endpoint: u64) -> SyscallResult {
    let caller = stack_caller()?;
    if !ipc::rights_of(caller, EndpointId(endpoint)).contains(Rights::SEND) {
        return Err(Error::NoCapability);
    }
    bind(EndpointId(endpoint));
    Ok(0)
}
