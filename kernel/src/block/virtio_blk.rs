//! virtio-blk: the disk a hypervisor hands a guest.
//!
//! Every request is a chain of three descriptors on one virtqueue: a 16-byte
//! header saying what to do and where, the data, and one byte the device writes
//! back with the outcome. Flush has no data, so its chain is two long.
//!
//! Completion is polled and one request is in flight at a time, as with the
//! other disk drivers: every call here is synchronous.

use alloc::sync::Arc;
use alloc::vec::Vec;

use x86_64::instructions::port::Port;

use super::{validate, BlockDevice, BlockError, SECTOR_SIZE};
use crate::memory::dma::DmaRegion;
use crate::pci::{self, Bar};
use crate::sync::Mutex;
use crate::virtio::{
    Queue, DESCRIPTOR_NEXT, DESCRIPTOR_WRITE, REG_CONFIG, REG_DEVICE_FEATURES, REG_GUEST_FEATURES,
    REG_QUEUE_NOTIFY, REG_STATUS, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, VENDOR,
};

/// A transitional block device: modern and legacy interfaces both.
const DEVICE_BLOCK_TRANSITIONAL: u16 = 0x1001;

/// The device can be asked to flush its write cache.
const FEATURE_FLUSH: u32 = 1 << 9;

const REQUEST_READ: u32 = 0;
const REQUEST_WRITE: u32 = 1;
const REQUEST_FLUSH: u32 = 4;
const OUTCOME_OK: u8 = 0;

/// Where devices are mapped: the queue, then a page for the header and outcome,
/// then the bounce buffer.
const VIRTIO_BLK_VIRT_BASE: u64 = 0x0000_7600_0000_0000;
const WINDOW_PAGES: u64 = 64;
const QUEUE_PAGES: u64 = 16;
const BOUNCE_BYTES: usize = 2 * 4096;

const TIMEOUT_SPINS: u64 = 200_000_000;

struct Device {
    port: u16,
    queue: Queue,
    /// Page 0: the header, and the outcome byte after it. Pages 1 and 2: the
    /// bounce buffer.
    buffers: DmaRegion,
    can_flush: bool,
}

pub struct VirtioBlkDisk {
    device: Mutex<Device>,
    sectors: u64,
}

// SAFETY: every access to the device and its memory holds `device`.
unsafe impl Send for VirtioBlkDisk {}
// SAFETY: as above.
unsafe impl Sync for VirtioBlkDisk {}

const HEADER: u64 = 0;
const OUTCOME: u64 = 16;
const BOUNCE: u64 = 4096;

impl Device {
    /// Send one request and wait for its outcome. `data` is the length of the
    /// bounce buffer taking part, or zero for none.
    fn request(&mut self, kind: u32, sector: u64, data: usize) -> Result<(), BlockError> {
        let header = self.buffers.virtual_at(HEADER);
        // SAFETY: the first page of this device's own buffers.
        unsafe {
            core::ptr::write_volatile(header as *mut u32, kind);
            core::ptr::write_volatile((header + 4) as *mut u32, 0);
            core::ptr::write_volatile((header + 8) as *mut u64, sector);
            core::ptr::write_volatile(self.buffers.virtual_at(OUTCOME) as *mut u8, 0xFF);
        }

        let header_physical = self.buffers.physical_at(HEADER);
        let outcome_physical = self.buffers.physical_at(OUTCOME);
        if data > 0 {
            let direction = if kind == REQUEST_READ { DESCRIPTOR_WRITE } else { 0 };
            self.queue.describe(0, header_physical, 16, DESCRIPTOR_NEXT, 1);
            self.queue.describe(
                1,
                self.buffers.physical_at(BOUNCE),
                data as u32,
                DESCRIPTOR_NEXT | direction,
                2,
            );
        } else {
            self.queue.describe(0, header_physical, 16, DESCRIPTOR_NEXT, 2);
        }
        self.queue.describe(2, outcome_physical, 1, DESCRIPTOR_WRITE, 0);

        self.queue.offer(0);
        // SAFETY: the legacy register block of this device.
        unsafe { Port::<u16>::new(self.port + REG_QUEUE_NOTIFY).write(0) };

        for _ in 0..TIMEOUT_SPINS {
            if self.queue.take_used().is_some() {
                // SAFETY: the outcome byte the device just wrote.
                let outcome = unsafe {
                    core::ptr::read_volatile(self.buffers.virtual_at(OUTCOME) as *const u8)
                };
                return if outcome == OUTCOME_OK {
                    Ok(())
                } else {
                    Err(BlockError::DeviceFault)
                };
            }
            core::hint::spin_loop();
        }
        Err(BlockError::DeviceFault)
    }

    fn write(&mut self, sectors_total: u64, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let sectors = validate(sectors_total, lba, buffer.len())?;
        let per_chunk = BOUNCE_BYTES / SECTOR_SIZE;
        let mut done = 0;
        while done < sectors {
            let chunk = (sectors - done).min(per_chunk);
            let bytes = chunk * SECTOR_SIZE;
            // SAFETY: the bounce buffer is `BOUNCE_BYTES`, and the chunk fits.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer[done * SECTOR_SIZE..].as_ptr(),
                    self.buffers.virtual_at(BOUNCE) as *mut u8,
                    bytes,
                );
            }
            self.request(REQUEST_WRITE, lba + done as u64, bytes)?;
            done += chunk;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        // A device without the feature has no cache to flush, and says so by
        // not offering it.
        if !self.can_flush {
            return Ok(());
        }
        self.request(REQUEST_FLUSH, 0, 0)
    }
}

impl BlockDevice for VirtioBlkDisk {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let sectors = validate(self.sectors, lba, buffer.len())?;
        let mut device = self.device.lock();
        let per_chunk = BOUNCE_BYTES / SECTOR_SIZE;
        let mut done = 0;
        while done < sectors {
            let chunk = (sectors - done).min(per_chunk);
            let bytes = chunk * SECTOR_SIZE;
            device.request(REQUEST_READ, lba + done as u64, bytes)?;
            // SAFETY: the device filled `bytes` of the bounce buffer, and the
            // caller's buffer was validated to hold them.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    device.buffers.virtual_at(BOUNCE) as *const u8,
                    buffer[done * SECTOR_SIZE..].as_mut_ptr(),
                    bytes,
                );
            }
            done += chunk;
        }
        Ok(())
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.device.lock().write(self.sectors, lba, buffer)
    }

    fn flush(&self) -> Result<(), BlockError> {
        self.device.lock().flush()
    }

    fn write_now(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let mut device = self.device.try_lock().ok_or(BlockError::Busy)?;
        device.write(self.sectors, lba, buffer)?;
        device.flush()
    }
}

/// Find every virtio block device and bring it up.
pub fn probe() -> Vec<Arc<dyn BlockDevice>> {
    let mut found: Vec<Arc<dyn BlockDevice>> = Vec::new();
    let mut slot = 0;
    for device in pci::enumerate() {
        if device.vendor_id != VENDOR || device.device_id != DEVICE_BLOCK_TRANSITIONAL {
            continue;
        }
        let window = VIRTIO_BLK_VIRT_BASE + slot * WINDOW_PAGES * 4096;
        slot += 1;
        match bring_up(device.address, window) {
            Some(disk) => found.push(Arc::new(disk)),
            None => crate::println!("warning: a virtio-blk device would not start"),
        }
    }
    found
}

fn bring_up(address: pci::Address, window: u64) -> Option<VirtioBlkDisk> {
    let Some(Bar::Io { port, .. }) = pci::read_bar(address, 0) else {
        return None;
    };

    // Bus mastering, or the device cannot reach the queue.
    let command = pci::read_config(address, 0x04);
    // SAFETY: enabling mastering on a device this driver owns.
    unsafe { pci::write_config(address, 0x04, command | 0b101) };

    // SAFETY: the legacy register block of the device being claimed.
    let can_flush = unsafe {
        Port::<u8>::new(port + REG_STATUS).write(0);
        Port::<u8>::new(port + REG_STATUS).write(STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        let offered = Port::<u32>::new(port + REG_DEVICE_FEATURES).read();
        Port::<u32>::new(port + REG_GUEST_FEATURES).write(offered & FEATURE_FLUSH);
        offered & FEATURE_FLUSH != 0
    };

    // SAFETY: capacity, in 512-byte sectors, at the start of the configuration.
    // No MSI-X, so the configuration is where the legacy layout first puts it.
    let sectors = unsafe {
        Port::<u32>::new(port + REG_CONFIG).read() as u64
            | (Port::<u32>::new(port + REG_CONFIG + 4).read() as u64) << 32
    };

    let queue = Queue::new(port, 0, window)?;
    if queue.size < 3 {
        return None;
    }
    let buffers = DmaRegion::new(1 + (BOUNCE_BYTES as u64).div_ceil(4096), window + QUEUE_PAGES * 4096)?;

    // SAFETY: as above. The device may use the queue from here.
    unsafe {
        Port::<u8>::new(port + REG_STATUS)
            .write(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK)
    };

    Some(VirtioBlkDisk {
        device: Mutex::new(Device {
            port,
            queue,
            buffers,
            can_flush,
        }),
        sectors,
    })
}
