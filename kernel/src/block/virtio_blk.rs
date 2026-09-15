//! virtio-blk: the disk a hypervisor hands a guest.
//!
//! Every request is a chain of three descriptors on one virtqueue: a 16-byte
//! header saying what to do and where, the data, and one byte the device writes
//! back with the outcome. Flush has no data, so its chain is two long.
//!
//! Each request slot owns three descriptors and a header page and bounce buffer
//! of its own, so a chain's head descriptor names its slot and several chains
//! can be with the device at once. The device announces finished chains by
//! MSI-X; see [`super::request`] for who sleeps and who polls.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::instructions::port::Port;

use super::request::{Completion, Slots};
use super::{validate, BlockDevice, BlockError, BlockStats, SECTOR_SIZE};
use crate::memory::dma::DmaRegion;
use crate::pci::{self, Bar};
use crate::sync::Mutex;
use crate::virtio::{
    Queue, DESCRIPTOR_NEXT, DESCRIPTOR_WRITE, NO_VECTOR, REG_CONFIG, REG_CONFIG_VECTOR, REG_DEVICE_FEATURES,
    REG_GUEST_FEATURES, REG_QUEUE_NOTIFY, REG_QUEUE_VECTOR, REG_STATUS, STATUS_ACKNOWLEDGE, STATUS_DRIVER,
    STATUS_DRIVER_OK, VENDOR,
};

/// A transitional block device: modern and legacy interfaces both.
const DEVICE_BLOCK_TRANSITIONAL: u16 = 0x1001;

/// The device can be asked to flush its write cache.
const FEATURE_FLUSH: u32 = 1 << 9;

const REQUEST_READ: u32 = 0;
const REQUEST_WRITE: u32 = 1;
const REQUEST_FLUSH: u32 = 4;
const OUTCOME_OK: u8 = 0;

/// Where devices are mapped: the queue, then each slot's header page and
/// bounce buffer.
const VIRTIO_BLK_VIRT_BASE: u64 = 0x0000_7600_0000_0000;
const WINDOW_PAGES: u64 = 64;
const QUEUE_PAGES: u64 = 16;
const BOUNCE_BYTES: usize = 2 * 4096;
const SLOT_PAGES: u64 = 1 + (BOUNCE_BYTES as u64).div_ceil(4096);
const MAX_SLOTS: usize = 8;

/// Within a slot's memory: the header, the outcome byte after it, and the
/// bounce buffer on the pages that follow.
const HEADER: u64 = 0;
const OUTCOME: u64 = 16;
const BOUNCE: u64 = 4096;

pub struct VirtioBlkDisk {
    port: u16,
    queue: Mutex<Queue>,
    slots: Slots,
    memory: Vec<DmaRegion>,
    completions: Vec<Completion>,
    sectors: u64,
    can_flush: bool,
    /// Whether the device announces finished chains; set once, at bring-up.
    interrupts: AtomicBool,
}

// SAFETY: the queue is behind its lock, and a slot's memory is touched only by
// the request holding the slot -- until it is handed to the device, which is
// what the slot allocator exists to serialise.
unsafe impl Send for VirtioBlkDisk {}
// SAFETY: as above.
unsafe impl Sync for VirtioBlkDisk {}

impl VirtioBlkDisk {
    /// Collect every chain the device has finished. The interrupt handler and a
    /// polling waiter both come here.
    fn service(&self, from_interrupt: bool) {
        // A panic may have stopped whoever holds the queue; everywhere else it
        // is held for a few instructions.
        let queue = if crate::crash::is_panicking() { self.queue.try_lock() } else { Some(self.queue.lock()) };
        let Some(mut queue) = queue else {
            return;
        };
        while let Some((head, _)) = queue.take_used() {
            let slot = head as usize / 3;
            let Some(memory) = self.memory.get(slot) else {
                continue;
            };
            // SAFETY: the outcome byte of the slot's own memory, which the
            // device has just written.
            let outcome = unsafe { core::ptr::read_volatile(memory.virtual_at(OUTCOME) as *const u8) };
            if from_interrupt {
                self.slots.interrupt_completions.fetch_add(1, Ordering::Relaxed);
            }
            self.completions[slot].finish(outcome == OUTCOME_OK);
        }
    }

    /// Send one request on `slot` and wait for its outcome. `data` is the
    /// length of the slot's bounce buffer taking part, or zero for none.
    fn request(&self, slot: usize, kind: u32, sector: u64, data: usize) -> Result<(), BlockError> {
        let memory = &self.memory[slot];
        let header = memory.virtual_at(HEADER);
        // SAFETY: the header page of a slot this request holds.
        unsafe {
            core::ptr::write_volatile(header as *mut u32, kind);
            core::ptr::write_volatile((header + 4) as *mut u32, 0);
            core::ptr::write_volatile((header + 8) as *mut u64, sector);
            core::ptr::write_volatile(memory.virtual_at(OUTCOME) as *mut u8, 0xFF);
        }
        let first = 3 * slot as u16;
        {
            // On the panic path the holder may have been stopped for good.
            let mut queue = if crate::crash::is_panicking() {
                self.queue.try_lock().ok_or(BlockError::Busy)?
            } else {
                self.queue.lock()
            };
            self.completions[slot].arm();
            let (header_physical, outcome_physical) = (memory.physical_at(HEADER), memory.physical_at(OUTCOME));
            if data > 0 {
                let direction = if kind == REQUEST_READ { DESCRIPTOR_WRITE } else { 0 };
                queue.describe(first, header_physical, 16, DESCRIPTOR_NEXT, first + 1);
                queue.describe(first + 1, memory.physical_at(BOUNCE), data as u32, DESCRIPTOR_NEXT | direction, first + 2);
            } else {
                queue.describe(first, header_physical, 16, DESCRIPTOR_NEXT, first + 2);
            }
            queue.describe(first + 2, outcome_physical, 1, DESCRIPTOR_WRITE, 0);
            queue.offer(first);
            // SAFETY: the legacy register block of this device.
            unsafe { Port::<u16>::new(self.port + REG_QUEUE_NOTIFY).write(0) };
        }

        self.completions[slot].wait(self.interrupts.load(Ordering::Acquire), &|| self.service(false))
    }

    /// Run `each` on a slot for every chunk the bounce buffer can carry. A slot
    /// whose request timed out is kept from reuse: the device may yet write it.
    fn chunked(
        &self,
        lba: u64,
        length: usize,
        mut each: impl FnMut(usize, u64, usize, usize) -> Result<(), BlockError>,
    ) -> Result<(), BlockError> {
        let sectors = validate(self.sectors, lba, length)?;
        let slot = self.slots.take(&|| self.service(false)).ok_or(BlockError::Busy)?;
        let per_chunk = BOUNCE_BYTES / SECTOR_SIZE;
        let mut done = 0;
        while done < sectors {
            let chunk = (sectors - done).min(per_chunk);
            if let Err(error) = each(slot, lba + done as u64, done * SECTOR_SIZE, chunk) {
                self.release(slot);
                return Err(error);
            }
            done += chunk;
        }
        self.slots.give(slot);
        Ok(())
    }

    /// Give a slot back, unless its request is still with the device -- a
    /// polled wait that timed out -- in which case its memory may yet be written.
    fn release(&self, slot: usize) {
        if !self.completions[slot].in_flight() {
            self.slots.give(slot);
        }
    }

    fn write_chunks(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.chunked(lba, buffer.len(), |slot, chunk_lba, offset, chunk| {
            let bytes = chunk * SECTOR_SIZE;
            // SAFETY: the slot's bounce buffer is `BOUNCE_BYTES`, and the chunk fits.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer[offset..].as_ptr(),
                    self.memory[slot].virtual_at(BOUNCE) as *mut u8,
                    bytes,
                );
            }
            self.request(slot, REQUEST_WRITE, chunk_lba, bytes)
        })
    }
}

impl BlockDevice for VirtioBlkDisk {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.chunked(lba, buffer.len(), |slot, chunk_lba, offset, chunk| {
            let bytes = chunk * SECTOR_SIZE;
            self.request(slot, REQUEST_READ, chunk_lba, bytes)?;
            // SAFETY: the device filled `bytes` of the slot's bounce buffer, and
            // the caller's buffer was validated to hold them.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.memory[slot].virtual_at(BOUNCE) as *const u8,
                    buffer[offset..].as_mut_ptr(),
                    bytes,
                );
            }
            Ok(())
        })
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.write_chunks(lba, buffer)
    }

    fn flush(&self) -> Result<(), BlockError> {
        // A device without the feature has no cache to flush, and says so by
        // not offering it.
        if !self.can_flush {
            return Ok(());
        }
        let slot = self.slots.take(&|| self.service(false)).ok_or(BlockError::Busy)?;
        let result = self.request(slot, REQUEST_FLUSH, 0, 0);
        self.release(slot);
        result
    }

    /// The panic path takes a free slot if there is one and polls; with every
    /// slot in flight it is `Busy`, as it would be behind any other lock.
    fn write_now(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.write_chunks(lba, buffer)?;
        self.flush()
    }

    fn stats(&self) -> BlockStats {
        self.slots.stats()
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
            Some(disk) => found.push(disk),
            None => crate::println!("warning: a virtio-blk device would not start"),
        }
    }
    found
}

fn on_interrupt(context: usize) {
    // SAFETY: the address of a disk leaked by `bring_up`, which lives forever.
    let disk = unsafe { &*(context as *const VirtioBlkDisk) };
    disk.service(true);
}

fn bring_up(address: pci::Address, window: u64) -> Option<Arc<dyn BlockDevice>> {
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
    // Read before MSI-X is on, while the configuration is where the legacy
    // layout first puts it.
    let sectors = unsafe {
        Port::<u32>::new(port + REG_CONFIG).read() as u64
            | (Port::<u32>::new(port + REG_CONFIG + 4).read() as u64) << 32
    };

    let queue = Queue::new(port, 0, window)?;
    let slots = MAX_SLOTS.min(queue.size as usize / 3);
    if slots == 0 {
        return None;
    }
    let memory = (0..slots as u64)
        .map(|slot| DmaRegion::new(SLOT_PAGES, window + (QUEUE_PAGES + slot * SLOT_PAGES) * 4096))
        .collect::<Option<Vec<_>>>()?;

    // Built before its interrupt can fire, and never freed, so the handler can
    // hold its address.
    let disk = Arc::new(VirtioBlkDisk {
        port,
        queue: Mutex::new(queue),
        slots: Slots::new(slots),
        memory,
        completions: (0..slots).map(|_| Completion::default()).collect(),
        sectors,
        can_flush,
        interrupts: AtomicBool::new(false),
    });
    let context = Arc::as_ptr(&disk) as usize;
    core::mem::forget(disk.clone());

    let routed = pci::route_msix(address, 0, on_interrupt, context).is_ok() && {
        // SAFETY: as above. MSI-X is on, so the vector registers exist; queue 0
        // is still selected from `Queue::new`. A device that cannot take the
        // vector reads back "none".
        unsafe {
            Port::<u16>::new(port + REG_CONFIG_VECTOR).write(NO_VECTOR);
            Port::<u16>::new(port + REG_QUEUE_VECTOR).write(0);
            Port::<u16>::new(port + REG_QUEUE_VECTOR).read() != NO_VECTOR
        }
    };

    // SAFETY: as above. The device may use the queue from here.
    unsafe {
        Port::<u8>::new(port + REG_STATUS).write(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK)
    };

    disk.interrupts.store(routed, Ordering::Release);
    Some(disk)
}
