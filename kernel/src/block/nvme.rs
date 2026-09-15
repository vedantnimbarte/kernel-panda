//! NVMe: the interface nearly every machine built this decade puts its disk on.
//!
//! No task files and no ATA. The controller is a pair of rings per queue: the
//! driver appends a 64-byte command to a submission queue and rings a doorbell,
//! and the controller appends a 16-byte completion to the matching completion
//! queue. Queue 0 is the admin queue, which is how the driver asks the
//! controller about itself and creates the I/O queue that reads and writes go
//! through.
//!
//! ```text
//! registers   BAR 0: capabilities, configuration, status, admin queue bases
//! doorbells   0x1000 + (2 * queue + 0 or 1) * stride: submission tail, completion head
//! ```
//!
//! The admin queue is used only while the controller is brought up, one
//! command at a time, polled. The I/O queue carries a command per request slot,
//! each tagged with its slot's number and pointing at its slot's bounce buffer,
//! and the controller announces completions on an MSI-X vector of its own; see
//! [`super::request`] for who sleeps and who polls.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::request::{Completion, Slots};
use super::{validate, BlockDevice, BlockError, BlockStats, SECTOR_SIZE};
use crate::memory::dma::DmaRegion;
use crate::memory::paging;
use crate::pci::{self, Bar};
use crate::sync::Mutex;

/// Mass storage, non-volatile memory, NVM Express.
const CLASS_STORAGE: u8 = 0x01;
const SUBCLASS_NVM: u8 = 0x08;
const PROG_IF_NVME: u8 = 0x02;

const REG_CAP: u64 = 0x00;
const REG_INTMS: u64 = 0x0C;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
const DOORBELLS: u64 = 0x1000;

/// Controller configuration: enabled, NVM command set, 4 KiB pages, and entry
/// sizes of 2^6 bytes for submissions and 2^4 for completions.
const CC_ENABLE: u32 = 1;
const CC_ENTRY_SIZES: u32 = (6 << 16) | (4 << 20);
const CSTS_READY: u32 = 1;

const OPCODE_CREATE_IO_SQ: u8 = 0x01;
const OPCODE_CREATE_IO_CQ: u8 = 0x05;
const OPCODE_IDENTIFY: u8 = 0x06;
const OPCODE_FLUSH: u8 = 0x00;
const OPCODE_WRITE: u8 = 0x01;
const OPCODE_READ: u8 = 0x02;

/// Entries per queue. A ring holds one fewer than it has entries, so the I/O
/// queue's slots stay clear of that.
const QUEUE_ENTRIES: u16 = 16;
const SLOTS: usize = 8;

// Layout of the controller's DMA region, a page apiece, then two bounce pages
// per slot.
const PAGE_ADMIN_SQ: u64 = 0;
const PAGE_ADMIN_CQ: u64 = 1;
const PAGE_IO_SQ: u64 = 2;
const PAGE_IO_CQ: u64 = 3;
const PAGE_IDENTIFY: u64 = 4;
const PAGE_BOUNCE: u64 = 5;
/// Two pages is as far as PRP2 reaches without a list.
const BOUNCE_PAGES: u64 = 2;
const BOUNCE_BYTES: usize = BOUNCE_PAGES as usize * 4096;
const REGION_FRAMES: u64 = PAGE_BOUNCE + SLOTS as u64 * BOUNCE_PAGES;

/// Where controllers are mapped: registers first, their DMA region above.
const NVME_VIRT_BASE: u64 = 0x0000_7500_0000_0000;
const WINDOW_PAGES: u64 = 128;
const REGISTER_PAGES: u64 = 16;

const TIMEOUT_SPINS: u64 = 200_000_000;

const ADMIN: u64 = 0;
const IO: u64 = 1;

/// The I/O completion queue's reading position.
struct Reader {
    head: u16,
    /// The phase tag a new entry carries. Starts at 1 against zeroed memory and
    /// flips each time the head wraps, when every older entry carries the old one.
    phase: u16,
}

pub struct NvmeDisk {
    registers: u64,
    stride: u64,
    dma: DmaRegion,
    /// Admin queue positions and the last command id, for bring-up.
    admin: Mutex<(u16, u16, u16)>,
    /// The I/O submission queue's tail.
    submit: Mutex<u16>,
    reader: Mutex<Reader>,
    slots: Slots,
    completions: Vec<Completion>,
    sectors: u64,
    interrupts: AtomicBool,
}

// SAFETY: the registers are written under the lock for the queue concerned,
// and a slot's bounce buffer is touched only by the request holding the slot.
unsafe impl Send for NvmeDisk {}
// SAFETY: as above.
unsafe impl Sync for NvmeDisk {}

impl NvmeDisk {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: a register inside the mapped BAR.
        unsafe { core::ptr::read_volatile((self.registers + offset) as *const u32) }
    }

    fn write32(&self, offset: u64, value: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u32, value) };
    }

    fn write64(&self, offset: u64, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }

    fn doorbell(&self, queue: u64, completion: bool, value: u16) {
        self.write32(DOORBELLS + (2 * queue + completion as u64) * self.stride, value as u32);
    }

    fn wait_ready(&self, ready: bool) -> Result<(), BlockError> {
        for _ in 0..TIMEOUT_SPINS {
            if (self.read32(REG_CSTS) & CSTS_READY != 0) == ready {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(BlockError::DeviceFault)
    }

    /// Run one admin command and wait for it, polled.
    ///
    /// The completion slot the controller will use is cleared first, and the
    /// command carries an id that is never zero -- so the slot holding that id
    /// is the answer, with no phase bits to track.
    fn admin(&self, mut command: [u8; 64]) -> Result<(), BlockError> {
        let mut admin = self.admin.lock();
        let (tail, head, last) = &mut *admin;
        *last = last.wrapping_add(1).max(1);
        command[2..4].copy_from_slice(&last.to_le_bytes());

        let slot = self.dma.virtual_at(PAGE_ADMIN_CQ * 4096) + *head as u64 * 16;
        // SAFETY: both rings are pages of this controller's own DMA region, and
        // each index is below `QUEUE_ENTRIES`.
        unsafe {
            core::ptr::write_bytes(slot as *mut u8, 0, 16);
            core::ptr::copy_nonoverlapping(
                command.as_ptr(),
                (self.dma.virtual_at(PAGE_ADMIN_SQ * 4096) + *tail as u64 * 64) as *mut u8,
                64,
            );
        }
        *tail = (*tail + 1) % QUEUE_ENTRIES;
        self.doorbell(ADMIN, false, *tail);

        for _ in 0..TIMEOUT_SPINS {
            // SAFETY: the completion slot cleared above, which the controller
            // writes by DMA.
            let (answered, status) = unsafe {
                (core::ptr::read_volatile((slot + 12) as *const u16), core::ptr::read_volatile((slot + 14) as *const u16))
            };
            if answered == *last {
                *head = (*head + 1) % QUEUE_ENTRIES;
                self.doorbell(ADMIN, true, *head);
                // Bit 0 is the phase tag; the status proper is above it.
                return if status >> 1 == 0 { Ok(()) } else { Err(BlockError::DeviceFault) };
            }
            core::hint::spin_loop();
        }
        Err(BlockError::DeviceFault)
    }

    /// Collect every I/O completion the controller has posted.
    fn service(&self, from_interrupt: bool) {
        let reader = if crate::crash::is_panicking() { self.reader.try_lock() } else { Some(self.reader.lock()) };
        let Some(mut reader) = reader else {
            return;
        };
        let base = self.dma.virtual_at(PAGE_IO_CQ * 4096);
        let mut advanced = false;
        loop {
            let entry = base + reader.head as u64 * 16;
            // SAFETY: an entry of the I/O completion ring, in this controller's
            // DMA region, which the controller writes.
            let (slot, status) = unsafe {
                (core::ptr::read_volatile((entry + 12) as *const u16), core::ptr::read_volatile((entry + 14) as *const u16))
            };
            if status & 1 != reader.phase {
                break;
            }
            reader.head = (reader.head + 1) % QUEUE_ENTRIES;
            if reader.head == 0 {
                reader.phase ^= 1;
            }
            advanced = true;
            if let Some(completion) = self.completions.get(slot as usize) {
                if from_interrupt {
                    self.slots.interrupt_completions.fetch_add(1, Ordering::Relaxed);
                }
                completion.finish(status >> 1 == 0);
            }
        }
        if advanced {
            self.doorbell(IO, true, reader.head);
        }
    }

    /// Submit `command` on `slot` and wait for it.
    fn run(&self, slot: usize, mut command: [u8; 64]) -> Result<(), BlockError> {
        command[2..4].copy_from_slice(&(slot as u16).to_le_bytes());
        {
            let mut tail = if crate::crash::is_panicking() {
                self.submit.try_lock().ok_or(BlockError::Busy)?
            } else {
                self.submit.lock()
            };
            // SAFETY: an entry of the I/O submission ring; a ring of 16 never
            // fills with 8 slots.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    command.as_ptr(),
                    (self.dma.virtual_at(PAGE_IO_SQ * 4096) + *tail as u64 * 64) as *mut u8,
                    64,
                );
            }
            self.completions[slot].arm();
            *tail = (*tail + 1) % QUEUE_ENTRIES;
            self.doorbell(IO, false, *tail);
        }
        self.completions[slot].wait(self.interrupts.load(Ordering::Acquire), &|| self.service(false))
    }

    fn bounce(&self, slot: usize) -> u64 {
        (PAGE_BOUNCE + slot as u64 * BOUNCE_PAGES) * 4096
    }

    fn transfer(&self, slot: usize, opcode: u8, lba: u64, sectors: usize) -> Result<(), BlockError> {
        let bytes = sectors * SECTOR_SIZE;
        let mut command = [0u8; 64];
        command[0] = opcode;
        command[4..8].copy_from_slice(&1u32.to_le_bytes());
        command[24..32].copy_from_slice(&self.dma.physical_at(self.bounce(slot)).to_le_bytes());
        if bytes > 4096 {
            command[32..40].copy_from_slice(&self.dma.physical_at(self.bounce(slot) + 4096).to_le_bytes());
        }
        command[40..48].copy_from_slice(&lba.to_le_bytes());
        command[48..52].copy_from_slice(&((sectors - 1) as u32).to_le_bytes());
        self.run(slot, command)
    }

    /// Give a slot back, unless its command is still with the controller.
    fn release(&self, slot: usize) {
        if !self.completions[slot].in_flight() {
            self.slots.give(slot);
        }
    }

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
}

impl BlockDevice for NvmeDisk {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.chunked(lba, buffer.len(), |slot, chunk_lba, offset, chunk| {
            self.transfer(slot, OPCODE_READ, chunk_lba, chunk)?;
            // SAFETY: the controller filled `chunk` sectors of the slot's bounce
            // buffer, and `validate` kept the caller's buffer at least that long.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.dma.virtual_at(self.bounce(slot)) as *const u8,
                    buffer[offset..].as_mut_ptr(),
                    chunk * SECTOR_SIZE,
                );
            }
            Ok(())
        })
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.chunked(lba, buffer.len(), |slot, chunk_lba, offset, chunk| {
            // SAFETY: the slot's bounce buffer is `BOUNCE_BYTES` and the chunk fits.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer[offset..].as_ptr(),
                    self.dma.virtual_at(self.bounce(slot)) as *mut u8,
                    chunk * SECTOR_SIZE,
                );
            }
            self.transfer(slot, OPCODE_WRITE, chunk_lba, chunk)
        })
    }

    fn flush(&self) -> Result<(), BlockError> {
        let slot = self.slots.take(&|| self.service(false)).ok_or(BlockError::Busy)?;
        let mut command = [0u8; 64];
        command[0] = OPCODE_FLUSH;
        command[4..8].copy_from_slice(&1u32.to_le_bytes());
        let result = self.run(slot, command);
        self.release(slot);
        result
    }

    /// The panic path takes a free slot if there is one and polls; with every
    /// slot in flight it is `Busy`.
    fn write_now(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.write(lba, buffer)?;
        self.flush()
    }

    fn stats(&self) -> BlockStats {
        self.slots.stats()
    }
}

/// Find every NVMe controller and bring up namespace 1 on each.
///
/// # Safety
///
/// Call once, during boot, after PCI and paging are up.
pub unsafe fn probe() -> Vec<Arc<dyn BlockDevice>> {
    let mut found: Vec<Arc<dyn BlockDevice>> = Vec::new();
    let mut slot = 0;
    for device in pci::enumerate() {
        if device.class != CLASS_STORAGE || device.subclass != SUBCLASS_NVM || device.prog_if != PROG_IF_NVME {
            continue;
        }
        let window = NVME_VIRT_BASE + slot * WINDOW_PAGES * 4096;
        slot += 1;
        match bring_up(device.address, window) {
            Some(disk) => found.push(disk),
            None => crate::println!("warning: an NVMe controller would not start"),
        }
    }
    found
}

fn on_interrupt(context: usize) {
    // SAFETY: the address of a disk leaked by `bring_up`, which lives forever.
    let disk = unsafe { &*(context as *const NvmeDisk) };
    disk.service(true);
}

fn bring_up(address: pci::Address, window: u64) -> Option<Arc<dyn BlockDevice>> {
    let Some(Bar::Memory { address: base, size, .. }) = pci::read_bar(address, 0) else {
        return None;
    };

    // Memory decoding and bus mastering; firmware may have left either off.
    let command = pci::read_config(address, 0x04);
    // SAFETY: enabling decoding and mastering on a controller this driver owns.
    unsafe { pci::write_config(address, 0x04, command | 0b110) };

    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;
    for page in 0..size.div_ceil(4096).min(REGISTER_PAGES) {
        // SAFETY: the controller's own register space, at a virtual range
        // reserved for it.
        unsafe {
            paging::map_to_frame(
                Page::<Size4KiB>::containing_address(VirtAddr::new(window + page * 4096)),
                PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(base + page * 4096)),
                flags,
            )
        }
        .ok()?;
    }

    let dma = DmaRegion::new(REGION_FRAMES, window + REGISTER_PAGES * 4096)?;
    let mut disk = NvmeDisk {
        registers: window,
        stride: 0,
        dma,
        admin: Mutex::new((0, 0, 0)),
        submit: Mutex::new(0),
        reader: Mutex::new(Reader { head: 0, phase: 1 }),
        slots: Slots::new(SLOTS),
        completions: (0..SLOTS).map(|_| Completion::default()).collect(),
        sectors: 0,
        interrupts: AtomicBool::new(false),
    };

    let capabilities = disk.read32(REG_CAP) as u64 | (disk.read32(REG_CAP + 4) as u64) << 32;
    disk.stride = 4 << ((capabilities >> 32) & 0xF);

    // Disabled, reconfigured, enabled. The admin queue's bases may only be set
    // while the controller is off.
    disk.write32(REG_CC, 0);
    disk.wait_ready(false).ok()?;
    let entries = (QUEUE_ENTRIES - 1) as u32;
    disk.write32(REG_AQA, entries << 16 | entries);
    disk.write64(REG_ASQ, disk.dma.physical_at(PAGE_ADMIN_SQ * 4096));
    disk.write64(REG_ACQ, disk.dma.physical_at(PAGE_ADMIN_CQ * 4096));
    // The legacy pin stays quiet; MSI-X, if it is routed, does not consult this.
    disk.write32(REG_INTMS, u32::MAX);
    disk.write32(REG_CC, CC_ENTRY_SIZES | CC_ENABLE);
    disk.wait_ready(true).ok()?;

    // What namespace 1 is: its size, and the size of a block on it.
    let mut identify = [0u8; 64];
    identify[0] = OPCODE_IDENTIFY;
    identify[4..8].copy_from_slice(&1u32.to_le_bytes());
    identify[24..32].copy_from_slice(&disk.dma.physical_at(PAGE_IDENTIFY * 4096).to_le_bytes());
    disk.admin(identify).ok()?;

    let namespace = disk.dma.virtual_at(PAGE_IDENTIFY * 4096);
    // SAFETY: the identify page the controller just filled.
    let (sectors, block_shift) = unsafe {
        let sectors = core::ptr::read_volatile(namespace as *const u64);
        let format = core::ptr::read_volatile((namespace + 26) as *const u8) & 0xF;
        let shift = core::ptr::read_volatile((namespace + 128 + 4 * format as u64 + 2) as *const u8);
        (sectors, shift)
    };
    // Everything above this layer speaks 512-byte sectors. A namespace
    // formatted with 4 KiB blocks is refused rather than silently misaddressed.
    if block_shift != 9 {
        crate::println!("warning: NVMe namespace 1 has {}-byte blocks; only 512 is supported", 1u64 << block_shift);
        return None;
    }
    disk.sectors = sectors;

    // Never freed, so the interrupt handler can hold its address. MSI-X entry 0
    // stays with the admin queue, which is polled; entry 1 is the I/O queue's.
    let disk = Arc::new(disk);
    let context = Arc::as_ptr(&disk) as usize;
    core::mem::forget(disk.clone());
    let routed = pci::route_msix(address, 1, on_interrupt, context).is_ok();

    // The I/O queue pair: completions first, since a submission queue names the
    // completion queue it reports to. Both commands put the queue's id, its size
    // and its flags in the same places; the submission queue then names its
    // completion queue in the word after -- not in the word the size shares, which
    // is what the first version of this assumed, and which QEMU's trace answered
    // with "invalid cqid=0". The completion queue's word after is its interrupt
    // vector.
    let mut create = [0u8; 64];
    create[0] = OPCODE_CREATE_IO_CQ;
    create[24..32].copy_from_slice(&disk.dma.physical_at(PAGE_IO_CQ * 4096).to_le_bytes());
    create[40..42].copy_from_slice(&1u16.to_le_bytes()); // queue 1
    create[42..44].copy_from_slice(&(entries as u16).to_le_bytes());
    // Physically contiguous, and interrupting on MSI-X entry 1 if it was routed.
    create[44..46].copy_from_slice(&(1u16 | (routed as u16) << 1).to_le_bytes());
    create[46..48].copy_from_slice(&(routed as u16).to_le_bytes());
    disk.admin(create).ok()?;

    let mut create = [0u8; 64];
    create[0] = OPCODE_CREATE_IO_SQ;
    create[24..32].copy_from_slice(&disk.dma.physical_at(PAGE_IO_SQ * 4096).to_le_bytes());
    create[40..42].copy_from_slice(&1u16.to_le_bytes()); // queue 1
    create[42..44].copy_from_slice(&(entries as u16).to_le_bytes());
    create[44..46].copy_from_slice(&1u16.to_le_bytes()); // physically contiguous
    create[46..48].copy_from_slice(&1u16.to_le_bytes()); // reporting to completion queue 1
    disk.admin(create).ok()?;

    disk.interrupts.store(routed, Ordering::Release);
    Some(disk)
}
