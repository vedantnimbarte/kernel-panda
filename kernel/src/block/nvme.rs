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
//! Completion is polled, as with AHCI, and one command is in flight at a time:
//! every call here is synchronous, and a disk that is only ever asked one thing
//! at once has no use for an interrupt to say it has answered. Interrupts are
//! masked at the controller so its legacy pin, which nothing routes, stays
//! quiet.

use alloc::sync::Arc;
use alloc::vec::Vec;

use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::{validate, BlockDevice, BlockError, SECTOR_SIZE};
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

/// Entries per queue. One command is ever in flight, so this only has to be
/// more than one.
const QUEUE_ENTRIES: u16 = 8;

const ADMIN: usize = 0;
const IO: usize = 1;

// Layout of the controller's DMA region, a page apiece.
const PAGE_ADMIN_SQ: u64 = 0;
const PAGE_ADMIN_CQ: u64 = 1;
const PAGE_IO_SQ: u64 = 2;
const PAGE_IO_CQ: u64 = 3;
const PAGE_IDENTIFY: u64 = 4;
const PAGE_BOUNCE: u64 = 5;
const BOUNCE_BYTES: usize = 2 * 4096;
const REGION_FRAMES: u64 = 7;

/// Where controllers are mapped: registers first, their DMA region above.
const NVME_VIRT_BASE: u64 = 0x0000_7500_0000_0000;
const WINDOW_PAGES: u64 = 128;
const REGISTER_PAGES: u64 = 16;

const TIMEOUT_SPINS: u64 = 200_000_000;

struct Queue {
    /// Page of this queue's submission ring within the region, and its
    /// completion ring's.
    submission_page: u64,
    completion_page: u64,
    tail: u16,
    head: u16,
}

struct Controller {
    registers: u64,
    stride: u64,
    dma: DmaRegion,
    queues: [Queue; 2],
    next_command: u16,
}

pub struct NvmeDisk {
    controller: Mutex<Controller>,
    sectors: u64,
}

// SAFETY: every access to the registers and the shared memory holds
// `controller`, and the memory is owned for the disk's lifetime.
unsafe impl Send for NvmeDisk {}
// SAFETY: as above.
unsafe impl Sync for NvmeDisk {}

impl Controller {
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

    fn wait_ready(&self, ready: bool) -> Result<(), BlockError> {
        for _ in 0..TIMEOUT_SPINS {
            if (self.read32(REG_CSTS) & CSTS_READY != 0) == ready {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(BlockError::DeviceFault)
    }

    /// Submit one command on queue `queue` and wait for it.
    ///
    /// The completion slot the controller will use is cleared first, and the
    /// command carries an id that is never zero -- so the slot holding that id
    /// is the answer, with no phase bits to track.
    fn run(&mut self, queue: usize, mut command: [u8; 64]) -> Result<(), BlockError> {
        self.next_command = self.next_command.wrapping_add(1).max(1);
        let id = self.next_command;
        command[2..4].copy_from_slice(&id.to_le_bytes());

        let (submission, completion, tail, head) = {
            let q = &self.queues[queue];
            (
                self.dma.virtual_at(q.submission_page * 4096),
                self.dma.virtual_at(q.completion_page * 4096),
                q.tail,
                q.head,
            )
        };

        let slot = completion + head as u64 * 16;
        // SAFETY: both rings are pages of this controller's own DMA region, and
        // each index is below `QUEUE_ENTRIES`.
        unsafe {
            core::ptr::write_bytes(slot as *mut u8, 0, 16);
            core::ptr::copy_nonoverlapping(
                command.as_ptr(),
                (submission + tail as u64 * 64) as *mut u8,
                64,
            );
        }

        let queue_id = queue as u64;
        let new_tail = (tail + 1) % QUEUE_ENTRIES;
        self.queues[queue].tail = new_tail;
        self.write32(DOORBELLS + 2 * queue_id * self.stride, new_tail as u32);

        for _ in 0..TIMEOUT_SPINS {
            // SAFETY: the completion slot cleared above, which the controller
            // writes by DMA.
            let (answered, status) = unsafe {
                (
                    core::ptr::read_volatile((slot + 12) as *const u16),
                    core::ptr::read_volatile((slot + 14) as *const u16),
                )
            };
            if answered == id {
                let new_head = (head + 1) % QUEUE_ENTRIES;
                self.queues[queue].head = new_head;
                self.write32(DOORBELLS + (2 * queue_id + 1) * self.stride, new_head as u32);
                // Bit 0 is the phase tag; the status proper is above it.
                return if status >> 1 == 0 {
                    Ok(())
                } else {
                    Err(BlockError::DeviceFault)
                };
            }
            core::hint::spin_loop();
        }
        Err(BlockError::DeviceFault)
    }

    fn transfer(&mut self, opcode: u8, lba: u64, sectors: usize) -> Result<(), BlockError> {
        let bytes = sectors * SECTOR_SIZE;
        let mut command = [0u8; 64];
        command[0] = opcode;
        command[4..8].copy_from_slice(&1u32.to_le_bytes());
        command[24..32].copy_from_slice(&self.dma.physical_at(PAGE_BOUNCE * 4096).to_le_bytes());
        if bytes > 4096 {
            // The second page of the bounce buffer. Two pages is as far as PRP2
            // reaches without a list, which is why the buffer is two pages.
            command[32..40]
                .copy_from_slice(&self.dma.physical_at((PAGE_BOUNCE + 1) * 4096).to_le_bytes());
        }
        command[40..48].copy_from_slice(&lba.to_le_bytes());
        command[48..52].copy_from_slice(&((sectors - 1) as u32).to_le_bytes());
        self.run(IO, command)
    }
}

impl NvmeDisk {
    fn chunked(
        &self,
        lba: u64,
        length: usize,
        mut each: impl FnMut(&mut Controller, u64, usize, usize) -> Result<(), BlockError>,
    ) -> Result<(), BlockError> {
        let sectors = validate(self.sectors, lba, length)?;
        let mut controller = self.controller.lock();
        let per_chunk = BOUNCE_BYTES / SECTOR_SIZE;
        let mut done = 0;
        while done < sectors {
            let chunk = (sectors - done).min(per_chunk);
            each(&mut controller, lba + done as u64, done * SECTOR_SIZE, chunk)?;
            done += chunk;
        }
        Ok(())
    }

    fn write_locked(controller: &mut Controller, sectors_total: u64, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let sectors = validate(sectors_total, lba, buffer.len())?;
        let per_chunk = BOUNCE_BYTES / SECTOR_SIZE;
        let mut done = 0;
        while done < sectors {
            let chunk = (sectors - done).min(per_chunk);
            let bounce = controller.dma.virtual_at(PAGE_BOUNCE * 4096) as *mut u8;
            // SAFETY: the bounce buffer is `BOUNCE_BYTES` and the chunk fits.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer[done * SECTOR_SIZE..].as_ptr(),
                    bounce,
                    chunk * SECTOR_SIZE,
                );
            }
            controller.transfer(OPCODE_WRITE, lba + done as u64, chunk)?;
            done += chunk;
        }
        Ok(())
    }

    fn flush_locked(controller: &mut Controller) -> Result<(), BlockError> {
        let mut command = [0u8; 64];
        command[0] = OPCODE_FLUSH;
        command[4..8].copy_from_slice(&1u32.to_le_bytes());
        controller.run(IO, command)
    }
}

impl BlockDevice for NvmeDisk {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.chunked(lba, buffer.len(), |controller, chunk_lba, offset, chunk| {
            controller.transfer(OPCODE_READ, chunk_lba, chunk)?;
            let bounce = controller.dma.virtual_at(PAGE_BOUNCE * 4096) as *const u8;
            // SAFETY: the controller filled `chunk` sectors of the bounce
            // buffer, and `validate` kept the caller's buffer at least that long.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bounce,
                    buffer[offset..].as_mut_ptr(),
                    chunk * SECTOR_SIZE,
                );
            }
            Ok(())
        })
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        Self::write_locked(&mut self.controller.lock(), self.sectors, lba, buffer)
    }

    fn flush(&self) -> Result<(), BlockError> {
        Self::flush_locked(&mut self.controller.lock())
    }

    fn write_now(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let mut controller = self.controller.try_lock().ok_or(BlockError::Busy)?;
        Self::write_locked(&mut controller, self.sectors, lba, buffer)?;
        Self::flush_locked(&mut controller)
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
        if device.class != CLASS_STORAGE
            || device.subclass != SUBCLASS_NVM
            || device.prog_if != PROG_IF_NVME
        {
            continue;
        }
        let window = NVME_VIRT_BASE + slot * WINDOW_PAGES * 4096;
        slot += 1;
        match bring_up(device.address, window) {
            Some(disk) => found.push(Arc::new(disk)),
            None => crate::println!("warning: an NVMe controller would not start"),
        }
    }
    found
}

fn bring_up(address: pci::Address, window: u64) -> Option<NvmeDisk> {
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
    let mut controller = Controller {
        registers: window,
        stride: 0,
        dma,
        queues: [
            Queue { submission_page: PAGE_ADMIN_SQ, completion_page: PAGE_ADMIN_CQ, tail: 0, head: 0 },
            Queue { submission_page: PAGE_IO_SQ, completion_page: PAGE_IO_CQ, tail: 0, head: 0 },
        ],
        next_command: 0,
    };

    let capabilities = controller.read32(REG_CAP) as u64 | (controller.read32(REG_CAP + 4) as u64) << 32;
    controller.stride = 4 << ((capabilities >> 32) & 0xF);

    // Disabled, reconfigured, enabled. The admin queue's bases may only be set
    // while the controller is off.
    controller.write32(REG_CC, 0);
    controller.wait_ready(false).ok()?;
    let entries = (QUEUE_ENTRIES - 1) as u32;
    controller.write32(REG_AQA, entries << 16 | entries);
    controller.write64(REG_ASQ, controller.dma.physical_at(PAGE_ADMIN_SQ * 4096));
    controller.write64(REG_ACQ, controller.dma.physical_at(PAGE_ADMIN_CQ * 4096));
    controller.write32(REG_INTMS, u32::MAX);
    controller.write32(REG_CC, CC_ENTRY_SIZES | CC_ENABLE);
    controller.wait_ready(true).ok()?;

    // What namespace 1 is: its size, and the size of a block on it.
    let mut identify = [0u8; 64];
    identify[0] = OPCODE_IDENTIFY;
    identify[4..8].copy_from_slice(&1u32.to_le_bytes());
    identify[24..32].copy_from_slice(&controller.dma.physical_at(PAGE_IDENTIFY * 4096).to_le_bytes());
    controller.run(ADMIN, identify).ok()?;

    let namespace = controller.dma.virtual_at(PAGE_IDENTIFY * 4096);
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

    // The I/O queue pair: completions first, since a submission queue names the
    // completion queue it reports to. Both commands put the queue's id, its size
    // and its flags in the same places; the submission queue then names its
    // completion queue in the word after -- not in the word the size shares, which
    // is what the first version of this assumed, and which QEMU's trace answered
    // with "invalid cqid=0".
    let mut create = [0u8; 64];
    create[0] = OPCODE_CREATE_IO_CQ;
    create[24..32].copy_from_slice(&controller.dma.physical_at(PAGE_IO_CQ * 4096).to_le_bytes());
    create[40..42].copy_from_slice(&1u16.to_le_bytes()); // queue 1
    create[42..44].copy_from_slice(&(entries as u16).to_le_bytes());
    create[44..46].copy_from_slice(&1u16.to_le_bytes()); // physically contiguous
    controller.run(ADMIN, create).ok()?;

    let mut create = [0u8; 64];
    create[0] = OPCODE_CREATE_IO_SQ;
    create[24..32].copy_from_slice(&controller.dma.physical_at(PAGE_IO_SQ * 4096).to_le_bytes());
    create[40..42].copy_from_slice(&1u16.to_le_bytes()); // queue 1
    create[42..44].copy_from_slice(&(entries as u16).to_le_bytes());
    create[44..46].copy_from_slice(&1u16.to_le_bytes()); // physically contiguous
    create[46..48].copy_from_slice(&1u16.to_le_bytes()); // reporting to completion queue 1
    controller.run(ADMIN, create).ok()?;

    Some(NvmeDisk {
        controller: Mutex::new(controller),
        sectors,
    })
}
