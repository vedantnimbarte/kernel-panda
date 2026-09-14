//! AHCI: the interface almost every x86 machine exposes for SATA.
//!
//! The controller is found over PCI (class 0x01, subclass 0x06) and its
//! registers live in BAR 5. Everything after that is a conversation conducted
//! through memory the *device* reads, not the CPU: a command list, a command
//! table per slot, and a scatter-gather list of where the data should land. The
//! CPU writes those structures, sets a bit, and waits.
//!
//! Reads and writes go through native command queueing where the controller and
//! the drive both offer it: each request slot is a tag of the queue, with a
//! command table and bounce buffer of its own, and the drive answers them in
//! whatever order it likes. Flush and identify are not queued commands, so they
//! take every slot and run alone. The controller interrupts by MSI; see
//! [`super::request`] for who sleeps and who polls.
//!
//! ```text
//! HBA registers        generic control at 0x00, then ports at 0x100 + n * 0x80
//! command list         32 headers x 32 bytes, 1 KiB aligned
//! received FIS         256 bytes, 256-byte aligned
//! command table        command FIS, then ATAPI, then the scatter-gather list
//! ```
//!
//! Three things about this code are load-bearing and easy to get wrong:
//!
//! * Every structure the controller reads is described to it by **physical**
//!   address, and is reached by the CPU through the physical-memory window. A
//!   virtual address handed to the device points at whatever happens to live at
//!   that physical address instead, which is memory corruption with no fault.
//! * Those structures must be **physically contiguous**. The frame allocator's
//!   contiguous path exists for exactly this.
//! * The mapping the CPU uses must be **uncached**, or a status byte the device
//!   updated by DMA can be answered from a cache line fetched before it did.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::request::{Completion, Slots};
use super::{validate, BlockDevice, BlockError, BlockStats, SECTOR_SIZE};
use crate::memory::dma::DmaRegion;
use crate::memory::paging;
use crate::pci;
use crate::sync::Mutex;

/// PCI class 0x01 subclass 0x06: a SATA controller. Programming interface 0x01
/// means it speaks AHCI rather than a vendor's own thing.
const CLASS_STORAGE: u8 = 0x01;
const SUBCLASS_SATA: u8 = 0x06;
const PROG_IF_AHCI: u8 = 0x01;

// Generic host control.
const REG_CAP: u64 = 0x00;
const REG_GHC: u64 = 0x04;
const REG_IS: u64 = 0x08;
const REG_PI: u64 = 0x0C;

/// GHC bit 31: hand the controller to the driver rather than to legacy IDE
/// emulation.
const GHC_AHCI_ENABLE: u32 = 1 << 31;
/// GHC bit 1: let the controller interrupt.
const GHC_INTERRUPT_ENABLE: u32 = 1 << 1;
/// CAP bit 30: the controller does native command queueing. Bits 4..0: how
/// many command slots it has, minus one.
const CAP_NCQ: u32 = 1 << 30;

/// CAP bit 31: the controller can address memory above 4 GiB.
const CAP_ADDR64: u32 = 1 << 31;

// Port registers, offsets from the port's base.
const PORT_CLB: u64 = 0x00;
const PORT_CLBU: u64 = 0x04;
const PORT_FB: u64 = 0x08;
const PORT_FBU: u64 = 0x0C;
const PORT_IS: u64 = 0x10;
const PORT_IE: u64 = 0x14;
const PORT_CMD: u64 = 0x18;
const PORT_TFD: u64 = 0x20;
const PORT_SIG: u64 = 0x24;
const PORT_SSTS: u64 = 0x28;
const PORT_SERR: u64 = 0x30;
const PORT_SACT: u64 = 0x34;
const PORT_CI: u64 = 0x38;

/// PxIE: a register FIS (a plain command finishing), a set-device-bits FIS (a
/// queued one finishing), and a task-file error.
const IE_ANSWERS: u32 = 1 << 0 | 1 << 3 | 1 << 30;

/// PxCMD bit 0: start processing the command list.
const CMD_START: u32 = 1 << 0;
/// PxCMD bit 4: the receive-FIS engine is running.
const CMD_FIS_RECEIVE_ENABLE: u32 = 1 << 4;
/// PxCMD bit 14: the receive-FIS engine has actually stopped.
const CMD_FIS_RECEIVE_RUNNING: u32 = 1 << 14;
/// PxCMD bit 15: the command engine has actually stopped.
const CMD_LIST_RUNNING: u32 = 1 << 15;

/// PxTFD bit 0: the last command failed.
const TFD_ERROR: u32 = 1 << 0;

/// PxIS bit 30: a task-file error. The one interrupt status bit that means the
/// command did not work rather than that it finished.
const IS_TASK_FILE_ERROR: u32 = 1 << 30;

/// PxSSTS bits 3..0 == 3: a device is present and communication established.
const SSTS_PRESENT: u32 = 0x3;

/// PxSIG for a plain SATA disk. Anything else -- an optical drive, a port
/// multiplier, an enclosure -- is skipped rather than guessed at.
const SIG_SATA_DISK: u32 = 0x0000_0101;

// ATA commands.
const ATA_IDENTIFY: u8 = 0xEC;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE_EXT: u8 = 0xEA;
const ATA_READ_FPDMA_QUEUED: u8 = 0x60;
const ATA_WRITE_FPDMA_QUEUED: u8 = 0x61;

/// Where AHCI register windows are mapped.
const AHCI_VIRT_BASE: u64 = 0x0000_7200_0000_0000;

/// Bound on every wait for the controller. Long enough for a real disk to
/// answer a flush, short enough that a dead controller does not hang the boot.
const TIMEOUT_SPINS: u64 = 200_000_000;

/// One command header, as the controller reads it.
#[repr(C)]
#[derive(Clone, Copy)]
struct CommandHeader {
    /// Low 5 bits: command FIS length in dwords. Bit 6: this is a write.
    flags: u16,
    /// Scatter-gather entries in the table below.
    prdt_length: u16,
    /// Written by the controller: bytes actually transferred.
    transferred: u32,
    /// Physical address of the command table.
    table_address: u64,
    reserved: [u32; 4],
}

/// One scatter-gather entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct PrdtEntry {
    address: u64,
    reserved: u32,
    /// Low 22 bits: byte count minus one. Bit 31: interrupt when done.
    count: u32,
}

/// The per-slot command table: the FIS the device executes, then the list of
/// places its data goes.
#[repr(C)]
struct CommandTable {
    command_fis: [u8; 64],
    atapi_command: [u8; 16],
    reserved: [u8; 48],
    prdt: [PrdtEntry; PRDT_ENTRIES],
}

/// Scatter-gather entries per command. Each covers up to 4 MiB, so this bounds
/// a single transfer at far more than anything here asks for.
const PRDT_ENTRIES: usize = 8;

// Layout within the port's DMA region: a page for the command list and the
// received FIS, then for each slot a page for its command table and two for its
// bounce buffer.
const OFFSET_COMMAND_LIST: u64 = 0;
const OFFSET_RECEIVED_FIS: u64 = 1024;
const SLOT_BASE: u64 = 4096;
const SLOT_PAGES: u64 = 3;
const BOUNCE_BYTES: u64 = 2 * 4096;
const MAX_SLOTS: usize = 8;
const REGION_FRAMES: u64 = 1 + MAX_SLOTS as u64 * SLOT_PAGES;

/// What is with the device, as far as the driver has told it.
struct Issued {
    /// Queued commands, by tag, which is also their slot.
    queued: u32,
    /// A command outside the queue, on slot 0. Only ever alone.
    plain: bool,
}

/// One SATA disk on one port.
pub struct AhciDisk {
    /// Virtual base of this port's registers.
    port: u64,
    /// Which port: its bit in the controller's interrupt status.
    index: u32,
    /// The structures the controller reads.
    dma: DmaRegion,
    sectors: u64,
    /// Whether reads and writes go through native command queueing. Without
    /// it, the drive takes one command at a time and so does this driver.
    queued: AtomicBool,
    issued: Mutex<Issued>,
    slots: Slots,
    completions: Vec<Completion>,
    interrupts: AtomicBool,
}

// SAFETY: the port's registers are written under `issued`, and a slot's command
// table and bounce buffer are touched only by the request holding the slot.
unsafe impl Send for AhciDisk {}
// SAFETY: as above.
unsafe impl Sync for AhciDisk {}

impl AhciDisk {
    /// # Safety
    ///
    /// `base` must be a mapped, uncached AHCI register window, and `offset` a
    /// register within it.
    unsafe fn read_reg(&self, offset: u64) -> u32 {
        // SAFETY: forwarded from this function's contract.
        unsafe { core::ptr::read_volatile((self.port + offset) as *const u32) }
    }

    /// # Safety
    ///
    /// As [`Self::read_reg`].
    unsafe fn write_reg(&self, offset: u64, value: u32) {
        // SAFETY: forwarded from this function's contract.
        unsafe { core::ptr::write_volatile((self.port + offset) as *mut u32, value) };
    }

    fn table(&self, slot: usize) -> u64 {
        SLOT_BASE + slot as u64 * SLOT_PAGES * 4096
    }

    fn bounce(&self, slot: usize) -> u64 {
        self.table(slot) + 4096
    }

    /// Build the command on `slot`: its FIS in the slot's table, and the slot's
    /// header in the command list pointing at it.
    fn build(&self, slot: usize, fis_bytes: [u8; 20], bytes: u64, write: bool) {
        let header = (self.dma.virtual_at(OFFSET_COMMAND_LIST) + slot as u64 * 32) as *mut CommandHeader;
        let table = self.dma.virtual_at(self.table(slot)) as *mut CommandTable;
        // SAFETY: both point into this disk's own DMA region, which is mapped
        // writable, and the caller holds `slot`, so nothing else is here.
        unsafe {
            core::ptr::write_bytes(table as *mut u8, 0, core::mem::size_of::<CommandTable>());
            let fis = &mut (*table).command_fis;
            fis[..20].copy_from_slice(&fis_bytes);
            if bytes > 0 {
                (*table).prdt[0] = PrdtEntry {
                    address: self.dma.physical_at(self.bounce(slot)),
                    reserved: 0,
                    // The count is a byte count *minus one*, which is the single
                    // most common way to transfer one sector too few.
                    count: (bytes as u32 - 1) & 0x003F_FFFF,
                };
            }
            (*header).flags = (fis_bytes.len() as u16 / 4) | if write { 1 << 6 } else { 0 };
            (*header).prdt_length = if bytes > 0 { 1 } else { 0 };
            (*header).transferred = 0;
            (*header).table_address = self.dma.physical_at(self.table(slot));
        }
        // Everything above must be visible to the device before the bit that
        // tells it to look. The mapping is uncached so there is no cache to
        // flush, but the compiler must not sink those stores past this point.
        compiler_fence(Ordering::SeqCst);
    }

    fn issued(&self) -> Result<crate::sync::MutexGuard<'_, Issued>, BlockError> {
        // On the panic path the holder may have been stopped for good.
        if crate::crash::is_panicking() {
            self.issued.try_lock().ok_or(BlockError::Busy)
        } else {
            Ok(self.issued.lock())
        }
    }

    /// Hand the device a queued command on `slot` and wait for it.
    fn run_queued(&self, slot: usize, write: bool, lba: u64, sectors: u16) -> Result<(), BlockError> {
        let mut fis = [0u8; 20];
        // FIS type 0x27: host to device, and bit 7 of byte 1 says this is a
        // command rather than a control update.
        fis[0] = 0x27;
        fis[1] = 0x80;
        fis[2] = if write { ATA_WRITE_FPDMA_QUEUED } else { ATA_READ_FPDMA_QUEUED };
        // Queued commands carry the count where others carry features, and the
        // tag where others carry the count.
        fis[3] = sectors as u8;
        fis[11] = (sectors >> 8) as u8;
        fis[12] = (slot as u8) << 3;
        put_lba(&mut fis, lba);
        self.build(slot, fis, sectors as u64 * SECTOR_SIZE as u64, write);

        {
            let mut issued = self.issued()?;
            self.completions[slot].arm();
            issued.queued |= 1 << slot;
            // SAFETY: the register window is mapped. Both registers are
            // write-one-to-set, so other slots' bits are untouched.
            unsafe {
                self.write_reg(PORT_SACT, 1 << slot);
                self.write_reg(PORT_CI, 1 << slot);
            }
        }
        self.completions[slot].wait(self.interrupts.load(Ordering::Acquire), &|| self.service(false))
    }

    /// Run a command outside the queue on slot 0. The caller holds every slot,
    /// so nothing else is with the device.
    fn run_plain(&self, command: u8, lba: u64, sectors: u16, bytes: u64, write: bool) -> Result<(), BlockError> {
        let mut fis = [0u8; 20];
        fis[0] = 0x27;
        fis[1] = 0x80;
        fis[2] = command;
        put_lba(&mut fis, lba);
        fis[12] = sectors as u8;
        fis[13] = (sectors >> 8) as u8;
        self.build(0, fis, bytes, write);

        {
            let mut issued = self.issued()?;
            self.completions[0].arm();
            issued.plain = true;
            // SAFETY: the register window is mapped.
            unsafe { self.write_reg(PORT_CI, 1) };
        }
        self.completions[0].wait(self.interrupts.load(Ordering::Acquire), &|| self.service(false))
    }

    /// Collect what the device has finished. The interrupt handler and a
    /// polling waiter both come here.
    fn service(&self, from_interrupt: bool) {
        let Ok(mut issued) = self.issued() else {
            return;
        };
        // SAFETY: the register window is mapped. Interrupt status is
        // write-one-to-clear, so this clears exactly what was read.
        let (status, active, commands, task_file) = unsafe {
            let status = self.read_reg(PORT_IS);
            self.write_reg(PORT_IS, status);
            (status, self.read_reg(PORT_SACT), self.read_reg(PORT_CI), self.read_reg(PORT_TFD))
        };
        let count = |n: u32| {
            if from_interrupt {
                self.slots.interrupt_completions.fetch_add(n as u64, Ordering::Relaxed);
            }
        };

        // An error stops the port and fails everything it was doing; the port
        // is restarted so the next command has somewhere to go.
        if status & IS_TASK_FILE_ERROR != 0 {
            for slot in 0..self.completions.len() {
                if issued.queued & (1 << slot) != 0 || (slot == 0 && issued.plain) {
                    self.completions[slot].finish(false);
                }
            }
            issued.queued = 0;
            issued.plain = false;
            self.restart();
            return;
        }

        let finished = issued.queued & !active;
        issued.queued &= !finished;
        count(finished.count_ones());
        for slot in (0..self.completions.len()).filter(|slot| finished & (1 << slot) != 0) {
            self.completions[slot].finish(true);
        }

        if issued.plain && commands & 1 == 0 {
            issued.plain = false;
            count(1);
            self.completions[0].finish(task_file & TFD_ERROR == 0);
        }
    }

    /// Stop the command engine and start it again, clearing the error that
    /// stopped it.
    fn restart(&self) {
        // SAFETY: the register window is mapped.
        unsafe {
            let command = self.read_reg(PORT_CMD);
            self.write_reg(PORT_CMD, command & !CMD_START);
            for _ in 0..TIMEOUT_SPINS {
                if self.read_reg(PORT_CMD) & CMD_LIST_RUNNING == 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            self.write_reg(PORT_SERR, u32::MAX);
            self.write_reg(PORT_IS, u32::MAX);
            self.write_reg(PORT_CMD, self.read_reg(PORT_CMD) | CMD_START);
        }
    }

    /// Give a slot back, unless its command is still with the device.
    fn release(&self, slot: usize) {
        if !self.completions[slot].in_flight() {
            self.slots.give(slot);
        }
    }

    /// Copy through bounce buffers in chunks they can hold: queued on one slot
    /// of its own, or alone on slot 0 with every slot held.
    ///
    /// The caller's buffer is ordinary kernel memory: it may be physically
    /// scattered, and handing its virtual address to a DMA engine would point
    /// the controller at unrelated physical pages.
    fn transfer(&self, lba: u64, length: usize, write: bool, mut copy: impl FnMut(u64, usize, usize, bool)) -> Result<(), BlockError> {
        let sectors = validate(self.sectors, lba, length)?;
        let service = || self.service(false);
        let queued = self.queued.load(Ordering::Acquire);
        let slot = if queued {
            self.slots.take(&service).ok_or(BlockError::Busy)?
        } else {
            self.slots.take_all(&service).ok_or(BlockError::Busy)?;
            0
        };

        let per_chunk = BOUNCE_BYTES as usize / SECTOR_SIZE;
        let mut done = 0usize;
        let mut result = Ok(());
        while done < sectors {
            let chunk = (sectors - done).min(per_chunk);
            let bytes = (chunk * SECTOR_SIZE) as u64;
            let bounce = self.dma.virtual_at(self.bounce(slot));
            if write {
                copy(bounce, done * SECTOR_SIZE, bytes as usize, true);
            }
            result = if queued {
                self.run_queued(slot, write, lba + done as u64, chunk as u16)
            } else {
                let command = if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT };
                self.run_plain(command, lba + done as u64, chunk as u16, bytes, write)
            };
            if result.is_err() {
                break;
            }
            if !write {
                copy(bounce, done * SECTOR_SIZE, bytes as usize, false);
            }
            done += chunk;
        }

        if queued {
            self.release(slot);
        } else if !self.completions[0].in_flight() {
            self.slots.give_all();
        }
        result
    }
}

fn put_lba(fis: &mut [u8; 20], lba: u64) {
    fis[4] = lba as u8;
    fis[5] = (lba >> 8) as u8;
    fis[6] = (lba >> 16) as u8;
    // Bit 6: LBA mode. The 28-bit-versus-48-bit distinction is in the command,
    // but this bit still has to be set or the device reads the address as
    // cylinder/head/sector.
    fis[7] = 1 << 6;
    fis[8] = (lba >> 24) as u8;
    fis[9] = (lba >> 32) as u8;
    fis[10] = (lba >> 40) as u8;
}

impl BlockDevice for AhciDisk {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.transfer(lba, buffer.len(), false, |bounce, offset, bytes, _| {
            // SAFETY: the controller filled `bytes` of the slot's bounce buffer,
            // and `validate` kept the caller's buffer at least that long.
            unsafe { core::ptr::copy_nonoverlapping(bounce as *const u8, buffer[offset..].as_mut_ptr(), bytes) };
        })
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.transfer(lba, buffer.len(), true, |bounce, offset, bytes, _| {
            // SAFETY: the slot's bounce buffer is `BOUNCE_BYTES`, and a chunk fits.
            unsafe { core::ptr::copy_nonoverlapping(buffer[offset..].as_ptr(), bounce as *mut u8, bytes) };
        })
    }

    /// Outside the queue, so alone.
    fn flush(&self) -> Result<(), BlockError> {
        self.slots.take_all(&|| self.service(false)).ok_or(BlockError::Busy)?;
        let result = self.run_plain(ATA_FLUSH_CACHE_EXT, 0, 0, 0, false);
        if !self.completions[0].in_flight() {
            self.slots.give_all();
        }
        result
    }

    /// The panic path takes what slots are free and polls; with the ones it
    /// needs in flight it is `Busy`.
    fn write_now(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        self.write(lba, buffer)?;
        self.flush()
    }

    fn stats(&self) -> BlockStats {
        self.slots.stats()
    }
}

/// Find every AHCI controller and every disk on it.
///
/// # Safety
///
/// Call once, during boot, after PCI and paging are up.
pub unsafe fn probe() -> Vec<Arc<dyn BlockDevice>> {
    let mut found: Vec<Arc<dyn BlockDevice>> = Vec::new();
    let mut window = AHCI_VIRT_BASE;

    for device in pci::enumerate() {
        if device.class != CLASS_STORAGE
            || device.subclass != SUBCLASS_SATA
            || device.prog_if != PROG_IF_AHCI
        {
            continue;
        }

        // SAFETY: forwarded from this function's contract.
        if let Some(disks) = unsafe { bring_up(device.address, &mut window) } {
            found.extend(disks);
        }
    }

    found
}

/// Bring up one controller and return the disks on it.
///
/// # Safety
///
/// `address` must name an AHCI controller, and `window` must point at unused
/// virtual space this may claim.
unsafe fn bring_up(
    address: pci::Address,
    window: &mut u64,
) -> Option<Vec<Arc<dyn BlockDevice>>> {
    // BAR 5 holds the register window. `read_config` reaches it whichever
    // configuration mechanism the machine has.
    let bar = pci::read_config(address, 0x24) as u64 & !0xF;
    if bar == 0 {
        return None;
    }

    // Bus mastering, or the controller cannot issue the DMA every transfer
    // depends on. Firmware often leaves it off.
    let command = pci::read_config(address, 0x04);
    // SAFETY: setting bus-master and memory-space enable on a controller this
    // driver is taking ownership of.
    unsafe { pci::write_config(address, 0x04, command | 0b110) };

    let base = *window;
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;

    // The register window is 0x1100 bytes for 32 ports; two pages covers it.
    for index in 0..2u64 {
        let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
            x86_64::VirtAddr::new(base + index * 4096),
        );
        let target =
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(bar + index * 4096));
        // SAFETY: device memory named by the controller's own BAR, at virtual
        // space reserved for AHCI.
        if unsafe { paging::map_to_frame(page, target, flags) }.is_err() {
            return None;
        }
    }
    *window += 2 * 4096;

    // SAFETY: the window is mapped uncached.
    unsafe {
        let ghc = core::ptr::read_volatile((base + REG_GHC) as *const u32);
        core::ptr::write_volatile((base + REG_GHC) as *mut u32, ghc | GHC_AHCI_ENABLE);
    }

    // SAFETY: as above.
    let (capabilities, ports_implemented) = unsafe {
        (
            core::ptr::read_volatile((base + REG_CAP) as *const u32),
            core::ptr::read_volatile((base + REG_PI) as *const u32),
        )
    };

    // Without 64-bit addressing the controller cannot reach a DMA region above
    // 4 GiB, and nothing here constrains the frame allocator to stay below it.
    // Refusing is better than a transfer that silently truncates the address.
    if capabilities & CAP_ADDR64 == 0 {
        crate::println!("ahci: controller cannot address above 4 GiB; skipping it");
        return None;
    }

    let controller_slots = (capabilities & 0x1F) as usize + 1;
    let controller_queues = capabilities & CAP_NCQ != 0;
    let mut disks: Vec<Arc<AhciDisk>> = Vec::new();
    for port_index in 0..32u32 {
        if ports_implemented & (1 << port_index) == 0 {
            continue;
        }
        let port = base + 0x100 + (port_index as u64) * 0x80;
        // SAFETY: a port the controller says it implements, inside the window.
        if let Some(disk) = unsafe { bring_up_port(port, port_index, window, controller_slots, controller_queues) } {
            disks.push(Arc::new(disk));
        }
    }

    // One interrupt for the controller, which says which ports want attention.
    // The list it walks is never freed, so the handler can hold its address.
    let hba = Box::leak(Box::new((base, disks.clone())));
    let context = hba as *const (u64, Vec<Arc<AhciDisk>>) as usize;
    if pci::route_msi(address, on_interrupt, context).is_ok() {
        for disk in &disks {
            disk.interrupts.store(true, Ordering::Release);
        }
        // SAFETY: the window is mapped uncached.
        unsafe {
            let ghc = core::ptr::read_volatile((base + REG_GHC) as *const u32);
            core::ptr::write_volatile((base + REG_GHC) as *mut u32, ghc | GHC_INTERRUPT_ENABLE);
        }
    }

    Some(disks.into_iter().map(|disk| disk as Arc<dyn BlockDevice>).collect())
}

fn on_interrupt(context: usize) {
    // SAFETY: the controller's base and disks, leaked by `bring_up`.
    let (base, disks) = unsafe { &*(context as *const (u64, Vec<Arc<AhciDisk>>)) };
    // SAFETY: the controller's register window, mapped for good. Each port's
    // status is cleared by its own service before the controller's bit for it,
    // which is write-one-to-clear.
    unsafe {
        let pending = core::ptr::read_volatile((base + REG_IS) as *const u32);
        for disk in disks.iter().filter(|disk| pending & (1 << disk.index) != 0) {
            disk.service(true);
        }
        core::ptr::write_volatile((base + REG_IS) as *mut u32, pending);
    }
}

/// Start one port and identify what is on it.
///
/// # Safety
///
/// `port` must be an implemented port's register block.
unsafe fn bring_up_port(
    port: u64,
    index: u32,
    window: &mut u64,
    controller_slots: usize,
    controller_queues: bool,
) -> Option<AhciDisk> {
    // SAFETY: forwarded from this function's contract.
    let (status, signature) = unsafe {
        (
            core::ptr::read_volatile((port + PORT_SSTS) as *const u32),
            core::ptr::read_volatile((port + PORT_SIG) as *const u32),
        )
    };

    if status & 0xF != SSTS_PRESENT || signature != SIG_SATA_DISK {
        return None;
    }

    // Stop the engines before repointing them. A controller still processing
    // the firmware's command list will read the new pointers halfway through.
    // SAFETY: as above.
    unsafe {
        let command = core::ptr::read_volatile((port + PORT_CMD) as *const u32);
        core::ptr::write_volatile(
            (port + PORT_CMD) as *mut u32,
            command & !CMD_START & !CMD_FIS_RECEIVE_ENABLE,
        );

        for _ in 0..TIMEOUT_SPINS {
            let running = core::ptr::read_volatile((port + PORT_CMD) as *const u32);
            if running & (CMD_LIST_RUNNING | CMD_FIS_RECEIVE_RUNNING) == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    let dma = DmaRegion::new(REGION_FRAMES, *window)?;
    *window += REGION_FRAMES * 4096;

    let command_list = dma.physical_at(OFFSET_COMMAND_LIST);
    let received_fis = dma.physical_at(OFFSET_RECEIVED_FIS);

    // SAFETY: the port window is mapped and the engines are stopped.
    unsafe {
        core::ptr::write_volatile((port + PORT_CLB) as *mut u32, command_list as u32);
        core::ptr::write_volatile((port + PORT_CLBU) as *mut u32, (command_list >> 32) as u32);
        core::ptr::write_volatile((port + PORT_FB) as *mut u32, received_fis as u32);
        core::ptr::write_volatile((port + PORT_FBU) as *mut u32, (received_fis >> 32) as u32);

        core::ptr::write_volatile((port + PORT_SERR) as *mut u32, u32::MAX);
        core::ptr::write_volatile((port + PORT_IS) as *mut u32, u32::MAX);
        // The answers a request waits on. Nothing arrives until the controller's
        // own enable, once its MSI is routed.
        core::ptr::write_volatile((port + PORT_IE) as *mut u32, IE_ANSWERS);

        let command = core::ptr::read_volatile((port + PORT_CMD) as *const u32);
        core::ptr::write_volatile(
            (port + PORT_CMD) as *mut u32,
            command | CMD_FIS_RECEIVE_ENABLE | CMD_START,
        );
    }

    let slots = MAX_SLOTS.min(controller_slots);
    let mut disk = AhciDisk {
        port,
        index,
        dma,
        sectors: 0,
        queued: AtomicBool::new(false),
        issued: Mutex::new(Issued { queued: 0, plain: false }),
        slots: Slots::new(slots),
        completions: (0..slots).map(|_| Completion::default()).collect(),
        interrupts: AtomicBool::new(false),
    };

    let (sectors, drive_queues) = identify(&disk)?;
    disk.sectors = sectors;
    disk.queued.store(controller_queues && drive_queues && slots > 1, Ordering::Release);
    Some(disk)
}

/// Ask the disk how big it is, and whether it queues commands.
fn identify(disk: &AhciDisk) -> Option<(u64, bool)> {
    disk.slots.take_all(&|| disk.service(false))?;
    let result = disk.run_plain(ATA_IDENTIFY, 0, 0, 512, false);
    // As in `flush`: give every slot back unless the command is still with the
    // device, whether or not it succeeded. An early return here on failure
    // would hold all eight slots for the life of the disk.
    if !disk.completions[0].in_flight() {
        disk.slots.give_all();
    }
    result.ok()?;

    let data = disk.dma.virtual_at(disk.bounce(0)) as *const u16;
    // SAFETY: the controller has written 512 bytes into the bounce buffer, and
    // the completion check established that it finished.
    let words: [u16; 256] = unsafe { core::ptr::read_volatile(data as *const [u16; 256]) };

    // Words 100..103 hold the 48-bit sector count. Words 60..61 hold the older
    // 28-bit one, which is what a drive smaller than 128 GiB may fill in
    // instead -- and a modern drive fills in both.
    let large = (words[100] as u64)
        | ((words[101] as u64) << 16)
        | ((words[102] as u64) << 32)
        | ((words[103] as u64) << 48);
    let small = (words[60] as u64) | ((words[61] as u64) << 16);
    // Word 76 bit 8: native command queueing.
    let queues = words[76] != 0xFFFF && words[76] & (1 << 8) != 0;
    match (large, small) {
        (0, 0) => None,
        (0, small) => Some((small, queues)),
        (large, _) => Some((large, queues)),
    }
}
