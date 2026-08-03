//! AHCI: the interface almost every x86 machine exposes for SATA.
//!
//! The controller is found over PCI (class 0x01, subclass 0x06) and its
//! registers live in BAR 5. Everything after that is a conversation conducted
//! through memory the *device* reads, not the CPU: a command list, a command
//! table per slot, and a scatter-gather list of where the data should land. The
//! CPU writes those structures, sets a bit, and waits.
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

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use super::{validate, BlockDevice, BlockError, SECTOR_SIZE};
use crate::memory::{frame, paging};
use crate::pci;

/// PCI class 0x01 subclass 0x06: a SATA controller. Programming interface 0x01
/// means it speaks AHCI rather than a vendor's own thing.
const CLASS_STORAGE: u8 = 0x01;
const SUBCLASS_SATA: u8 = 0x06;
const PROG_IF_AHCI: u8 = 0x01;

// Generic host control.
const REG_CAP: u64 = 0x00;
const REG_GHC: u64 = 0x04;
const REG_PI: u64 = 0x0C;

/// GHC bit 31: hand the controller to the driver rather than to legacy IDE
/// emulation.
const GHC_AHCI_ENABLE: u32 = 1 << 31;

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
const PORT_CI: u64 = 0x38;

/// PxCMD bit 0: start processing the command list.
const CMD_START: u32 = 1 << 0;
/// PxCMD bit 4: the receive-FIS engine is running.
const CMD_FIS_RECEIVE_ENABLE: u32 = 1 << 4;
/// PxCMD bit 14: the receive-FIS engine has actually stopped.
const CMD_FIS_RECEIVE_RUNNING: u32 = 1 << 14;
/// PxCMD bit 15: the command engine has actually stopped.
const CMD_LIST_RUNNING: u32 = 1 << 15;

/// PxTFD: the device is busy, or has data to transfer. Either means it is not
/// ready for a new command.
const TFD_BUSY: u32 = 1 << 7;
const TFD_DATA_REQUEST: u32 = 1 << 3;
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

/// Physically contiguous memory shared with the controller.
///
/// Freed when the port is dropped, which never happens -- a disk found at boot
/// stays found. Kept as an owned type anyway so the lifetime is stated rather
/// than implied.
struct DmaRegion {
    physical: PhysAddr,
    virtual_base: u64,
    frames: u64,
}

impl DmaRegion {
    /// Allocate `frames` contiguous physical frames and map them uncached.
    fn new(frames: u64, virtual_base: u64) -> Option<Self> {
        let first = frame::with(|allocator| allocator.allocate_contiguous(frames as usize))?;

        // Uncached and write-through. The controller updates these structures by
        // DMA; a cached view can answer a read from a line fetched before it
        // did, which shows up as a command that never appears to complete.
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH
            | PageTableFlags::NO_EXECUTE;

        for index in 0..frames {
            let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                x86_64::VirtAddr::new(virtual_base + index * 4096),
            );
            let target = PhysFrame::<Size4KiB>::containing_address(
                first.start_address() + index * 4096,
            );
            // SAFETY: the frames were just allocated contiguously and belong to
            // nobody else, and this virtual range is reserved for AHCI.
            if unsafe { paging::map_to_frame(page, target, flags) }.is_err() {
                for done in 0..index {
                    let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                        x86_64::VirtAddr::new(virtual_base + done * 4096),
                    );
                    let _ = paging::unmap(page);
                }
                frame::with(|allocator| {
                    for offset in 0..frames {
                        allocator.deallocate(PhysFrame::containing_address(
                            first.start_address() + offset * 4096,
                        ));
                    }
                });
                return None;
            }
        }

        // Zeroed, because the controller reads these before the CPU has written
        // every field and whatever the last owner left looks like a command.
        // SAFETY: just mapped, writable, and this size.
        unsafe {
            core::ptr::write_bytes(virtual_base as *mut u8, 0, (frames * 4096) as usize);
        }

        Some(Self {
            physical: first.start_address(),
            virtual_base,
            frames,
        })
    }

    fn physical_at(&self, offset: u64) -> u64 {
        self.physical.as_u64() + offset
    }

    fn virtual_at(&self, offset: u64) -> u64 {
        self.virtual_base + offset
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        for index in 0..self.frames {
            let page = x86_64::structures::paging::Page::<Size4KiB>::containing_address(
                x86_64::VirtAddr::new(self.virtual_base + index * 4096),
            );
            let _ = paging::unmap_and_free(page);
        }
    }
}

// Layout within the port's DMA region. One page for the command list and
// received FIS, one for the command table, and two for a bounce buffer.
const OFFSET_COMMAND_LIST: u64 = 0;
const OFFSET_RECEIVED_FIS: u64 = 1024;
const OFFSET_COMMAND_TABLE: u64 = 4096;
const OFFSET_BOUNCE: u64 = 8192;
const BOUNCE_BYTES: u64 = 2 * 4096;
const REGION_FRAMES: u64 = 4;

/// One SATA disk on one port.
pub struct AhciDisk {
    /// Virtual base of this port's registers.
    port: u64,
    /// The structures the controller reads.
    dma: DmaRegion,
    sectors: u64,
    /// Serialises access: one command slot is used, so two callers cannot both
    /// be in flight.
    lock: crate::sync::Mutex<()>,
}

// SAFETY: every path that touches the port or the shared structures holds
// `lock`, and the memory is owned by this struct for its lifetime.
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

    /// Wait for the device to stop being busy.
    fn wait_ready(&self) -> Result<(), BlockError> {
        for _ in 0..TIMEOUT_SPINS {
            // SAFETY: the window is mapped for this disk's lifetime.
            let status = unsafe { self.read_reg(PORT_TFD) };
            if status & (TFD_BUSY | TFD_DATA_REQUEST) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(BlockError::DeviceFault)
    }

    /// Build a command in slot zero and run it to completion.
    ///
    /// `write` says which way the data flows; `bytes` is how much of the bounce
    /// buffer takes part.
    fn run_command(
        &self,
        command: u8,
        lba: u64,
        sectors: u16,
        bytes: u64,
        write: bool,
    ) -> Result<(), BlockError> {
        self.wait_ready()?;

        // SAFETY: the DMA region is mapped and this offset is inside it.
        let header = self.dma.virtual_at(OFFSET_COMMAND_LIST) as *mut CommandHeader;
        let table = self.dma.virtual_at(OFFSET_COMMAND_TABLE) as *mut CommandTable;

        // SAFETY: both point into this disk's own DMA region, which is mapped
        // writable, and `lock` is held by the caller so nothing else is here.
        unsafe {
            core::ptr::write_bytes(table as *mut u8, 0, core::mem::size_of::<CommandTable>());

            let fis = &mut (*table).command_fis;
            // FIS type 0x27: host to device. Bit 7 of byte 1 says this is a
            // command rather than a control update -- without it the device
            // quietly ignores the whole thing.
            fis[0] = 0x27;
            fis[1] = 0x80;
            fis[2] = command;
            fis[3] = 0; // features

            fis[4] = lba as u8;
            fis[5] = (lba >> 8) as u8;
            fis[6] = (lba >> 16) as u8;
            // Bit 6: LBA mode. The 28-bit-versus-48-bit distinction is in the
            // command, but this bit still has to be set or the device reads the
            // address as cylinder/head/sector.
            fis[7] = 1 << 6;
            fis[8] = (lba >> 24) as u8;
            fis[9] = (lba >> 32) as u8;
            fis[10] = (lba >> 40) as u8;

            fis[12] = sectors as u8;
            fis[13] = (sectors >> 8) as u8;

            if bytes > 0 {
                (*table).prdt[0] = PrdtEntry {
                    address: self.dma.physical_at(OFFSET_BOUNCE),
                    reserved: 0,
                    // The count is a byte count *minus one*, which is the single
                    // most common way to transfer one sector too few.
                    count: (bytes as u32 - 1) & 0x003F_FFFF,
                };
            }

            (*header).flags = (core::mem::size_of::<[u8; 20]>() as u16 / 4)
                | if write { 1 << 6 } else { 0 };
            (*header).prdt_length = if bytes > 0 { 1 } else { 0 };
            (*header).transferred = 0;
            (*header).table_address = self.dma.physical_at(OFFSET_COMMAND_TABLE);
        }

        // Everything above must be visible to the device before the bit that
        // tells it to look. The mapping is uncached so there is no cache to
        // flush, but the compiler must not sink those stores past this point.
        compiler_fence(Ordering::SeqCst);

        // SAFETY: the register window is mapped.
        unsafe {
            // Clear stale status before issuing, or the completion check below
            // can be satisfied by the previous command's error.
            self.write_reg(PORT_IS, u32::MAX);
            self.write_reg(PORT_SERR, u32::MAX);
            self.write_reg(PORT_CI, 1);
        }

        for _ in 0..TIMEOUT_SPINS {
            // SAFETY: as above.
            let (issued, status) = unsafe { (self.read_reg(PORT_CI), self.read_reg(PORT_IS)) };
            if status & IS_TASK_FILE_ERROR != 0 {
                return Err(BlockError::DeviceFault);
            }
            if issued & 1 == 0 {
                compiler_fence(Ordering::SeqCst);
                // SAFETY: as above.
                let task_file = unsafe { self.read_reg(PORT_TFD) };
                if task_file & TFD_ERROR != 0 {
                    return Err(BlockError::DeviceFault);
                }
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(BlockError::DeviceFault)
    }

    /// Copy through the bounce buffer in chunks it can hold.
    ///
    /// The caller's buffer is ordinary kernel memory: it may be physically
    /// scattered, and handing its virtual address to a DMA engine would point
    /// the controller at unrelated physical pages. Building a scatter-gather
    /// list from the caller's actual frames would avoid the copy and is what a
    /// fast driver does; this one is correct first.
    fn transfer(&self, lba: u64, buffer: &mut [u8], write: bool) -> Result<(), BlockError> {
        let sectors = validate(self.sectors, lba, buffer.len())?;
        let _guard = self.lock.lock();

        let per_chunk = (BOUNCE_BYTES as usize) / SECTOR_SIZE;
        let mut done = 0usize;

        while done < sectors {
            let chunk = (sectors - done).min(per_chunk);
            let bytes = (chunk * SECTOR_SIZE) as u64;
            let bounce = self.dma.virtual_at(OFFSET_BOUNCE) as *mut u8;

            if write {
                // SAFETY: `bounce` is this disk's own buffer, at least
                // `BOUNCE_BYTES` long, and `bytes` never exceeds that.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer[done * SECTOR_SIZE..].as_ptr(),
                        bounce,
                        bytes as usize,
                    );
                }
            }

            let command = if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT };
            self.run_command(command, lba + done as u64, chunk as u16, bytes, write)?;

            if !write {
                // SAFETY: as above; the controller has finished writing into
                // the bounce buffer, which the completion check established.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bounce,
                        buffer[done * SECTOR_SIZE..].as_mut_ptr(),
                        bytes as usize,
                    );
                }
            }

            done += chunk;
        }

        Ok(())
    }
}

impl BlockDevice for AhciDisk {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.transfer(lba, buffer, false)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        // The transfer path needs a mutable slice for the read direction; a
        // write never touches the caller's buffer, so this is a cast rather
        // than a copy.
        let sectors = validate(self.sectors, lba, buffer.len())?;
        let _ = sectors;

        let _guard = self.lock.lock();
        let per_chunk = (BOUNCE_BYTES as usize) / SECTOR_SIZE;
        let mut done = 0usize;
        let total = buffer.len() / SECTOR_SIZE;

        while done < total {
            let chunk = (total - done).min(per_chunk);
            let bytes = (chunk * SECTOR_SIZE) as u64;
            let bounce = self.dma.virtual_at(OFFSET_BOUNCE) as *mut u8;

            // SAFETY: `bounce` is this disk's own buffer and `bytes` fits.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer[done * SECTOR_SIZE..].as_ptr(),
                    bounce,
                    bytes as usize,
                );
            }

            self.run_command(
                ATA_WRITE_DMA_EXT,
                lba + done as u64,
                chunk as u16,
                bytes,
                true,
            )?;
            done += chunk;
        }

        Ok(())
    }

    fn flush(&self) -> Result<(), BlockError> {
        let _guard = self.lock.lock();
        self.run_command(ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)
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

    let mut disks: Vec<Arc<dyn BlockDevice>> = Vec::new();
    for port_index in 0..32u32 {
        if ports_implemented & (1 << port_index) == 0 {
            continue;
        }
        let port = base + 0x100 + (port_index as u64) * 0x80;
        // SAFETY: a port the controller says it implements, inside the window.
        if let Some(disk) = unsafe { bring_up_port(port, window) } {
            disks.push(Arc::new(disk));
        }
    }

    Some(disks)
}

/// Start one port and identify what is on it.
///
/// # Safety
///
/// `port` must be an implemented port's register block.
unsafe fn bring_up_port(port: u64, window: &mut u64) -> Option<AhciDisk> {
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
        // Interrupts stay masked: every wait here polls. Routing them would mean
        // another I/O APIC entry and a handler, and the driver would still have
        // to poll during boot before interrupts are on.
        core::ptr::write_volatile((port + PORT_IE) as *mut u32, 0);

        let command = core::ptr::read_volatile((port + PORT_CMD) as *const u32);
        core::ptr::write_volatile(
            (port + PORT_CMD) as *mut u32,
            command | CMD_FIS_RECEIVE_ENABLE | CMD_START,
        );
    }

    let disk = AhciDisk {
        port,
        dma,
        sectors: 0,
        lock: crate::sync::Mutex::new(()),
    };

    let sectors = identify(&disk)?;
    Some(AhciDisk { sectors, ..disk })
}

/// Ask the disk how big it is.
fn identify(disk: &AhciDisk) -> Option<u64> {
    disk.run_command(ATA_IDENTIFY, 0, 0, 512, false).ok()?;

    let data = disk.dma.virtual_at(OFFSET_BOUNCE) as *const u16;
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
    if large > 0 {
        return Some(large);
    }

    let small = (words[60] as u64) | ((words[61] as u64) << 16);
    if small > 0 {
        Some(small)
    } else {
        None
    }
}
