//! Block devices: the first thing in this kernel that outlives a reboot.
//!
//! Everything above here -- files, configuration, logs, programs loaded from
//! somewhere other than the kernel image -- needs somewhere to put bytes that is
//! still there next time. This is that layer, and it is deliberately thin: a
//! device is something you can ask for a sector by number, and nothing more.
//!
//! ## Where the driver lives
//!
//! In the kernel, which is a deviation from the PRD's rule that drivers belong
//! in Ring 3, and it is worth being straight about why rather than quietly
//! doing it.
//!
//! A disk controller is a DMA engine. It writes wherever its command tables
//! tell it to, and those tables are physical addresses. A Ring 3 driver handed
//! that controller can write to any physical page in the machine by asking the
//! hardware to do it -- the page tables it runs under are not consulted, because
//! the device is not the CPU. So a Ring 3 disk driver on a machine with no IOMMU
//! is not isolated; it merely looks isolated, which is worse than an honest
//! Ring 0 driver because it invites you to trust it.
//!
//! Making it real needs an IOMMU (VT-d) programmed with a per-device domain, so
//! the controller physically cannot reach memory the driver does not own. That
//! is the right destination and it is not built yet. Until it is, this is a
//! kernel driver and the PRD's Phase 4 claim about Ring 3 drivers does not cover
//! storage.
//!
//! The layer above -- partitions, filesystems, policy -- has no such excuse and
//! is meant to move out.

pub mod ahci;

use alloc::vec::Vec;

/// Every device here speaks 512-byte sectors.
///
/// Drives with 4 KiB physical sectors present a 512-byte logical view, so this
/// is the interface even where it is not the geometry. Alignment matters for
/// performance, not correctness, and nothing here is fast yet.
pub const SECTOR_SIZE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// No device answered.
    NotPresent,
    /// The request runs off the end of the device.
    OutOfRange,
    /// The buffer is not a whole number of sectors.
    Unaligned,
    /// The controller reported a failure, or stopped answering.
    DeviceFault,
    /// The request could not be set up -- no memory for the descriptors.
    OutOfMemory,
    /// Writing was refused because the device is read-only.
    ReadOnly,
}

/// Something that stores numbered sectors and gives them back.
pub trait BlockDevice: Send + Sync {
    /// How many sectors it holds.
    fn sector_count(&self) -> u64;

    /// Read `buffer.len() / SECTOR_SIZE` sectors starting at `lba`.
    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError>;

    /// Write `buffer.len() / SECTOR_SIZE` sectors starting at `lba`.
    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError>;

    /// Make sure everything written so far has reached the medium.
    ///
    /// A write that has been accepted is not a write that has survived: drives
    /// buffer, and a power cut between the two loses it. Anything claiming to be
    /// crash-safe has to be able to ask.
    fn flush(&self) -> Result<(), BlockError>;

    /// Bytes it holds, for reporting.
    fn capacity(&self) -> u64 {
        self.sector_count() * SECTOR_SIZE as u64
    }
}

/// Reject a request before it reaches hardware.
///
/// Shared by every implementation, because getting it wrong means a controller
/// pointed at memory outside the transfer, and every driver would otherwise
/// write the same three checks slightly differently.
pub fn validate(
    device_sectors: u64,
    lba: u64,
    length: usize,
) -> Result<usize, BlockError> {
    if length == 0 || !length.is_multiple_of(SECTOR_SIZE) {
        return Err(BlockError::Unaligned);
    }
    let sectors = length / SECTOR_SIZE;
    let end = lba
        .checked_add(sectors as u64)
        .ok_or(BlockError::OutOfRange)?;
    if end > device_sectors {
        return Err(BlockError::OutOfRange);
    }
    Ok(sectors)
}

/// What the kernel found attached.
static DEVICES: crate::sync::Mutex<Vec<alloc::sync::Arc<dyn BlockDevice>>> =
    crate::sync::Mutex::new(Vec::new());

/// Probe the buses for storage and record what answers.
///
/// # Safety
///
/// Call once, during boot, after PCI and paging are up.
pub unsafe fn init() {
    // SAFETY: forwarded from this function's contract.
    let found = unsafe { ahci::probe() };
    if found.is_empty() {
        return;
    }

    crate::sync::without_interrupts(|| {
        let mut devices = DEVICES.lock();
        for device in found {
            crate::println!(
                "block: disk {} with {} sectors ({} MiB)",
                devices.len(),
                device.sector_count(),
                device.capacity() / (1024 * 1024)
            );
            devices.push(device);
        }
    });
}

/// How many block devices were found.
pub fn count() -> usize {
    crate::sync::without_interrupts(|| DEVICES.lock().len())
}

/// One of the devices, by index.
pub fn device(index: usize) -> Option<alloc::sync::Arc<dyn BlockDevice>> {
    crate::sync::without_interrupts(|| DEVICES.lock().get(index).cloned())
}
