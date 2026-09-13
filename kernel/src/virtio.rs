//! Virtio's legacy PCI interface, shared by every virtio driver here.
//!
//! A legacy virtio device is a block of I/O-port registers in BAR 0 -- features,
//! status, queue selection -- followed by configuration specific to the kind of
//! device. Work moves through virtqueues: rings the driver and the device share
//! by DMA. The modern interface describes the same registers through PCI
//! capabilities and memory BARs, and is the one to move to for hardware that
//! offers nothing else.

use x86_64::instructions::port::Port;

use crate::memory::dma::DmaRegion;

pub const VENDOR: u16 = 0x1AF4;

// Legacy register block, offsets into BAR 0.
pub const REG_DEVICE_FEATURES: u16 = 0x00;
pub const REG_GUEST_FEATURES: u16 = 0x04;
pub const REG_QUEUE_PFN: u16 = 0x08;
pub const REG_QUEUE_SIZE: u16 = 0x0C;
pub const REG_QUEUE_SELECT: u16 = 0x0E;
pub const REG_QUEUE_NOTIFY: u16 = 0x10;
pub const REG_STATUS: u16 = 0x12;
// These two exist only while MSI-X is enabled, and push the device-specific
// configuration four bytes further along.
pub const REG_CONFIG_VECTOR: u16 = 0x14;
pub const REG_QUEUE_VECTOR: u16 = 0x16;
pub const REG_CONFIG_WITH_MSIX: u16 = 0x18;

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;

/// "No interrupt" for a queue or for configuration changes.
pub const NO_VECTOR: u16 = 0xFFFF;

/// Descriptor flag: another descriptor follows in this request.
pub const DESCRIPTOR_NEXT: u16 = 1;
/// Descriptor flag: the device writes into this buffer.
pub const DESCRIPTOR_WRITE: u16 = 2;

/// Device-specific configuration without MSI-X. With it, the two vector
/// registers push it to [`REG_CONFIG_WITH_MSIX`].
pub const REG_CONFIG: u16 = 0x14;

/// One virtqueue, in the legacy layout: the descriptor table, then the
/// available ring, then -- page aligned -- the used ring.
pub struct Queue {
    region: DmaRegion,
    pub size: u16,
    used_offset: u64,
    /// The next available-ring index this driver writes.
    next_available: u16,
    /// The next used-ring index this driver has not yet read.
    next_used: u16,
}

impl Queue {
    /// Allocate and describe queue `index` to the device.
    pub fn new(port: u16, index: u16, virtual_base: u64) -> Option<Self> {
        // SAFETY: the legacy register block of the device this driver owns.
        let size = unsafe {
            Port::<u16>::new(port + REG_QUEUE_SELECT).write(index);
            Port::<u16>::new(port + REG_QUEUE_SIZE).read()
        };
        if size == 0 {
            return None;
        }

        let size_bytes = size as u64;
        let used_offset = (16 * size_bytes + 6 + 2 * size_bytes).next_multiple_of(4096);
        let total = used_offset + 6 + 8 * size_bytes;
        let region = DmaRegion::new(total.div_ceil(4096), virtual_base)?;

        // The device takes the queue's page frame number, which is why the
        // layout is page aligned from its first byte.
        let frame_number = (region.physical_at(0) >> 12) as u32;
        // SAFETY: as above.
        unsafe { Port::<u32>::new(port + REG_QUEUE_PFN).write(frame_number) };

        Some(Self {
            region,
            size,
            used_offset,
            next_available: 0,
            next_used: 0,
        })
    }

    /// Point descriptor `index` at a buffer. `next` names the following
    /// descriptor when `flags` carries [`DESCRIPTOR_NEXT`].
    pub fn describe(&self, index: u16, physical: u64, length: u32, flags: u16, next: u16) {
        let descriptor = self.region.virtual_at(16 * index as u64);
        // SAFETY: inside the descriptor table of this queue's own region.
        unsafe {
            core::ptr::write_volatile(descriptor as *mut u64, physical);
            core::ptr::write_volatile((descriptor + 8) as *mut u32, length);
            core::ptr::write_volatile((descriptor + 12) as *mut u16, flags);
            core::ptr::write_volatile((descriptor + 14) as *mut u16, next);
        }
    }

    /// Offer descriptor `index` to the device.
    pub fn offer(&mut self, index: u16) {
        // The available ring follows the descriptor table.
        let ring = 16 * self.size as u64;
        let slot = self.region.virtual_at(ring + 4 + 2 * (self.next_available % self.size) as u64);
        self.next_available = self.next_available.wrapping_add(1);
        // SAFETY: the available ring of this queue's own region. The ring entry
        // is written before the index that exposes it.
        unsafe {
            core::ptr::write_volatile(slot as *mut u16, index);
            core::ptr::write_volatile(self.region.virtual_at(ring + 2) as *mut u16, self.next_available);
        }
    }

    /// Take the next buffer the device has finished with: its descriptor index
    /// and how many bytes it wrote.
    pub fn take_used(&mut self) -> Option<(u16, u32)> {
        // SAFETY: the used ring of this queue's own region, which the device
        // advances by DMA.
        let device_index =
            unsafe { core::ptr::read_volatile(self.region.virtual_at(self.used_offset + 2) as *const u16) };
        if device_index == self.next_used {
            return None;
        }
        let element = self
            .region
            .virtual_at(self.used_offset + 4 + 8 * (self.next_used % self.size) as u64);
        self.next_used = self.next_used.wrapping_add(1);
        // SAFETY: as above.
        unsafe {
            Some((
                core::ptr::read_volatile(element as *const u32) as u16,
                core::ptr::read_volatile((element + 4) as *const u32),
            ))
        }
    }
}

