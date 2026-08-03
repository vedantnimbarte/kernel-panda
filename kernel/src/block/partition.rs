//! Partition tables: where a filesystem is allowed to live.
//!
//! A disk is rarely one filesystem. Writing to the whole device means writing
//! over the partition table, the boot loader and anything else already there --
//! so before anything mounts, something has to read the map.
//!
//! Both schemes are handled, because both are still in use. MBR is the older
//! one: four entries in the first sector, sizes as 32-bit sector counts, which
//! is why it cannot describe a disk past 2 TiB. GPT is the replacement, and a
//! GPT disk carries a *protective* MBR claiming one partition of type 0xEE
//! covering everything -- so that a tool which only understands MBR sees a full
//! disk rather than an empty one and declines to help.
//!
//! Reading the protective MBR as a real partition is the classic way to
//! overwrite a GPT disk, so GPT is checked first and MBR only believed when
//! there is no GPT header.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::{BlockDevice, BlockError, SECTOR_SIZE};

/// The signature at the end of a valid MBR.
const MBR_SIGNATURE: u16 = 0xAA55;
/// MBR partition type 0xEE: "this is really a GPT disk, keep out".
const MBR_TYPE_PROTECTIVE: u8 = 0xEE;
/// An unused MBR entry.
const MBR_TYPE_EMPTY: u8 = 0x00;

/// GPT headers start with this, in the sector after the protective MBR.
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// A GPT entry whose type is all zeroes is unused.
const GPT_TYPE_UNUSED: [u8; 16] = [0; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Gpt,
    Mbr,
}

/// One partition, in sectors of its parent device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    pub index: usize,
    pub start: u64,
    pub sectors: u64,
    /// MBR type byte, or the first byte of the GPT type GUID. Enough to spot a
    /// partition this kernel put there; not enough to identify every scheme.
    pub kind: u8,
    pub scheme: Scheme,
}

impl Partition {
    pub fn end(&self) -> u64 {
        self.start + self.sectors
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

/// Read whatever partition table the device carries.
///
/// An empty list means no table, which is not an error: a disk can perfectly
/// well hold a filesystem with no partitioning at all.
pub fn read(device: &dyn BlockDevice) -> Result<Vec<Partition>, BlockError> {
    let mut sector = vec![0u8; SECTOR_SIZE];
    device.read(0, &mut sector)?;

    if read_u16(&sector, 510) != MBR_SIGNATURE {
        return Ok(Vec::new());
    }

    // GPT first. An MBR on a GPT disk is protective and describes nothing real.
    if let Some(partitions) = read_gpt(device)? {
        return Ok(partitions);
    }

    Ok(read_mbr(&sector))
}

/// Parse the four MBR entries.
fn read_mbr(sector: &[u8]) -> Vec<Partition> {
    let mut partitions = Vec::new();

    for index in 0..4 {
        let entry = 446 + index * 16;
        let kind = sector[entry + 4];
        if kind == MBR_TYPE_EMPTY {
            continue;
        }

        // A protective entry reaching here means the GPT header was unreadable.
        // Treating it as a real partition would hand out the whole disk,
        // including the GPT structures, as somewhere to write.
        if kind == MBR_TYPE_PROTECTIVE {
            continue;
        }

        let start = read_u32(sector, entry + 8) as u64;
        let sectors = read_u32(sector, entry + 12) as u64;
        if sectors == 0 {
            continue;
        }

        partitions.push(Partition {
            index,
            start,
            sectors,
            kind,
            scheme: Scheme::Mbr,
        });
    }

    partitions
}

/// Parse the GPT header and entry array, or `None` if there is no GPT.
fn read_gpt(device: &dyn BlockDevice) -> Result<Option<Vec<Partition>>, BlockError> {
    let mut header = vec![0u8; SECTOR_SIZE];
    device.read(1, &mut header)?;

    if &header[0..8] != GPT_SIGNATURE {
        return Ok(None);
    }

    // The header states its own size and checksums itself with that field
    // zeroed. A header that does not verify is one this kernel should not act
    // on -- the alternative is writing a filesystem into whatever the garbage
    // says, which on a disk holding real data is unrecoverable.
    let header_size = read_u32(&header, 12) as usize;
    if !(92..=SECTOR_SIZE).contains(&header_size) {
        return Ok(None);
    }
    if !header_checksum_ok(&header, header_size) {
        crate::println!("partition: the GPT header failed its checksum; ignoring the table");
        return Ok(None);
    }

    let entry_lba = read_u64(&header, 72);
    let entry_count = read_u32(&header, 80) as usize;
    let entry_size = read_u32(&header, 84) as usize;

    // A malformed table must not become an unbounded read.
    if entry_size < 128 || entry_count > 512 {
        return Ok(None);
    }

    let per_sector = SECTOR_SIZE / entry_size;
    if per_sector == 0 {
        return Ok(None);
    }
    let sectors_needed = entry_count.div_ceil(per_sector);

    let mut table = vec![0u8; sectors_needed * SECTOR_SIZE];
    device.read(entry_lba, &mut table)?;

    let mut partitions = Vec::new();
    for index in 0..entry_count {
        let entry = index * entry_size;
        if entry + entry_size > table.len() {
            break;
        }

        let mut kind_guid = [0u8; 16];
        kind_guid.copy_from_slice(&table[entry..entry + 16]);
        if kind_guid == GPT_TYPE_UNUSED {
            continue;
        }

        let first = read_u64(&table, entry + 32);
        let last = read_u64(&table, entry + 40);
        // GPT's last LBA is inclusive, so a partition of one sector has
        // first == last. Reading it as exclusive loses the final sector of
        // every partition on the disk.
        if last < first {
            continue;
        }

        partitions.push(Partition {
            index,
            start: first,
            sectors: last - first + 1,
            kind: kind_guid[0],
            scheme: Scheme::Gpt,
        });
    }

    Ok(Some(partitions))
}

/// CRC32 over the header with its own checksum field zeroed.
fn header_checksum_ok(header: &[u8], header_size: usize) -> bool {
    let stated = read_u32(header, 16);

    let mut copy = vec![0u8; header_size];
    copy.copy_from_slice(&header[..header_size]);
    copy[16..20].fill(0);

    crc32(&copy) == stated
}

/// CRC-32 as GPT uses it: the reflected polynomial, initial and final xor of
/// all ones.
///
/// Computed a bit at a time rather than from a table. It runs twice per boot on
/// a few hundred bytes, and a 1 KiB table of constants to make that faster is
/// not a trade worth taking in a kernel image.
fn crc32(bytes: &[u8]) -> u32 {
    const POLYNOMIAL: u32 = 0xEDB8_8320;
    let mut crc = u32::MAX;

    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLYNOMIAL & mask);
        }
    }

    !crc
}

/// A partition presented as a device in its own right.
///
/// Every request is bounds-checked against the partition and then offset, so a
/// filesystem asking for sector zero gets the partition's first sector and
/// cannot reach the table that describes it however wrong its arithmetic is.
pub struct PartitionDevice {
    disk: Arc<dyn BlockDevice>,
    start: u64,
    sectors: u64,
}

impl PartitionDevice {
    pub fn new(disk: Arc<dyn BlockDevice>, partition: &Partition) -> Result<Self, BlockError> {
        let end = partition
            .start
            .checked_add(partition.sectors)
            .ok_or(BlockError::OutOfRange)?;
        if end > disk.sector_count() {
            return Err(BlockError::OutOfRange);
        }
        Ok(Self {
            disk,
            start: partition.start,
            sectors: partition.sectors,
        })
    }

    fn map(&self, lba: u64, length: usize) -> Result<u64, BlockError> {
        super::validate(self.sectors, lba, length)?;
        Ok(self.start + lba)
    }
}

impl BlockDevice for PartitionDevice {
    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let absolute = self.map(lba, buffer.len())?;
        self.disk.read(absolute, buffer)
    }

    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let absolute = self.map(lba, buffer.len())?;
        self.disk.write(absolute, buffer)
    }

    fn flush(&self) -> Result<(), BlockError> {
        self.disk.flush()
    }
}

/// Write a single-partition GPT covering the whole disk.
///
/// Needed because a blank disk has no table and the filesystem has to go
/// somewhere. Writes the protective MBR, both headers and both copies of the
/// entry array, because a GPT with only the primary copy is one bad sector away
/// from being unreadable -- and the backup is what every other tool will look
/// for when the primary fails.
pub fn write_single_partition_gpt(
    device: &dyn BlockDevice,
    kind: [u8; 16],
) -> Result<Partition, BlockError> {
    let total = device.sector_count();
    // Header, entry array, and the same again at the far end.
    if total < 64 {
        return Err(BlockError::OutOfRange);
    }

    const ENTRY_SIZE: usize = 128;
    const ENTRY_COUNT: usize = 128;
    let entry_sectors = (ENTRY_SIZE * ENTRY_COUNT).div_ceil(SECTOR_SIZE) as u64;

    let first_usable = 2 + entry_sectors;
    let last_usable = total - entry_sectors - 2;
    if last_usable <= first_usable {
        return Err(BlockError::OutOfRange);
    }

    // Protective MBR: one entry of type 0xEE covering the disk, so a tool that
    // only speaks MBR sees a full disk rather than an empty one.
    let mut mbr = vec![0u8; SECTOR_SIZE];
    mbr[446 + 4] = MBR_TYPE_PROTECTIVE;
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    let claimed = u32::try_from(total - 1).unwrap_or(u32::MAX);
    mbr[446 + 12..446 + 16].copy_from_slice(&claimed.to_le_bytes());
    mbr[510..512].copy_from_slice(&MBR_SIGNATURE.to_le_bytes());
    device.write(0, &mbr)?;

    // The entry array.
    let mut entries = vec![0u8; (entry_sectors as usize) * SECTOR_SIZE];
    entries[0..16].copy_from_slice(&kind);
    // A unique id for the partition. Derived from the disk size rather than
    // random, because there is no entropy source here yet and a fixed constant
    // would collide with every other disk this kernel formats.
    let unique = total.rotate_left(17) ^ 0x5061_6E64_6100_0001;
    entries[16..24].copy_from_slice(&unique.to_le_bytes());
    entries[24..32].copy_from_slice(&(!unique).to_le_bytes());
    entries[32..40].copy_from_slice(&first_usable.to_le_bytes());
    entries[40..48].copy_from_slice(&(last_usable).to_le_bytes());
    // Name, UTF-16LE: "panda".
    for (index, ch) in "panda".encode_utf16().enumerate() {
        let at = 56 + index * 2;
        entries[at..at + 2].copy_from_slice(&ch.to_le_bytes());
    }

    let entries_crc = crc32(&entries[..ENTRY_SIZE * ENTRY_COUNT]);

    device.write(2, &entries)?;
    let backup_entries_lba = total - 1 - entry_sectors;
    device.write(backup_entries_lba, &entries)?;

    write_gpt_header(device, 1, total - 1, 2, first_usable, last_usable, entries_crc)?;
    write_gpt_header(
        device,
        total - 1,
        1,
        backup_entries_lba,
        first_usable,
        last_usable,
        entries_crc,
    )?;

    device.flush()?;

    Ok(Partition {
        index: 0,
        start: first_usable,
        sectors: last_usable - first_usable + 1,
        kind: kind[0],
        scheme: Scheme::Gpt,
    })
}

#[allow(clippy::too_many_arguments)]
fn write_gpt_header(
    device: &dyn BlockDevice,
    at: u64,
    other: u64,
    entries_lba: u64,
    first_usable: u64,
    last_usable: u64,
    entries_crc: u32,
) -> Result<(), BlockError> {
    const HEADER_SIZE: usize = 92;
    let mut header = vec![0u8; SECTOR_SIZE];

    header[0..8].copy_from_slice(GPT_SIGNATURE);
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    header[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    // 16..20 is the checksum, left zero while it is computed.
    header[24..32].copy_from_slice(&at.to_le_bytes());
    header[32..40].copy_from_slice(&other.to_le_bytes());
    header[40..48].copy_from_slice(&first_usable.to_le_bytes());
    header[48..56].copy_from_slice(&last_usable.to_le_bytes());
    // Disk GUID, derived the same way as the partition's.
    let disk_guid = first_usable.rotate_left(29) ^ 0x4B65_726E_656C_5061;
    header[56..64].copy_from_slice(&disk_guid.to_le_bytes());
    header[64..72].copy_from_slice(&(!disk_guid).to_le_bytes());
    header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    header[80..84].copy_from_slice(&128u32.to_le_bytes());
    header[84..88].copy_from_slice(&128u32.to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());

    let checksum = crc32(&header[..HEADER_SIZE]);
    header[16..20].copy_from_slice(&checksum.to_le_bytes());

    device.write(at, &header)
}
