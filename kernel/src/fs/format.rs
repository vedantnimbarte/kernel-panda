//! Putting an empty filesystem on a device.

use alloc::sync::Arc;
use alloc::vec;

use super::{FileSystem, FsError, Inode, SuperBlock, BLOCK_SIZE, DIRECT_BLOCKS, MAGIC, VERSION};
use crate::block::BlockDevice;

/// Write an empty filesystem over whatever was there.
///
/// Both superblocks are written, with the second carrying the lower generation,
/// so a mount immediately after formatting sees a definite winner rather than
/// two equal candidates. The bitmap is written with the metadata blocks already
/// marked used, because an allocator that can hand out the superblock is an
/// allocator that will eventually destroy the filesystem it belongs to.
pub fn format(device: Arc<dyn BlockDevice>) -> Result<FileSystem, FsError> {
    let total_blocks = device.sector_count();
    if total_blocks < 16 {
        return Err(FsError::Full);
    }

    // One bit per block, rounded up to whole blocks.
    let bitmap_bits = total_blocks;
    let bitmap_bytes = bitmap_bits.div_ceil(8);
    let bitmap_blocks = bitmap_bytes.div_ceil(BLOCK_SIZE as u64);

    let bitmap_start = 2;
    let root_inode = bitmap_start + bitmap_blocks;
    let first_data_block = root_inode + 1;

    if first_data_block >= total_blocks {
        return Err(FsError::Full);
    }

    let mut bitmap = vec![0u8; (bitmap_blocks as usize) * BLOCK_SIZE];
    // Everything up to and including the root inode is metadata and must never
    // be allocated.
    for block in 0..first_data_block {
        let index = block as usize;
        bitmap[index / 8] |= 1 << (index % 8);
    }
    // Blocks past the end of the device, in the bitmap's final partial byte,
    // are marked used so the allocator cannot hand out a sector that is not
    // there.
    for block in total_blocks..(bitmap_blocks * BLOCK_SIZE as u64 * 8) {
        let index = block as usize;
        if index / 8 < bitmap.len() {
            bitmap[index / 8] |= 1 << (index % 8);
        }
    }

    device.write(bitmap_start, &bitmap)?;

    let root = Inode {
        kind: 1,
        size: 0,
        blocks_used: 0,
        direct: [0; DIRECT_BLOCKS],
    };
    device.write(root_inode, &root.encode())?;

    // Data before the superblock that names it, and flushed, or a power cut
    // here leaves a filesystem whose root points at nothing.
    device.flush()?;

    let mut superblock = SuperBlock {
        magic: MAGIC,
        version: VERSION,
        generation: 1,
        total_blocks,
        bitmap_start,
        bitmap_blocks,
        root_inode,
        first_data_block,
        checksum: 0,
    };
    device.write(0, &superblock.encode())?;

    // The older sibling. Written second and deliberately stale, so the mount
    // that follows has an unambiguous winner and the first commit has a slot to
    // write to that is not the live one.
    superblock.generation = 0;
    device.write(1, &superblock.encode())?;
    device.flush()?;

    FileSystem::mount(device)
}
