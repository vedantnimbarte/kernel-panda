//! A filesystem that survives a power cut.
//!
//! ## Why not update in place
//!
//! The obvious design writes a file's data, then updates the block pointing at
//! it. A power cut between the two leaves a directory entry naming a block that
//! holds something else -- and nothing on the disk records that this happened,
//! so the next mount reads corruption and believes it.
//!
//! The two answers are journalling (write what you are about to do, do it,
//! erase the note) and copy-on-write (never overwrite live data; write the new
//! version elsewhere and switch to it in one atomic step). This is the second,
//! because the atomic step is a single sector write and the recovery story is
//! "use the older superblock", which needs no replay logic and therefore has no
//! replay bugs.
//!
//! ## The shape of it
//!
//! ```text
//! sector 0..1     superblock A       one of these is live
//! sector 1..2     superblock B       the other is the previous commit
//! sector 2..      allocation bitmap  one bit per block
//! then            blocks             inodes, directories and file data
//! ```
//!
//! A commit writes every changed block to *free* space, then writes the
//! superblock that names the new root -- to whichever of the two slots is not
//! currently live. Until that final sector lands, the old tree is intact and
//! the disk still mounts as it was. After it lands, the new tree is live. There
//! is no in-between state that a reader can observe, which is the whole point.
//!
//! The generation counter decides which superblock is newer, and both carry a
//! checksum, so a superblock torn mid-write loses to its sibling rather than
//! being believed.
//!
//! ## What this is not
//!
//! Not fast. Every commit rewrites the path from the changed block to the root,
//! and the allocator is a linear scan of a bitmap. Not concurrent: one lock
//! covers the whole filesystem. Both are fixable without changing the on-disk
//! format, which is the part that is expensive to change later.

pub mod format;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::block::{BlockDevice, BlockError, SECTOR_SIZE};
use crate::users::{UserId, SYSTEM};
use crate::sync::SleepMutex;

/// Bytes per filesystem block. One sector, so a block write is a sector write
/// and the atomicity argument does not need a second layer of reasoning.
pub const BLOCK_SIZE: usize = SECTOR_SIZE;

/// What a superblock starts with, so a disk that is not ours is not mounted as
/// if it were.
pub const MAGIC: u64 = 0x5061_6E64_6146_5301;

/// On-disk format version. Refusing an unknown one is better than reading a
/// future layout as if it were this one.
///
/// 2 added an owner and permission bits to every inode, in bytes version 1 left
/// zero. A version 1 disk would read as everything owned by the system and
/// closed to everyone, so it is refused rather than half-understood.
pub const VERSION: u32 = 2;

/// Who may do what to a file or directory: read and write, for its owner and
/// for everyone else. For a directory, read is looking names up in it and
/// listing it, and write is adding or removing names.
///
/// There is deliberately no superuser bit and no bypass: the system's own user
/// is held to these like any other. See `crate::users`.
pub const OWNER_READ: u16 = 1 << 0;
pub const OWNER_WRITE: u16 = 1 << 1;
pub const OTHERS_READ: u16 = 1 << 2;
pub const OTHERS_WRITE: u16 = 1 << 3;
const ALL_PERMISSIONS: u16 = OWNER_READ | OWNER_WRITE | OTHERS_READ | OTHERS_WRITE;

/// What a new file or directory gets: its owner may change it, anyone may read
/// it.
pub const DEFAULT_MODE: u16 = OWNER_READ | OWNER_WRITE | OTHERS_READ;

/// Blocks a single file can hold, as direct pointers from its inode.
///
/// No indirect blocks yet, so a file is capped at this many blocks -- 30 KiB.
/// The cap is reported as `TooLarge` rather than being an unexplained failure.
///
/// Sized to what is left of a block after the header, not chosen: 24 bytes of
/// header and eight per pointer leaves room for 61, and 60 keeps a little slack
/// for a field the format may need later without moving every pointer.
pub const DIRECT_BLOCKS: usize = 60;

/// Longest name a directory entry can hold.
pub const MAX_NAME: usize = 55;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// The device does not hold this filesystem.
    NotFormatted,
    /// It does, but of a version this kernel does not understand.
    WrongVersion,
    /// No such file or directory.
    NotFound,
    /// A file of that name is already there.
    Exists,
    /// The name is empty, too long, or contains a separator.
    BadName,
    /// The file is larger than the direct-block layout can address.
    TooLarge,
    /// No free blocks.
    Full,
    /// The operation needs a directory and got a file, or the reverse.
    WrongType,
    /// A directory with entries cannot be removed.
    NotEmpty,
    /// The caller's user may not do this.
    Denied,
    /// The device reported a failure.
    Device(BlockError),
    /// The structure on disk does not make sense.
    Corrupt,
}

impl From<BlockError> for FsError {
    fn from(error: BlockError) -> Self {
        FsError::Device(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Directory,
}

/// The root of a committed tree.
///
/// Written last and atomically; everything else on disk is only reachable
/// through whichever copy of this is live.
#[repr(C)]
#[derive(Clone, Copy)]
struct SuperBlock {
    magic: u64,
    version: u32,
    /// Higher wins. This is what decides which of the two superblocks is the
    /// live one after a crash.
    generation: u64,
    /// Total blocks on the device.
    total_blocks: u64,
    /// First block of the allocation bitmap.
    bitmap_start: u64,
    bitmap_blocks: u64,
    /// Block holding the root directory's inode.
    root_inode: u64,
    /// First block that can hold data.
    first_data_block: u64,
    /// CRC over everything above, with this field zeroed.
    checksum: u32,
}

/// A file or directory.
#[repr(C)]
#[derive(Clone, Copy)]
struct Inode {
    kind: u32,
    owner: UserId,
    mode: u16,
    /// Bytes for a file; entries for a directory.
    size: u64,
    blocks_used: u32,
    direct: [u64; DIRECT_BLOCKS],
}

/// One name in a directory.
#[repr(C)]
#[derive(Clone, Copy)]
struct DirEntry {
    /// Block holding the inode, or zero for an unused slot.
    inode: u64,
    name_length: u8,
    name: [u8; MAX_NAME],
}

/// Entries that fit in one block.
const ENTRIES_PER_BLOCK: usize = BLOCK_SIZE / core::mem::size_of::<DirEntry>();

/// What a transaction does at the component it targets.
///
/// Takes the block holding that component's inode if it exists, and returns the
/// block that should replace it -- or `None` to remove the name entirely. The
/// caller rewrites the path above it either way.
/// Who is making a change, and whether it adds or removes a name -- which needs
/// write permission on the directory holding it.
#[derive(Clone, Copy)]
struct Access {
    user: Option<UserId>,
    changes_parent: bool,
}

impl Access {
    fn changing_parent(user: Option<UserId>) -> Self {
        Self { user, changes_parent: true }
    }

    fn within_parent(user: Option<UserId>) -> Self {
        Self { user, changes_parent: false }
    }
}

type Action<'a> =
    &'a mut dyn FnMut(&FileSystem, &mut State, Option<u64>) -> Result<Option<u64>, FsError>;

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

impl SuperBlock {
    fn encode(&self) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE];
        block[0..8].copy_from_slice(&self.magic.to_le_bytes());
        block[8..12].copy_from_slice(&self.version.to_le_bytes());
        block[16..24].copy_from_slice(&self.generation.to_le_bytes());
        block[24..32].copy_from_slice(&self.total_blocks.to_le_bytes());
        block[32..40].copy_from_slice(&self.bitmap_start.to_le_bytes());
        block[40..48].copy_from_slice(&self.bitmap_blocks.to_le_bytes());
        block[48..56].copy_from_slice(&self.root_inode.to_le_bytes());
        block[56..64].copy_from_slice(&self.first_data_block.to_le_bytes());

        let checksum = crc32(&block[0..64]);
        block[64..68].copy_from_slice(&checksum.to_le_bytes());
        block
    }

    fn decode(block: &[u8]) -> Option<Self> {
        let magic = u64::from_le_bytes(block[0..8].try_into().ok()?);
        if magic != MAGIC {
            return None;
        }

        let stated = u32::from_le_bytes(block[64..68].try_into().ok()?);
        if crc32(&block[0..64]) != stated {
            // A superblock torn mid-write. Not an error: the sibling is the
            // previous commit and is intact, which is exactly the situation
            // this design exists to survive.
            return None;
        }

        Some(Self {
            magic,
            version: u32::from_le_bytes(block[8..12].try_into().ok()?),
            generation: u64::from_le_bytes(block[16..24].try_into().ok()?),
            total_blocks: u64::from_le_bytes(block[24..32].try_into().ok()?),
            bitmap_start: u64::from_le_bytes(block[32..40].try_into().ok()?),
            bitmap_blocks: u64::from_le_bytes(block[40..48].try_into().ok()?),
            root_inode: u64::from_le_bytes(block[48..56].try_into().ok()?),
            first_data_block: u64::from_le_bytes(block[56..64].try_into().ok()?),
            checksum: stated,
        })
    }
}

/// The inode layout has to fit in one block, and a pointer array sized past the
/// end would panic on every write rather than failing to compile. Checked here
/// so changing `DIRECT_BLOCKS` cannot silently overrun.
const _: () = assert!(24 + DIRECT_BLOCKS * 8 <= BLOCK_SIZE);

impl Inode {
    fn encode(&self) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE];
        block[0..4].copy_from_slice(&self.kind.to_le_bytes());
        block[4..8].copy_from_slice(&self.owner.to_le_bytes());
        block[8..16].copy_from_slice(&self.size.to_le_bytes());
        block[16..20].copy_from_slice(&self.blocks_used.to_le_bytes());
        block[20..22].copy_from_slice(&self.mode.to_le_bytes());
        for (index, pointer) in self.direct.iter().enumerate() {
            let at = 24 + index * 8;
            block[at..at + 8].copy_from_slice(&pointer.to_le_bytes());
        }
        block
    }

    fn decode(block: &[u8]) -> Result<Self, FsError> {
        let kind = u32::from_le_bytes(block[0..4].try_into().map_err(|_| FsError::Corrupt)?);
        if kind > 1 {
            return Err(FsError::Corrupt);
        }

        let mut direct = [0u64; DIRECT_BLOCKS];
        for (index, pointer) in direct.iter_mut().enumerate() {
            let at = 24 + index * 8;
            *pointer =
                u64::from_le_bytes(block[at..at + 8].try_into().map_err(|_| FsError::Corrupt)?);
        }

        Ok(Self {
            kind,
            owner: u32::from_le_bytes(block[4..8].try_into().map_err(|_| FsError::Corrupt)?),
            mode: u16::from_le_bytes(block[20..22].try_into().map_err(|_| FsError::Corrupt)?) & ALL_PERMISSIONS,
            size: u64::from_le_bytes(block[8..16].try_into().map_err(|_| FsError::Corrupt)?),
            blocks_used: u32::from_le_bytes(
                block[16..20].try_into().map_err(|_| FsError::Corrupt)?,
            ),
            direct,
        })
    }

    /// Whether `user` may read (or write) this node. `None` is the kernel
    /// acting on its own account, which permissions do not bind.
    fn permits(&self, user: Option<UserId>, write: bool) -> bool {
        let Some(user) = user else {
            return true;
        };
        let bit = match (user == self.owner, write) {
            (true, false) => OWNER_READ,
            (true, true) => OWNER_WRITE,
            (false, false) => OTHERS_READ,
            (false, true) => OTHERS_WRITE,
        };
        self.mode & bit != 0
    }

    fn node_kind(&self) -> NodeKind {
        if self.kind == 1 {
            NodeKind::Directory
        } else {
            NodeKind::File
        }
    }
}

impl DirEntry {
    fn encode_into(&self, out: &mut [u8]) {
        out[0..8].copy_from_slice(&self.inode.to_le_bytes());
        out[8] = self.name_length;
        out[9..9 + MAX_NAME].copy_from_slice(&self.name);
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut name = [0u8; MAX_NAME];
        name.copy_from_slice(&bytes[9..9 + MAX_NAME]);
        Self {
            inode: u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8])),
            name_length: bytes[8],
            name,
        }
    }

    fn name_str(&self) -> Option<&str> {
        let length = (self.name_length as usize).min(MAX_NAME);
        core::str::from_utf8(&self.name[..length]).ok()
    }
}

/// A mounted filesystem.
pub struct FileSystem {
    device: Arc<dyn BlockDevice>,
    /// Held across disk I/O, so it sleeps rather than spins: a request that
    /// waits on its disk's interrupt must not do so with interrupts masked.
    state: SleepMutex<State>,
}

struct State {
    superblock: SuperBlock,
    /// Which superblock slot is live. The next commit writes the other one.
    live_slot: u64,
    /// The allocation bitmap, held in memory and written out on commit.
    bitmap: Vec<u8>,
    /// Blocks the transaction in progress has stopped referring to.
    ///
    /// Not freed until the commit lands. Freeing one earlier would let the same
    /// transaction allocate it and write over a block the *old* tree still
    /// needs -- which is the one way copy-on-write can still corrupt itself.
    retired: Vec<u64>,
}

impl State {
    fn retire(&mut self, block: u64) {
        self.retired.push(block);
    }
}

impl State {
    fn is_allocated(&self, block: u64) -> bool {
        let index = block as usize;
        self.bitmap
            .get(index / 8)
            .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
    }

    fn mark(&mut self, block: u64, allocated: bool) {
        // Metadata is never released. The superblocks, the bitmap and the
        // inode the root started in are reserved at format time, and the
        // allocator never scans below `first_data_block` -- so clearing one of
        // those bits could not hand the block out, but it would leave the
        // bitmap claiming free space that does not exist.
        //
        // The root inode is the case that reaches here: the first transaction
        // copies the root into the data area, and the original block in
        // reserved space is then unreferenced. One block, once, and it stays
        // marked.
        if !allocated && block < self.superblock.first_data_block {
            return;
        }

        let index = block as usize;
        if let Some(byte) = self.bitmap.get_mut(index / 8) {
            if allocated {
                *byte |= 1 << (index % 8);
            } else {
                *byte &= !(1 << (index % 8));
            }
        }
    }

    /// Find a free block and claim it.
    ///
    /// Never returns a block that is currently live, which is what makes the
    /// copy-on-write argument hold: a commit that fails partway has only
    /// written to space nothing was reading.
    fn allocate(&mut self) -> Result<u64, FsError> {
        for block in self.superblock.first_data_block..self.superblock.total_blocks {
            if !self.is_allocated(block) {
                self.mark(block, true);
                return Ok(block);
            }
        }
        Err(FsError::Full)
    }

    fn free_blocks(&self) -> u64 {
        (self.superblock.first_data_block..self.superblock.total_blocks)
            .filter(|block| !self.is_allocated(*block))
            .count() as u64
    }
}

/// Reject a name before it reaches the disk.
fn check_name(name: &str) -> Result<(), FsError> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(FsError::BadName);
    }
    // A name containing a separator would make one entry addressable by two
    // paths, and `.`/`..` would make the tree cyclic to walk.
    if name.contains('/') || name == "." || name == ".." {
        return Err(FsError::BadName);
    }
    Ok(())
}

impl FileSystem {
    /// Read the superblocks and mount whichever is newer and intact.
    pub fn mount(device: Arc<dyn BlockDevice>) -> Result<Self, FsError> {
        let mut block = vec![0u8; BLOCK_SIZE];

        device.read(0, &mut block)?;
        let first = SuperBlock::decode(&block);
        device.read(1, &mut block)?;
        let second = SuperBlock::decode(&block);

        // The newer generation wins, and a torn one loses to its sibling
        // because it fails its checksum and decodes to `None`. That is the
        // whole crash-recovery story: no log, no replay, no repair pass.
        let (superblock, live_slot) = match (first, second) {
            (Some(a), Some(b)) => {
                if a.generation >= b.generation {
                    (a, 0)
                } else {
                    (b, 1)
                }
            }
            (Some(a), None) => (a, 0),
            (None, Some(b)) => (b, 1),
            (None, None) => return Err(FsError::NotFormatted),
        };

        if superblock.version != VERSION {
            return Err(FsError::WrongVersion);
        }

        let mut bitmap = vec![0u8; (superblock.bitmap_blocks as usize) * BLOCK_SIZE];
        device.read(superblock.bitmap_start, &mut bitmap)?;

        Ok(Self {
            device,
            state: SleepMutex::new(State {
                superblock,
                live_slot,
                bitmap,
                retired: Vec::new(),
            }),
        })
    }

    fn read_block(&self, block: u64) -> Result<Vec<u8>, FsError> {
        let mut buffer = vec![0u8; BLOCK_SIZE];
        self.device.read(block, &mut buffer)?;
        Ok(buffer)
    }

    fn write_block(&self, block: u64, data: &[u8]) -> Result<(), FsError> {
        self.device.write(block, data)?;
        Ok(())
    }

    /// Make everything written since the last commit durable, atomically.
    ///
    /// The order is not negotiable. The bitmap and every changed block are on
    /// disk and flushed *before* the superblock that names them; otherwise a
    /// power cut can leave a superblock pointing at blocks whose contents never
    /// landed, which is precisely the corruption this design is meant to rule
    /// out. The second flush is what makes the superblock itself durable rather
    /// than merely accepted.
    fn commit(&self, state: &mut State) -> Result<(), FsError> {
        self.device
            .write(state.superblock.bitmap_start, &state.bitmap)?;
        self.device.flush()?;

        let next_slot = 1 - state.live_slot;
        state.superblock.generation += 1;
        let encoded = state.superblock.encode();
        self.device.write(next_slot, &encoded)?;
        self.device.flush()?;

        state.live_slot = next_slot;
        Ok(())
    }

    fn read_inode(&self, block: u64) -> Result<Inode, FsError> {
        Inode::decode(&self.read_block(block)?)
    }

    /// Walk a path from the root.
    ///
    /// Returns the block holding the final component's inode.
    ///
    /// Looking a name up in a directory needs read permission on it, so a
    /// private directory hides what is in it even from someone who knows the
    /// name.
    fn resolve(&self, state: &State, path: &str, user: Option<UserId>) -> Result<u64, FsError> {
        let mut current = state.superblock.root_inode;

        for component in path.split('/').filter(|part| !part.is_empty()) {
            let inode = self.read_inode(current)?;
            if inode.node_kind() != NodeKind::Directory {
                return Err(FsError::WrongType);
            }
            if !inode.permits(user, false) {
                return Err(FsError::Denied);
            }
            current = self
                .find_entry(&inode, component)?
                .ok_or(FsError::NotFound)?;
        }

        Ok(current)
    }

    fn find_entry(&self, directory: &Inode, name: &str) -> Result<Option<u64>, FsError> {
        for slot in 0..directory.blocks_used as usize {
            let block = directory.direct[slot];
            if block == 0 {
                continue;
            }
            let data = self.read_block(block)?;
            for index in 0..ENTRIES_PER_BLOCK {
                let at = index * core::mem::size_of::<DirEntry>();
                let entry = DirEntry::decode(&data[at..]);
                if entry.inode == 0 {
                    continue;
                }
                if entry.name_str() == Some(name) {
                    return Ok(Some(entry.inode));
                }
            }
        }
        Ok(None)
    }

    /// Rewrite the path from `directory` down to the component the change
    /// touches, and give back the new block holding `directory`'s inode.
    ///
    /// This is the copy-on-write machinery, and the reason it exists is a bug
    /// the crash test caught: an earlier version updated directory blocks and
    /// inodes *in place*, which meant the committed tree saw the change
    /// immediately and a crash before the superblock landed could not roll it
    /// back. The design claimed copy-on-write; only file data actually had it.
    ///
    /// Nothing reachable from the live superblock is written. Every block on
    /// the path from the root to the change is copied to fresh space, so until
    /// the new superblock lands the old tree is complete and untouched.
    ///
    /// `garbage` collects the blocks the new tree no longer refers to. They are
    /// released only after the commit succeeds, because releasing them earlier
    /// would let this same transaction hand one out and overwrite a block the
    /// old tree still needs.
    fn rewrite(
        &self,
        state: &mut State,
        directory_block: u64,
        components: &[&str],
        access: Access,
        action: Action<'_>,
        garbage: &mut Vec<u64>,
    ) -> Result<u64, FsError> {
        let mut directory = self.read_inode(directory_block)?;
        if directory.node_kind() != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        if !directory.permits(access.user, false) {
            return Err(FsError::Denied);
        }

        let (name, rest) = components.split_first().ok_or(FsError::BadName)?;
        let existing = self.find_entry(&directory, name)?;

        let replacement = if rest.is_empty() {
            // Adding or removing a name is a change to this directory.
            if access.changes_parent && !directory.permits(access.user, true) {
                return Err(FsError::Denied);
            }
            // The change itself happens here.
            action(self, state, existing)?
        } else {
            let child = existing.ok_or(FsError::NotFound)?;
            Some(self.rewrite(state, child, rest, access, action, garbage)?)
        };

        // Rewrite this directory's contents with the entry updated, into blocks
        // nothing currently points at.
        let mut entries: Vec<DirEntry> = Vec::new();
        for slot in 0..directory.blocks_used as usize {
            let block = directory.direct[slot];
            let data = self.read_block(block)?;
            for index in 0..ENTRIES_PER_BLOCK {
                let at = index * core::mem::size_of::<DirEntry>();
                let entry = DirEntry::decode(&data[at..]);
                if entry.inode != 0 && entry.name_str() != Some(*name) {
                    entries.push(entry);
                }
            }
            garbage.push(block);
        }

        if let Some(target) = replacement {
            let mut bytes = [0u8; MAX_NAME];
            bytes[..name.len()].copy_from_slice(name.as_bytes());
            entries.push(DirEntry {
                inode: target,
                name_length: name.len() as u8,
                name: bytes,
            });
        }

        let needed = entries.len().div_ceil(ENTRIES_PER_BLOCK).max(1);
        if needed > DIRECT_BLOCKS {
            return Err(FsError::TooLarge);
        }

        let mut fresh = [0u64; DIRECT_BLOCKS];
        for (slot, chunk) in entries.chunks(ENTRIES_PER_BLOCK).enumerate() {
            let block = state.allocate()?;
            let mut data = vec![0u8; BLOCK_SIZE];
            for (index, entry) in chunk.iter().enumerate() {
                entry.encode_into(&mut data[index * core::mem::size_of::<DirEntry>()..]);
            }
            self.write_block(block, &data)?;
            fresh[slot] = block;
        }
        // An empty directory still needs one block, so a later `link` has
        // somewhere to put the first entry without special-casing zero.
        let used = if entries.is_empty() {
            let block = state.allocate()?;
            self.write_block(block, &vec![0u8; BLOCK_SIZE])?;
            fresh[0] = block;
            1
        } else {
            entries.len().div_ceil(ENTRIES_PER_BLOCK)
        };

        directory.direct = fresh;
        directory.blocks_used = used as u32;
        directory.size = entries.len() as u64;

        let new_inode_block = state.allocate()?;
        self.write_block(new_inode_block, &directory.encode())?;
        garbage.push(directory_block);

        Ok(new_inode_block)
    }

    /// Apply a change to the tree and commit it atomically.
    ///
    /// Everything goes through here, so the copy-on-write discipline is in one
    /// place rather than repeated at each call site with slightly different
    /// mistakes.
    fn transact(
        &self,
        path: &str,
        access: Access,
        mut action: impl FnMut(&FileSystem, &mut State, Option<u64>) -> Result<Option<u64>, FsError>,
    ) -> Result<(), FsError> {
        let components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        if components.is_empty() {
            return Err(FsError::BadName);
        }

        let mut state = self.state.lock();
        let mut garbage = Vec::new();

        let root = state.superblock.root_inode;
        let new_root = self.rewrite(
            &mut state,
            root,
            &components,
            access,
            &mut action,
            &mut garbage,
        )?;

        state.superblock.root_inode = new_root;
        self.commit(&mut state)?;

        // Only now: the superblock naming the new tree has landed, so
        // nothing reachable refers to these any more. Until this point they
        // were still marked in use, both in memory and on the disk the
        // commit just wrote, so a crash anywhere above left the old tree
        // complete.
        let retired = core::mem::take(&mut state.retired);
        for block in garbage.into_iter().chain(retired) {
            state.mark(block, false);
        }
        Ok(())
    }

    /// Create a file or directory at `path`.
    pub fn create(&self, path: &str, kind: NodeKind) -> Result<(), FsError> {
        self.create_as(path, kind, None)
    }

    /// As [`Self::create`], for `user`: it needs write permission on the
    /// directory the name goes in, and owns what it creates.
    pub fn create_as(&self, path: &str, kind: NodeKind, user: Option<UserId>) -> Result<(), FsError> {
        self.create_for(path, kind, user, user.unwrap_or(SYSTEM))
    }

    /// As [`Self::create`], owned by `owner`. Kernel-facing: the one way a node
    /// is made for a user other than the one making it.
    pub fn create_owned_by(&self, path: &str, kind: NodeKind, owner: UserId) -> Result<(), FsError> {
        self.create_for(path, kind, None, owner)
    }

    fn create_for(&self, path: &str, kind: NodeKind, user: Option<UserId>, owner: UserId) -> Result<(), FsError> {
        let (_, name) = split_path(path)?;
        check_name(name)?;

        self.transact(path, Access::changing_parent(user), move |fs, state, existing| {
            if existing.is_some() {
                return Err(FsError::Exists);
            }

            let mut inode = Inode {
                kind: if kind == NodeKind::Directory { 1 } else { 0 },
                owner,
                mode: DEFAULT_MODE,
                size: 0,
                blocks_used: 0,
                direct: [0; DIRECT_BLOCKS],
            };

            if kind == NodeKind::Directory {
                // One empty block, so the directory has somewhere to put its
                // first entry.
                let block = state.allocate()?;
                fs.write_block(block, &vec![0u8; BLOCK_SIZE])?;
                inode.direct[0] = block;
                inode.blocks_used = 1;
            }

            let block = state.allocate()?;
            fs.write_block(block, &inode.encode())?;
            Ok(Some(block))
        })
    }

    /// Replace a file's contents.
    ///
    /// Copy-on-write: the new data goes to freshly allocated blocks and the old
    /// ones are released only once the commit that stops referring to them has
    /// landed. A crash halfway leaves the previous contents entirely intact.
    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<(), FsError> {
        self.write_file_as(path, data, None)
    }

    /// As [`Self::write_file`], for `user`, who needs write permission on the
    /// file.
    pub fn write_file_as(&self, path: &str, data: &[u8], user: Option<UserId>) -> Result<(), FsError> {
        if data.len().div_ceil(BLOCK_SIZE) > DIRECT_BLOCKS {
            return Err(FsError::TooLarge);
        }

        self.transact(path, Access::within_parent(user), move |fs, state, existing| {
            let inode_block = existing.ok_or(FsError::NotFound)?;
            let mut inode = fs.read_inode(inode_block)?;
            if inode.node_kind() != NodeKind::File {
                return Err(FsError::WrongType);
            }
            if !inode.permits(user, true) {
                return Err(FsError::Denied);
            }

            // Fresh blocks for the contents; the old ones stay live until the
            // commit, and are released by `transact` afterwards.
            let mut fresh = [0u64; DIRECT_BLOCKS];
            let mut count = 0;
            for chunk in data.chunks(BLOCK_SIZE) {
                let block = state.allocate()?;
                let mut buffer = vec![0u8; BLOCK_SIZE];
                buffer[..chunk.len()].copy_from_slice(chunk);
                fs.write_block(block, &buffer)?;
                fresh[count] = block;
                count += 1;
            }

            for slot in 0..inode.blocks_used as usize {
                if inode.direct[slot] != 0 {
                    state.retire(inode.direct[slot]);
                }
            }
            state.retire(inode_block);

            inode.direct = fresh;
            inode.blocks_used = count as u32;
            inode.size = data.len() as u64;

            let new_block = state.allocate()?;
            fs.write_block(new_block, &inode.encode())?;
            Ok(Some(new_block))
        })
    }

    /// Read a whole file.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, FsError> {
        self.read_file_as(path, None)
    }

    /// As [`Self::read_file`], for `user`, who needs read permission on it.
    pub fn read_file_as(&self, path: &str, user: Option<UserId>) -> Result<Vec<u8>, FsError> {
        let state = self.state.lock();
        let inode_block = self.resolve(&state, path, user)?;
        let inode = self.read_inode(inode_block)?;
        if inode.node_kind() != NodeKind::File {
            return Err(FsError::WrongType);
        }
        if !inode.permits(user, false) {
            return Err(FsError::Denied);
        }

        let mut out = Vec::with_capacity(inode.size as usize);
        let mut left = inode.size as usize;
        for slot in 0..inode.blocks_used as usize {
            let block = self.read_block(inode.direct[slot])?;
            let take = left.min(BLOCK_SIZE);
            out.extend_from_slice(&block[..take]);
            left -= take;
        }
        Ok(out)
    }

    /// Names in a directory.
    pub fn list(&self, path: &str) -> Result<Vec<String>, FsError> {
        self.list_as(path, None)
    }

    /// As [`Self::list`], for `user`, who needs read permission on it.
    pub fn list_as(&self, path: &str, user: Option<UserId>) -> Result<Vec<String>, FsError> {
        let state = self.state.lock();
        let inode_block = self.resolve(&state, path, user)?;
        let inode = self.read_inode(inode_block)?;
        if inode.node_kind() != NodeKind::Directory {
            return Err(FsError::WrongType);
        }
        if !inode.permits(user, false) {
            return Err(FsError::Denied);
        }

        let mut names = Vec::new();
        for slot in 0..inode.blocks_used as usize {
            let data = self.read_block(inode.direct[slot])?;
            for index in 0..ENTRIES_PER_BLOCK {
                let at = index * core::mem::size_of::<DirEntry>();
                let entry = DirEntry::decode(&data[at..]);
                if entry.inode == 0 {
                    continue;
                }
                if let Some(name) = entry.name_str() {
                    names.push(String::from(name));
                }
            }
        }
        Ok(names)
    }

    /// Remove a file, or an empty directory.
    pub fn remove(&self, path: &str) -> Result<(), FsError> {
        self.remove_as(path, None)
    }

    /// As [`Self::remove`], for `user`, who needs write permission on the
    /// directory holding the name. As on Unix without the sticky bit, that is
    /// all: whoever may change a directory may remove what is in it.
    pub fn remove_as(&self, path: &str, user: Option<UserId>) -> Result<(), FsError> {
        let (_, name) = split_path(path)?;
        check_name(name)?;

        self.transact(path, Access::changing_parent(user), move |fs, state, existing| {
            let target_block = existing.ok_or(FsError::NotFound)?;
            let target = fs.read_inode(target_block)?;

            // A directory that still holds names would leave them unreachable:
            // nothing else refers to those inodes.
            if target.node_kind() == NodeKind::Directory && target.size > 0 {
                return Err(FsError::NotEmpty);
            }

            for slot in 0..target.blocks_used as usize {
                if target.direct[slot] != 0 {
                    state.retire(target.direct[slot]);
                }
            }
            state.retire(target_block);

            // No replacement: the entry disappears from the rewritten parent.
            Ok(None)
        })
    }

    /// Whether a path exists, and what it is.
    pub fn stat(&self, path: &str) -> Result<(NodeKind, u64), FsError> {
        self.stat_as(path, None)
    }

    /// As [`Self::stat`], for `user`, who needs only to be able to reach it.
    pub fn stat_as(&self, path: &str, user: Option<UserId>) -> Result<(NodeKind, u64), FsError> {
        let state = self.state.lock();
        let inode_block = self.resolve(&state, path, user)?;
        let inode = self.read_inode(inode_block)?;
        Ok((inode.node_kind(), inode.size))
    }

    /// Who owns a node, and its permission bits.
    pub fn owner_as(&self, path: &str, user: Option<UserId>) -> Result<(UserId, u16), FsError> {
        let state = self.state.lock();
        let inode_block = self.resolve(&state, path, user)?;
        let inode = self.read_inode(inode_block)?;
        Ok((inode.owner, inode.mode))
    }

    /// Change a node's permission bits. Only its owner may; there is no way to
    /// change who the owner is, so a file cannot be given away to make it
    /// somebody else's problem.
    pub fn set_mode_as(&self, path: &str, mode: u16, user: Option<UserId>) -> Result<(), FsError> {
        if mode & !ALL_PERMISSIONS != 0 {
            return Err(FsError::BadName);
        }
        self.transact(path, Access::within_parent(user), move |fs, state, existing| {
            let inode_block = existing.ok_or(FsError::NotFound)?;
            let mut inode = fs.read_inode(inode_block)?;
            if user.is_some_and(|user| user != inode.owner) {
                return Err(FsError::Denied);
            }
            inode.mode = mode;
            // Copy-on-write like any other change: the old inode is released
            // once the commit that stops naming it has landed.
            state.retire(inode_block);
            let new_block = state.allocate()?;
            fs.write_block(new_block, &inode.encode())?;
            Ok(Some(new_block))
        })
    }

    /// Blocks not currently in use.
    pub fn free_blocks(&self) -> u64 {
        self.state.lock().free_blocks()
    }

    /// Commits since the filesystem was created. Diagnostic, and how a test
    /// tells one commit from none.
    pub fn generation(&self) -> u64 {
        self.state.lock().superblock.generation
    }
}

/// The filesystem the rest of the kernel talks to.
///
/// One, because there is no mount table yet: a second disk is visible as a
/// block device and nothing above knows how to name it.
static ROOT: crate::sync::Mutex<Option<Arc<FileSystem>>> = crate::sync::Mutex::new(None);

/// Find a filesystem on the attached disks and mount it.
///
/// Deliberately does not format anything it fails to recognise. A kernel that
/// formats an unrecognised disk destroys whatever was on it -- and "I did not
/// recognise it" covers a disk written by a newer version of this very
/// filesystem.
pub fn mount_root() {
    for index in 0..crate::block::count() {
        let Some(disk) = crate::block::device(index) else {
            continue;
        };

        // Whole-device first, then each partition. A disk formatted directly is
        // what the tests produce; a partitioned one is what a real install
        // looks like.
        let mut candidates: alloc::vec::Vec<Arc<dyn BlockDevice>> = alloc::vec![disk.clone()];
        if let Ok(partitions) = crate::block::partition::read(&*disk) {
            for entry in partitions {
                if let Ok(view) = crate::block::partition::PartitionDevice::new(disk.clone(), &entry)
                {
                    candidates.push(Arc::new(view));
                }
            }
        }

        for candidate in candidates {
            let Ok(fs) = FileSystem::mount(candidate) else {
                continue;
            };
            crate::println!(
                "fs: mounted on disk {index}, {} free blocks",
                fs.free_blocks()
            );
            crate::sync::without_interrupts(|| {
                *ROOT.lock() = Some(Arc::new(fs));
            });
            return;
        }
    }
}

/// The mounted filesystem, if there is one.
pub fn root() -> Option<Arc<FileSystem>> {
    crate::sync::without_interrupts(|| ROOT.lock().clone())
}

/// Mount a filesystem the caller has already opened. Test support.
pub fn set_root(fs: Arc<FileSystem>) {
    crate::sync::without_interrupts(|| *ROOT.lock() = Some(fs));
}

/// Split a path into its parent and final component.
fn split_path(path: &str) -> Result<(&str, &str), FsError> {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(index) => Ok((&trimmed[..index], &trimmed[index + 1..])),
        None => {
            if trimmed.is_empty() {
                Err(FsError::BadName)
            } else {
                Ok(("", trimmed))
            }
        }
    }
}
