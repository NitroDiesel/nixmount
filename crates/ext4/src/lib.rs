//! Memory-safe ext2/ext3/ext4 engine.
//!
//! All metadata changes go through a transaction ([`Fs::dirty`]) that is committed
//! through the on-disk jbd2 journal when the volume has one, so a crash at any point
//! leaves a volume that replays cleanly on Windows or Linux. File data is ordered:
//! it reaches the disk before the metadata that references it.
//!
//! Every on-disk value is treated as hostile: geometry is validated at mount, block
//! numbers are range-checked on use, and walks are bounded.
#![forbid(unsafe_code)]

mod alloc;
mod dir;
mod extent;
mod file;
mod hash;
mod indirect;
mod inode;
mod journal;
mod mount;
mod ops;
mod xattr;

use fscore::cache::BlockCache;
use fscore::{BlockDev, FsError, Result};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

pub use mount::{inspect, Ext4};

pub(crate) const ROOT_INO: u32 = 2;

/// Immutable geometry derived from the validated superblock.
pub(crate) struct Geo {
    pub bs: usize,
    pub blocks: u64,
    pub first_data: u64,
    pub bpg: u32,
    pub ipg: u32,
    pub cpg: u32,
    pub inodes: u32,
    pub isize: usize,
    pub desc_size: usize,
    pub groups: u32,
    pub first_ino: u32,
    pub csum_seed: u32,
    pub metadata_csum: bool,
    pub gdt_csum: bool,
    pub is_64bit: bool,
    pub extents: bool,
    pub filetype: bool,
    pub dir_index: bool,
    pub large_dir: bool,
    pub sparse_super: bool,
    pub meta_bg: bool,
    pub first_meta_bg: u32,
    pub reserved_gdt: u32,
    pub huge_file: bool,
    pub hash_seed: [u32; 4],
    pub def_hash: u8,
    pub hash_unsigned: bool,
    pub want_extra: u16,
    pub uuid: [u8; 16],
}

impl Geo {
    /// Descriptors held by one block.
    pub fn gd_per_block(&self) -> u32 {
        (self.bs / self.desc_size) as u32
    }
    pub fn gd_blocks(&self) -> u64 {
        (self.groups as u64).div_ceil(self.gd_per_block() as u64)
    }
    pub fn group_start(&self, g: u32) -> u64 {
        self.first_data + g as u64 * self.bpg as u64
    }
    pub fn group_of(&self, block: u64) -> u32 {
        (block.saturating_sub(self.first_data) / self.bpg as u64).min(self.groups as u64 - 1) as u32
    }
    /// Blocks in group `g`; the last group is usually short.
    pub fn group_blocks(&self, g: u32) -> u32 {
        (self.blocks - self.group_start(g)).min(self.bpg as u64) as u32
    }
    /// Whether group `g` holds a superblock backup.
    pub fn has_super(&self, g: u32) -> bool {
        if !self.sparse_super || g <= 1 {
            return true;
        }
        [3u32, 5, 7].iter().any(|&p| {
            let mut n = p;
            while n < g {
                match n.checked_mul(p) {
                    Some(m) => n = m,
                    None => return false,
                }
            }
            n == g
        })
    }
}

/// Mutable volume state. Readers share it, writers hold it exclusively.
pub(crate) struct Fs {
    pub g: Geo,
    pub dev: Arc<dyn BlockDev>,
    pub cache: BlockCache,
    pub sb: Vec<u8>,
    pub gds: Vec<u8>,
    /// The running transaction: metadata blocks changed but not yet committed.
    pub dirty: HashMap<u64, Arc<[u8]>>,
    /// Journal contents replayed in memory for read-only mounts of dirty volumes,
    /// so looking at a volume never changes it.
    pub overlay: HashMap<u64, Arc<[u8]>>,
    /// Blocks freed in this transaction. Their bitmap bits clear at commit, which
    /// keeps them from being reused while the old metadata may still be what's on disk.
    pub pending_free: Vec<(u64, u32)>,
    pub touched: BTreeSet<u32>,
    pub journal: Option<journal::Journal>,
    pub read_only: bool,
    pub ro_reasons: Vec<String>,
    pub notes: Vec<String>,
    pub features: Vec<String>,
    /// Savepoint of the operation in progress, for rollback on failure.
    pub undo: Option<Undo>,
}

/// What an operation changed, so a failure leaves earlier work in the transaction intact.
#[derive(Default)]
pub(crate) struct Undo {
    pub blocks: HashMap<u64, Option<Arc<[u8]>>>,
    pub gds: HashMap<u32, Vec<u8>>,
    pub sb: Vec<u8>,
    pub pending: usize,
}

impl Fs {
    pub fn check_block(&self, n: u64) -> Result<()> {
        if n >= self.g.blocks {
            return Err(FsError::Corrupt(format!("block {n} is outside the volume")));
        }
        Ok(())
    }

    /// Reads a metadata block through the transaction, recovery overlay and cache.
    pub fn block(&self, n: u64) -> Result<Arc<[u8]>> {
        if let Some(b) = self.dirty.get(&n).or_else(|| self.overlay.get(&n)) {
            return Ok(b.clone());
        }
        if let Some(b) = self.cache.get(n) {
            return Ok(b);
        }
        self.check_block(n)?;
        let mut v = vec![0; self.g.bs];
        self.dev.read_at(n * self.g.bs as u64, &mut v)?;
        let b: Arc<[u8]> = v.into();
        self.cache.insert(n, b.clone());
        Ok(b)
    }

    /// Remembers block `n`'s transaction state before the current operation changes it.
    pub fn note_undo(&mut self, n: u64) {
        if let Some(u) = &mut self.undo {
            let old = self.dirty.get(&n).cloned();
            u.blocks.entry(n).or_insert(old);
        }
    }

    pub fn begin_op(&mut self) {
        self.undo = Some(Undo { sb: self.sb.clone(), pending: self.pending_free.len(), ..Undo::default() });
    }

    /// Reverts everything the current operation did.
    pub fn rollback_op(&mut self) {
        let Some(u) = self.undo.take() else { return };
        for (n, old) in u.blocks {
            match old {
                Some(b) => self.dirty.insert(n, b),
                None => self.dirty.remove(&n),
            };
        }
        for (g, d) in u.gds {
            let o = g as usize * self.g.desc_size;
            self.gds[o..o + d.len()].copy_from_slice(&d);
        }
        self.sb = u.sb;
        self.pending_free.truncate(u.pending);
    }

    /// A writable view of a metadata block in the running transaction.
    pub fn modify(&mut self, n: u64) -> Result<&mut [u8]> {
        self.note_undo(n);
        if !self.dirty.contains_key(&n) {
            let b = self.block(n)?;
            self.dirty.insert(n, b);
        }
        let e = self.dirty.get_mut(&n).ok_or(FsError::Invalid("dirty block vanished"))?;
        Ok(Arc::make_mut(e))
    }

    /// Starts a metadata block from zeroes, without reading what was there.
    pub fn fresh(&mut self, n: u64) -> Result<&mut [u8]> {
        self.check_block(n)?;
        self.note_undo(n);
        self.dirty.insert(n, vec![0u8; self.g.bs].into());
        self.modify(n)
    }

    pub fn require_write(&self) -> Result<()> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        Ok(())
    }
}

pub(crate) type Shared = RwLock<Fs>;

pub(crate) fn corrupt<T>(msg: impl Into<String>) -> Result<T> {
    Err(FsError::Corrupt(msg.into()))
}
