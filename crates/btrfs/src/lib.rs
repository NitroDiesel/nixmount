//! Memory-safe Btrfs engine.
//!
//! Reads every profile (single, DUP, RAID0/1/10/1C3/1C4/5/6), all checksum algorithms and
//! all compression codecs, and verifies checksums on every read. Writes follow the same
//! copy-on-write rule as the format itself: nothing the last committed superblock can
//! reach is ever overwritten, so a crash at any point leaves the previous transaction.
//!
//! All on-disk data is treated as hostile; see [`tree::validate`].
#![forbid(unsafe_code)]

mod alloc;
mod chunk;
mod commit;
mod compress;
mod cow;
mod file;
mod inode;
mod mount;
mod ops;
mod refs;
mod scrub;
mod subvol;
mod tree;

use chunk::Chunk;
use fscore::cache::BlockCache;
use fscore::{BlockDev, FsError, Result};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

pub use mount::{group_devices, Btrfs};

pub const K_INODE_ITEM: u8 = 1;
pub const K_INODE_REF: u8 = 12;
pub const K_INODE_EXTREF: u8 = 13;
pub const K_XATTR_ITEM: u8 = 24;
pub const K_DIR_ITEM: u8 = 84;
pub const K_DIR_INDEX: u8 = 96;
pub const K_EXTENT_DATA: u8 = 108;
pub const K_EXTENT_CSUM: u8 = 128;
pub const K_ROOT_ITEM: u8 = 132;
pub const K_ROOT_BACKREF: u8 = 144;
pub const K_ROOT_REF: u8 = 156;
pub const K_EXTENT_ITEM: u8 = 168;
pub const K_METADATA_ITEM: u8 = 169;
pub const K_TREE_BLOCK_REF: u8 = 176;
pub const K_EXTENT_DATA_REF: u8 = 178;
pub const K_SHARED_BLOCK_REF: u8 = 182;
pub const K_SHARED_DATA_REF: u8 = 184;
pub const K_BLOCK_GROUP_ITEM: u8 = 192;
pub const K_FREE_SPACE_INFO: u8 = 198;
pub const K_FREE_SPACE_EXTENT: u8 = 199;
pub const K_FREE_SPACE_BITMAP: u8 = 200;
pub const K_DEV_EXTENT: u8 = 204;
pub const K_DEV_ITEM: u8 = 216;
pub const K_CHUNK_ITEM: u8 = 228;
pub const K_UUID_SUBVOL: u8 = 251;

pub const ROOT_TREE: u64 = 1;
pub const EXTENT_TREE: u64 = 2;
pub const CHUNK_TREE: u64 = 3;
pub const DEV_TREE: u64 = 4;
pub const FS_TREE: u64 = 5;
pub const ROOT_DIR: u64 = 6;
pub const CSUM_TREE: u64 = 7;
pub const QUOTA_TREE: u64 = 8;
pub const UUID_TREE: u64 = 9;
pub const FREE_SPACE_TREE: u64 = 10;
pub const BLOCK_GROUP_TREE: u64 = 11;
pub const FIRST_FREE: u64 = 256;
pub const LAST_FREE: u64 = u64::MAX - 256;
pub const CSUM_OBJECTID: u64 = -10i64 as u64;

/// A B-tree key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Key {
    pub obj: u64,
    pub ty: u8,
    pub off: u64,
}

impl Key {
    pub const fn new(obj: u64, ty: u8, off: u64) -> Key {
        Key { obj, ty, off }
    }
}

/// Where a tree starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub bytenr: u64,
    pub level: u8,
}

/// Mutable volume state.
pub(crate) struct Fs {
    pub devs: HashMap<u64, Arc<dyn BlockDev>>,
    pub sb: Vec<u8>,
    pub nodesize: usize,
    pub sectorsize: usize,
    pub csum_type: u16,
    pub csum_size: usize,
    pub fsid: [u8; 16],
    pub chunks: BTreeMap<u64, Chunk>,
    pub cache: BlockCache,
    pub root_tree: Root,
    pub chunk_tree: Root,
    pub default_subvol: u64,
    pub read_only: bool,
    pub ro_reasons: Vec<String>,
    pub notes: Vec<String>,
    pub features: Vec<String>,
    pub incompat: u64,
    pub compat_ro: u64,
    pub txn: commit::Txn,
    pub alloc: alloc::Allocator,
}

pub(crate) fn bad<T>(msg: impl Into<String>) -> Result<T> {
    Err(FsError::Corrupt(msg.into()))
}

pub(crate) type Shared = RwLock<Fs>;
