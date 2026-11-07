//! Device assembly, superblock selection and the mount policy.
use crate::chunk::{parse_chunk, Chunk, PROFILE_MASK, RAID5, RAID6};
use crate::*;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use fscore::{crc32c_raw, fmt_uuid, Le, MountOpts, VolumeInfo};
use sha2::Sha256;

pub const SB_OFFSETS: [u64; 3] = [0x1_0000, 0x400_0000, 0x40_0000_0000];
pub const SB_SIZE: usize = 4096;
const MAGIC: &[u8; 8] = b"_BHRfS_M";

pub const IN_MIXED_BACKREF: u64 = 1 << 0;
pub const IN_DEFAULT_SUBVOL: u64 = 1 << 1;
pub const IN_MIXED_GROUPS: u64 = 1 << 2;
pub const IN_LZO: u64 = 1 << 3;
pub const IN_ZSTD: u64 = 1 << 4;
pub const IN_BIG_METADATA: u64 = 1 << 5;
pub const IN_EXTENDED_IREF: u64 = 1 << 6;
pub const IN_RAID56: u64 = 1 << 7;
pub const IN_SKINNY: u64 = 1 << 8;
pub const IN_NO_HOLES: u64 = 1 << 9;
pub const IN_METADATA_UUID: u64 = 1 << 10;
pub const IN_RAID1C34: u64 = 1 << 11;
pub const IN_ZONED: u64 = 1 << 12;
pub const IN_EXTENT_TREE_V2: u64 = 1 << 13;
pub const IN_RAID_STRIPE_TREE: u64 = 1 << 14;
pub const IN_SIMPLE_QUOTA: u64 = 1 << 16;
const IN_KNOWN: u64 = IN_MIXED_BACKREF
    | IN_DEFAULT_SUBVOL
    | IN_MIXED_GROUPS
    | IN_LZO
    | IN_ZSTD
    | IN_BIG_METADATA
    | IN_EXTENDED_IREF
    | IN_RAID56
    | IN_SKINNY
    | IN_NO_HOLES
    | IN_METADATA_UUID
    | IN_RAID1C34
    | IN_SIMPLE_QUOTA;

pub const RO_FREE_SPACE_TREE: u64 = 1;
pub const RO_FREE_SPACE_TREE_VALID: u64 = 2;
pub const RO_VERITY: u64 = 4;
pub const RO_BLOCK_GROUP_TREE: u64 = 8;
const RO_KNOWN: u64 = RO_FREE_SPACE_TREE | RO_FREE_SPACE_TREE_VALID | RO_VERITY | RO_BLOCK_GROUP_TREE;

fn raw_csum(ty: u16, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    match ty {
        0 => out[..4].copy_from_slice(&crc32c::crc32c(data).to_le_bytes()),
        1 => out[..8].copy_from_slice(&xxhash_rust::xxh64::xxh64(data, 0).to_le_bytes()),
        2 => out.copy_from_slice(&Sha256::digest(data)),
        3 => out.copy_from_slice(&Blake2b::<U32>::digest(data)),
        _ => {}
    }
    out
}

fn csum_len(ty: u16) -> Option<usize> {
    match ty {
        0 => Some(4),
        1 => Some(8),
        2 | 3 => Some(32),
        _ => None,
    }
}

impl Fs {
    pub fn csum(&self, data: &[u8]) -> [u8; 32] {
        raw_csum(self.csum_type, data)
    }
    pub fn csum_matches(&self, data: &[u8], stored: &[u8]) -> bool {
        let c = self.csum(data);
        stored.len() >= self.csum_size && c[..self.csum_size] == stored[..self.csum_size]
    }
}

fn sb_valid(b: &[u8], at: u64) -> bool {
    if &b[0x40..0x48] != MAGIC || b.u64_at(0x30) != at {
        return false;
    }
    let ty = b.u16_at(0xC4);
    csum_len(ty).is_some_and(|n| raw_csum(ty, &b[0x20..SB_SIZE])[..n] == b[..n])
}

/// The newest valid superblock on a device.
fn read_super(dev: &dyn BlockDev) -> Result<Vec<u8>> {
    let mut best: Option<Vec<u8>> = None;
    for at in SB_OFFSETS {
        if at + SB_SIZE as u64 > dev.len() {
            continue;
        }
        let mut b = vec![0u8; SB_SIZE];
        if dev.read_at(at, &mut b).is_ok()
            && sb_valid(&b, at)
            && best.as_ref().is_none_or(|x| b.u64_at(0x48) > x.u64_at(0x48))
        {
            best = Some(b);
        }
    }
    best.ok_or_else(|| FsError::Corrupt("no valid btrfs superblock".into()))
}

/// Identifies a member device: (filesystem uuid, device id, devices in the filesystem).
pub fn group_devices(dev: &dyn BlockDev) -> Result<([u8; 16], u64, u64)> {
    let sb = read_super(dev)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&sb[0x20..0x30]);
    Ok((id, sb.u64_at(0xC9), sb.u64_at(0x88)))
}

pub struct Btrfs {
    pub(crate) fs: Shared,
}

fn feature_names(incompat: u64, ro: u64) -> Vec<String> {
    let t: &[(u64, &str)] = &[
        (IN_MIXED_BACKREF, "mixed_backref"),
        (IN_DEFAULT_SUBVOL, "default_subvol"),
        (IN_MIXED_GROUPS, "mixed_groups"),
        (IN_LZO, "compress_lzo"),
        (IN_ZSTD, "compress_zstd"),
        (IN_BIG_METADATA, "big_metadata"),
        (IN_EXTENDED_IREF, "extended_iref"),
        (IN_RAID56, "raid56"),
        (IN_SKINNY, "skinny_metadata"),
        (IN_NO_HOLES, "no_holes"),
        (IN_METADATA_UUID, "metadata_uuid"),
        (IN_RAID1C34, "raid1c34"),
    ];
    let mut v: Vec<String> = t.iter().filter(|x| incompat & x.0 != 0).map(|x| x.1.to_string()).collect();
    if ro & RO_FREE_SPACE_TREE != 0 {
        v.push("free_space_tree".into());
    }
    if ro & RO_BLOCK_GROUP_TREE != 0 {
        v.push("block_group_tree".into());
    }
    v
}

impl Btrfs {
    /// Assembles and mounts a filesystem from its member devices. Missing members are
    /// tolerated read-only when the profiles allow it.
    pub fn open(devices: Vec<Arc<dyn BlockDev>>, opts: MountOpts) -> Result<Btrfs> {
        let mut supers: Vec<(Vec<u8>, Arc<dyn BlockDev>)> = vec![];
        for d in devices {
            supers.push((read_super(d.as_ref())?, d));
        }
        supers.sort_by_key(|s| std::cmp::Reverse(s.0.u64_at(0x48)));
        let Some((sb, _)) = supers.first() else { return bad("no devices") };
        let sb = sb.clone();
        let fsid = sb[0x20..0x30].to_vec();
        let (incompat, compat_ro) = (sb.u64_at(0xBC), sb.u64_at(0xB4));
        if incompat & !IN_KNOWN != 0 {
            return Err(FsError::Unsupported(format!("incompatible features {:#x}", incompat & !IN_KNOWN)));
        }
        let (nodesize, sectorsize) = (sb.u32_at(0x94) as usize, sb.u32_at(0x90) as usize);
        if !nodesize.is_power_of_two() || !(4096..=65536).contains(&nodesize) {
            return bad("invalid node size");
        }
        if !sectorsize.is_power_of_two() || !(4096..=65536).contains(&sectorsize) || sectorsize > nodesize {
            return bad("invalid sector size");
        }
        let csum_type = sb.u16_at(0xC4);
        let csum_size = csum_len(csum_type).ok_or_else(|| FsError::Unsupported("unknown checksum".into()))?;
        let mut tree_id = [0u8; 16];
        tree_id.copy_from_slice(if incompat & IN_METADATA_UUID != 0 { &sb[0x23B..0x24B] } else { &fsid });

        let mut devs = HashMap::new();
        let mut reasons: Vec<String> = vec![];
        for (s, d) in supers {
            if s[0x20..0x30] != fsid[..] {
                return Err(FsError::Invalid("devices belong to different filesystems"));
            }
            if s.u64_at(0x48) != sb.u64_at(0x48) {
                reasons.push("member devices are at different generations".into());
            }
            devs.insert(s.u64_at(0xC9), d);
        }
        if devs.len() as u64 != sb.u64_at(0x88) {
            reasons.push(format!("degraded: {} of {} devices present", devs.len(), sb.u64_at(0x88)));
        }
        let cache_bytes = if opts.cache_bytes == 0 { 32 << 20 } else { opts.cache_bytes };
        let mut fs = Fs {
            devs,
            cache: BlockCache::new(cache_bytes, nodesize),
            nodesize,
            sectorsize,
            csum_type,
            csum_size,
            fsid: tree_id,
            chunks: BTreeMap::new(),
            root_tree: Root { bytenr: sb.u64_at(0x50), level: sb.u8_at(0xC6) },
            chunk_tree: Root { bytenr: sb.u64_at(0x58), level: sb.u8_at(0xC7) },
            default_subvol: FS_TREE,
            read_only: true,
            ro_reasons: vec![],
            notes: vec![],
            features: feature_names(incompat, compat_ro),
            incompat,
            compat_ro,
            txn: commit::Txn::default(),
            alloc: alloc::Allocator::default(),
            sb,
        };
        fs.load_sys_chunks()?;
        fs.load_chunk_tree()?;
        fs.find_default_subvol()?;

        if fs.sb.u64_at(0x60) != 0 {
            fs.notes.push("unclean shutdown: fsync log ignored, the last moments of writes may be missing".into());
            reasons.push("a tree log is pending: mount once in Linux to replay it".into());
        }
        if compat_ro & !RO_KNOWN != 0 {
            reasons.push(format!("unknown read-only features {:#x}", compat_ro & !RO_KNOWN));
        }
        if compat_ro & RO_VERITY != 0 {
            reasons.push("verity: protected files must stay untouched".into());
        }
        if incompat & IN_MIXED_GROUPS != 0 {
            reasons.push("mixed block groups aren't writable yet".into());
        }
        if incompat & IN_SIMPLE_QUOTA != 0 {
            reasons.push("simple quotas would go stale".into());
        }
        if compat_ro & RO_FREE_SPACE_TREE != 0 && compat_ro & RO_FREE_SPACE_TREE_VALID == 0 {
            reasons.push("the free space tree is marked invalid".into());
        }
        if fs.chunks.values().any(|c| c.ty & (RAID5 | RAID6) != 0) {
            reasons.push("RAID5/6 volumes are read-only here: the write hole risks data on a crash".into());
        }
        if fs.root_item(QUOTA_TREE).is_ok() {
            reasons.push("quotas are enabled: writing would leave qgroup accounting stale".into());
        }
        if opts.write && fs.devs.values().any(|d| !d.writable()) {
            reasons.push("a device was opened read-only".into());
        }
        fs.read_only = !opts.write || !reasons.is_empty();
        fs.ro_reasons = reasons;
        if !fs.read_only {
            fs.begin_writes()?;
        }
        Ok(Btrfs { fs: RwLock::new(fs) })
    }
}

impl Fs {
    fn load_sys_chunks(&mut self) -> Result<()> {
        let size = (self.sb.u32_at(0xA0) as usize).min(2048);
        let array = self.sb[0x32B..0x32B + size].to_vec();
        let mut o = 0;
        while o + 17 + 48 <= array.len() {
            let k = tree::key_at(&array, o);
            if k.ty != K_CHUNK_ITEM {
                return bad("bad system chunk array");
            }
            o += 17;
            let n = array.u16_at(o + 44) as usize;
            let end = o + 48 + n * 32;
            let Some(item) = array.get(o..end) else { return bad("system chunk overruns") };
            let c = parse_chunk(k.off, item)?;
            self.chunks.insert(c.start, c);
            o = end;
        }
        Ok(())
    }

    fn load_chunk_tree(&mut self) -> Result<()> {
        let mut found: Vec<Chunk> = vec![];
        let start = Key::new(256, K_CHUNK_ITEM, 0);
        self.scan(self.chunk_tree, start, &mut |k, d| {
            if k.ty == K_CHUNK_ITEM {
                found.push(parse_chunk(k.off, d)?);
            }
            Ok(true)
        })?;
        for c in found {
            self.chunks.insert(c.start, c);
        }
        Ok(())
    }

    /// The `default` entry in the root directory says which subvolume mounts as `/`.
    fn find_default_subvol(&mut self) -> Result<()> {
        let dir = Key::new(self.sb.u64_at(0x80), K_DIR_ITEM, inode::name_hash(b"default"));
        if let Some(d) = self.get(self.root_tree, dir)? {
            if let Some(e) = inode::parse_dir_items(&d)?.into_iter().find(|e| e.name == b"default") {
                self.default_subvol = e.location.obj;
            }
        }
        Ok(())
    }

    pub fn volume_info(&self) -> VolumeInfo {
        let label = self.sb[0x12B..0x22B].split(|b| *b == 0).next().unwrap_or(&[]);
        let total = self.sb.u64_at(0x70);
        let used = self.sb.u64_at(0x78);
        let mut features = self.features.clone();
        let profiles: std::collections::BTreeSet<String> = self
            .chunks
            .values()
            .map(|c| {
                let p = match c.ty & PROFILE_MASK {
                    chunk::RAID0 => "raid0",
                    chunk::RAID1 => "raid1",
                    chunk::DUP => "dup",
                    chunk::RAID10 => "raid10",
                    RAID5 => "raid5",
                    RAID6 => "raid6",
                    chunk::RAID1C3 => "raid1c3",
                    chunk::RAID1C4 => "raid1c4",
                    _ => "single",
                };
                p.to_string()
            })
            .collect();
        features.extend(profiles);
        VolumeInfo {
            fs_type: "btrfs".into(),
            label: String::from_utf8_lossy(label).into_owned(),
            uuid: fmt_uuid(&self.sb[0x20..0x30]),
            block_size: self.sectorsize as u32,
            total_bytes: total,
            free_bytes: total.saturating_sub(used),
            read_only: self.read_only,
            ro_reasons: self.ro_reasons.clone(),
            notes: self.notes.clone(),
            features,
        }
    }
}

/// CRC-32C of a little-endian u64, the building block of extent ref hashes.
pub fn crc_le(seed: u32, v: u64) -> u32 {
    crc32c_raw(seed, &v.to_le_bytes())
}
