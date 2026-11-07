//! Superblock validation and the mount policy: a volume is only writable when every
//! feature it uses is fully supported and its state is known to be safe.
use crate::inode::{Inode, F_INLINE};
use crate::journal::Journal;
use crate::{corrupt, Fs, Geo, Shared};
use fscore::cache::BlockCache;
use fscore::{crc32c_raw, fmt_uuid, BlockDev, FsError, Le, LeMut, MountOpts, Result, Time, VolumeInfo};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

const SB_OFFSET: u64 = 1024;
const MAGIC: u16 = 0xEF53;

const COMPAT_HAS_JOURNAL: u32 = 0x4;
const COMPAT_DIR_INDEX: u32 = 0x20;
const COMPAT_SPARSE_SUPER2: u32 = 0x200;
const COMPAT_FAST_COMMIT: u32 = 0x400;

const IN_COMPRESSION: u32 = 0x1;
const IN_FILETYPE: u32 = 0x2;
const IN_RECOVER: u32 = 0x4;
const IN_JOURNAL_DEV: u32 = 0x8;
const IN_META_BG: u32 = 0x10;
const IN_EXTENTS: u32 = 0x40;
const IN_64BIT: u32 = 0x80;
const IN_MMP: u32 = 0x100;
const IN_FLEX_BG: u32 = 0x200;
const IN_EA_INODE: u32 = 0x400;
const IN_DIRDATA: u32 = 0x1000;
const IN_CSUM_SEED: u32 = 0x2000;
const IN_LARGEDIR: u32 = 0x4000;
const IN_INLINE_DATA: u32 = 0x8000;
const IN_ENCRYPT: u32 = 0x1_0000;
const IN_CASEFOLD: u32 = 0x2_0000;
const IN_KNOWN: u32 = IN_FILETYPE
    | IN_RECOVER
    | IN_META_BG
    | IN_EXTENTS
    | IN_64BIT
    | IN_MMP
    | IN_FLEX_BG
    | IN_EA_INODE
    | IN_CSUM_SEED
    | IN_LARGEDIR
    | IN_INLINE_DATA
    | IN_ENCRYPT
    | IN_CASEFOLD;

const RO_SPARSE_SUPER: u32 = 0x1;
const RO_LARGE_FILE: u32 = 0x2;
const RO_HUGE_FILE: u32 = 0x8;
const RO_GDT_CSUM: u32 = 0x10;
const RO_DIR_NLINK: u32 = 0x20;
const RO_EXTRA_ISIZE: u32 = 0x40;
const RO_QUOTA: u32 = 0x100;
const RO_BIGALLOC: u32 = 0x200;
const RO_METADATA_CSUM: u32 = 0x400;
const RO_READONLY: u32 = 0x1000;
const RO_PROJECT: u32 = 0x2000;
const RO_SHARED_BLOCKS: u32 = 0x4000;
const RO_VERITY: u32 = 0x8000;
const RO_ORPHAN_PRESENT: u32 = 0x1_0000;
const RO_WRITABLE: u32 =
    RO_SPARSE_SUPER | RO_LARGE_FILE | 0x4 | RO_HUGE_FILE | RO_GDT_CSUM | RO_DIR_NLINK | RO_EXTRA_ISIZE | RO_METADATA_CSUM;

/// Reasons a known feature forces read-only, with the wording shown to the user.
const RO_INCOMPAT: &[(u32, &str)] = &[
    (IN_INLINE_DATA, "inline_data: small files live inside inodes; writing them isn't supported yet"),
    (IN_EA_INODE, "ea_inode: large extended attributes aren't writable yet"),
    (IN_ENCRYPT, "encrypt: fscrypt keys aren't available on Windows"),
    (IN_CASEFOLD, "casefold: case-insensitive directories aren't writable yet"),
    (IN_MMP, "mmp: multi-mount protection could not be honoured while writing"),
];
const RO_ROCOMPAT: &[(u32, &str)] = &[
    (RO_QUOTA, "quota: writing would leave quota accounting stale"),
    (RO_PROJECT, "project: project quotas would go stale"),
    (RO_BIGALLOC, "bigalloc: cluster allocation isn't writable yet"),
    (RO_VERITY, "verity: protected files must stay untouched"),
    (RO_ORPHAN_PRESENT, "orphan_file has pending entries: mount once in Linux to clear them"),
    (RO_SHARED_BLOCKS, "shared_blocks: the volume has deduplicated blocks"),
    (RO_READONLY, "the volume is flagged read-only"),
];

fn feature_names(compat: u32, incompat: u32, ro: u32) -> Vec<String> {
    let table: &[(u32, u32, &str)] = &[
        (0, COMPAT_HAS_JOURNAL, "has_journal"),
        (0, 0x8, "ext_attr"),
        (0, 0x10, "resize_inode"),
        (0, COMPAT_DIR_INDEX, "dir_index"),
        (0, COMPAT_FAST_COMMIT, "fast_commit"),
        (0, 0x1000, "orphan_file"),
        (1, IN_FILETYPE, "filetype"),
        (1, IN_RECOVER, "needs_recovery"),
        (1, IN_META_BG, "meta_bg"),
        (1, IN_EXTENTS, "extent"),
        (1, IN_64BIT, "64bit"),
        (1, IN_MMP, "mmp"),
        (1, IN_FLEX_BG, "flex_bg"),
        (1, IN_EA_INODE, "ea_inode"),
        (1, IN_CSUM_SEED, "metadata_csum_seed"),
        (1, IN_LARGEDIR, "large_dir"),
        (1, IN_INLINE_DATA, "inline_data"),
        (1, IN_ENCRYPT, "encrypt"),
        (1, IN_CASEFOLD, "casefold"),
        (2, RO_SPARSE_SUPER, "sparse_super"),
        (2, RO_LARGE_FILE, "large_file"),
        (2, RO_HUGE_FILE, "huge_file"),
        (2, RO_GDT_CSUM, "uninit_bg"),
        (2, RO_DIR_NLINK, "dir_nlink"),
        (2, RO_EXTRA_ISIZE, "extra_isize"),
        (2, RO_QUOTA, "quota"),
        (2, RO_BIGALLOC, "bigalloc"),
        (2, RO_METADATA_CSUM, "metadata_csum"),
        (2, RO_PROJECT, "project"),
        (2, RO_VERITY, "verity"),
    ];
    let word = [compat, incompat, ro];
    table.iter().filter(|(w, bit, _)| word[*w as usize] & bit != 0).map(|t| t.2.to_string()).collect()
}

fn parse_geo(sb: &[u8], dev_len: u64) -> Result<Geo> {
    if sb.u16_at(0x38) != MAGIC {
        return corrupt("no ext2/3/4 signature");
    }
    let log = sb.u32_at(0x18);
    if log > 6 {
        return corrupt("block size out of range");
    }
    let bs = 1024usize << log;
    let (compat, incompat, ro) = (sb.u32_at(0x5C), sb.u32_at(0x60), sb.u32_at(0x64));
    let is_64bit = incompat & IN_64BIT != 0;
    let blocks = sb.u32_at(4) as u64 | if is_64bit { (sb.u32_at(0x150) as u64) << 32 } else { 0 };
    let first_data = sb.u32_at(0x14) as u64;
    let (bpg, ipg, inodes) = (sb.u32_at(0x20), sb.u32_at(0x28), sb.u32_at(0));
    let bigalloc = ro & RO_BIGALLOC != 0;
    let cpg = if bigalloc { sb.u32_at(0x24) } else { bpg };
    if bpg == 0 || ipg == 0 || blocks <= first_data || first_data != (bs == 1024) as u64 {
        return corrupt("bad block group geometry");
    }
    if cpg as usize > bs * 8 || ipg as usize > bs * 8 || (!bigalloc && bpg as usize > bs * 8) {
        return corrupt("block group larger than its bitmap");
    }
    let rev = sb.u32_at(0x4C);
    let (isize, first_ino) =
        if rev == 0 { (128, 11) } else { (sb.u16_at(0x58) as usize, sb.u32_at(0x54)) };
    if isize < 128 || isize > bs || !isize.is_power_of_two() || first_ino < 3 || first_ino > inodes {
        return corrupt("bad inode geometry");
    }
    let desc_size = if is_64bit { (sb.u16_at(0xFE) as usize).max(64) } else { 32 };
    if desc_size > bs.min(1024) || !desc_size.is_power_of_two() {
        return corrupt("bad group descriptor size");
    }
    let groups = (blocks - first_data).div_ceil(bpg as u64);
    if groups > u32::MAX as u64 / 2 || groups.saturating_mul(ipg as u64) < inodes as u64 {
        return corrupt("group count disagrees with inode count");
    }
    let gd_bytes = groups * desc_size as u64;
    if gd_bytes > dev_len {
        return corrupt("group descriptors exceed the device");
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb[0x68..0x78]);
    let metadata_csum = ro & RO_METADATA_CSUM != 0;
    let csum_seed = if incompat & IN_CSUM_SEED != 0 { sb.u32_at(0x270) } else { crc32c_raw(!0, &uuid) };
    let mut hash_seed = [0u32; 4];
    for (i, s) in hash_seed.iter_mut().enumerate() {
        *s = sb.u32_at(0xEC + i * 4);
    }
    Ok(Geo {
        bs,
        blocks,
        first_data,
        bpg,
        ipg,
        cpg,
        inodes,
        isize,
        desc_size,
        groups: groups as u32,
        first_ino,
        csum_seed,
        metadata_csum,
        gdt_csum: ro & RO_GDT_CSUM != 0,
        is_64bit,
        extents: incompat & IN_EXTENTS != 0,
        filetype: incompat & IN_FILETYPE != 0,
        dir_index: compat & COMPAT_DIR_INDEX != 0,
        large_dir: incompat & IN_LARGEDIR != 0,
        sparse_super: ro & RO_SPARSE_SUPER != 0,
        meta_bg: incompat & IN_META_BG != 0,
        first_meta_bg: sb.u32_at(0x104),
        reserved_gdt: sb.u16_at(0xCE) as u32,
        huge_file: ro & RO_HUGE_FILE != 0,
        hash_seed,
        def_hash: sb.u8_at(0xFC),
        hash_unsigned: sb.u32_at(0x160) & 2 != 0,
        want_extra: sb.u16_at(0x15E).max(32),
        uuid,
    })
}

/// Superblock checksum: everything before the checksum field, seeded with ~0.
fn sb_csum(sb: &[u8]) -> u32 {
    crc32c_raw(!0, &sb[..0x3FC])
}

pub struct Ext4 {
    pub(crate) fs: Shared,
}

impl Ext4 {
    /// Mounts `dev`. With `opts.write` the volume is writable only if nothing argues
    /// against it; the reasons are reported by [`fscore::Filesystem::info`]. Read-only
    /// mounts never write, even to recover a dirty journal.
    pub fn open(dev: Arc<dyn BlockDev>, opts: MountOpts) -> Result<Ext4> {
        let mut sb = vec![0u8; 1024];
        dev.read_at(SB_OFFSET, &mut sb)?;
        let g = parse_geo(&sb, dev.len())?;
        let (compat, incompat, ro) = (sb.u32_at(0x5C), sb.u32_at(0x60), sb.u32_at(0x64));
        if incompat & IN_JOURNAL_DEV != 0 {
            return Err(FsError::Unsupported("this is an external journal, not a filesystem".into()));
        }
        if incompat & (IN_COMPRESSION | IN_DIRDATA) != 0 || incompat & !IN_KNOWN != 0 {
            let unknown = incompat & !IN_KNOWN;
            return Err(FsError::Unsupported(format!("incompatible features {unknown:#x}")));
        }
        let mut reasons: Vec<String> = vec![];
        let mut notes: Vec<String> = vec![];
        for (bit, why) in RO_INCOMPAT {
            if incompat & bit != 0 {
                reasons.push((*why).to_string());
            }
        }
        for (bit, why) in RO_ROCOMPAT {
            if ro & bit != 0 {
                reasons.push((*why).to_string());
            }
        }
        if ro & !(RO_WRITABLE | RO_ROCOMPAT.iter().fold(0, |a, r| a | r.0)) != 0 {
            reasons.push(format!("unknown read-only features {:#x}", ro & !RO_WRITABLE));
        }
        if compat & COMPAT_SPARSE_SUPER2 != 0 {
            reasons.push("sparse_super2 isn't writable yet".into());
        }
        if !g.extents && g.is_64bit {
            reasons.push("64bit without extents is not a supported layout".into());
        }
        if g.metadata_csum && sb.u32_at(0x3FC) != sb_csum(&sb) {
            reasons.push("superblock failed its checksum: run e2fsck in Linux".into());
        }
        let state = sb.u16_at(0x3A);
        if state & 2 != 0 {
            reasons.push("the filesystem has recorded errors: run e2fsck in Linux first".into());
        }
        if dev.len() < g.blocks * g.bs as u64 {
            reasons.push("the device is smaller than the filesystem: it may be truncated".into());
        }
        let has_journal = compat & COMPAT_HAS_JOURNAL != 0;
        if !has_journal && state & 1 == 0 {
            reasons.push("not cleanly unmounted and has no journal: run e2fsck in Linux first".into());
        }
        if has_journal && sb.u32_at(0xE0) == 0 {
            reasons.push("external journals aren't supported for writing".into());
        }
        if !dev.writable() {
            reasons.push("the device was opened read-only".into());
        }

        let groups = g.groups;
        let desc_size = g.desc_size;
        let cache_bytes = if opts.cache_bytes == 0 { 32 << 20 } else { opts.cache_bytes };
        let cache = BlockCache::new(cache_bytes, g.bs);
        let mut fs = Fs {
            cache,
            sb,
            gds: vec![0; groups as usize * desc_size],
            dirty: HashMap::new(),
            overlay: HashMap::new(),
            pending_free: vec![],
            touched: BTreeSet::new(),
            journal: None,
            read_only: true,
            ro_reasons: vec![],
            notes: vec![],
            features: feature_names(compat, incompat, ro),
            undo: None,
            g,
            dev,
        };
        fs.load_group_descriptors()?;

        let want_write = opts.write && reasons.is_empty();
        let mut journal: Option<Journal> = None;
        if has_journal && fs.sb.u32_at(0xE0) != 0 {
            let mut j = fs.open_journal(fs.sb.u32_at(0xE0))?;
            if j.has_fast_commit() {
                reasons.push("fast_commit journals aren't writable yet".into());
            }
            if incompat & IN_RECOVER != 0 && !j.is_clean() {
                let replay = fs.scan_journal(&j)?;
                let want_write = want_write && reasons.is_empty();
                if want_write {
                    notes.push(format!("journal recovered: {} blocks replayed", replay.len()));
                    fs.replay_to_disk(&mut j, &replay)?;
                    fs.cache.clear();
                } else {
                    notes.push(format!(
                        "volume was not cleanly unmounted: {} journal blocks applied in memory only, nothing was written",
                        replay.len()
                    ));
                    fs.overlay = replay;
                }
                fs.reload_superblock()?;
            }
            journal = Some(j);
        }
        let want_write = want_write && reasons.is_empty();
        fs.journal = journal;
        if opts.write {
            fs.ro_reasons = reasons;
        }
        fs.notes = notes;
        if want_write {
            fs.read_only = false;
            fs.mark_mounted()?;
            fs.process_orphans()?;
        }
        Ok(Ext4 { fs: RwLock::new(fs) })
    }
}

/// Reads a volume's description without keeping it mounted.
pub fn inspect(dev: Arc<dyn BlockDev>) -> Result<VolumeInfo> {
    use fscore::Filesystem;
    let probe = Ext4::open(dev, MountOpts { write: false, cache_bytes: 1 << 20 })?;
    Ok(probe.info())
}

impl Fs {
    fn load_group_descriptors(&mut self) -> Result<()> {
        let per = self.g.gd_per_block() as usize;
        let ds = self.g.desc_size;
        for i in 0..self.g.gd_blocks() {
            let b = self.block(self.gd_block(i))?;
            let n = (self.g.groups as usize - i as usize * per).min(per) * ds;
            let o = i as usize * per * ds;
            self.gds[o..o + n].copy_from_slice(&b[..n]);
        }
        let bs = self.g.bs as u64;
        for g in 0..self.g.groups {
            if (self.g.metadata_csum || self.g.gdt_csum) && self.gd(g).u16_at(0x1E) != self.gd_csum(g) {
                self.notes.push(format!("group descriptor {g} failed its checksum"));
                return corrupt(format!("group descriptor {g} failed its checksum"));
            }
            let (b, i, t) = (self.block_bitmap_loc(g), self.inode_bitmap_loc(g), self.inode_table(g));
            let table = (self.g.ipg as u64 * self.g.isize as u64).div_ceil(bs);
            if b >= self.g.blocks || i >= self.g.blocks || t.saturating_add(table) > self.g.blocks {
                return corrupt(format!("group {g} metadata lies outside the volume"));
            }
        }
        Ok(())
    }

    /// Re-reads superblock and descriptors after journal recovery changed them.
    fn reload_superblock(&mut self) -> Result<()> {
        let sb_blk = if self.g.bs == 1024 { 1 } else { 0 };
        let off = if self.g.bs == 1024 { 0 } else { 1024 };
        let b = self.block(sb_blk)?;
        self.sb.copy_from_slice(&b[off..off + 1024]);
        self.load_group_descriptors()
    }

    fn sb_location(&self) -> (u64, usize) {
        if self.g.bs == 1024 {
            (1, 0)
        } else {
            (0, 1024)
        }
    }

    fn stamp_superblock(&mut self) {
        if self.g.metadata_csum {
            let c = sb_csum(&self.sb);
            self.sb.put_u32(0x3FC, c);
        }
    }

    /// Writes the superblock directly, outside any transaction.
    fn write_sb_direct(&mut self) -> Result<()> {
        self.stamp_superblock();
        self.dev.write_at(SB_OFFSET, &self.sb)?;
        self.dev.flush()?;
        let (blk, _) = self.sb_location();
        self.cache.remove(blk);
        Ok(())
    }

    /// Flags the volume as in use, so a crash is noticed by the next mount or fsck.
    fn mark_mounted(&mut self) -> Result<()> {
        let now = Time::now();
        self.sb.put_u32(0x2C, now.sec as u32);
        self.sb.put_u8(0x275, (now.sec >> 32) as u8);
        let mounts = self.sb.u16_at(0x34).wrapping_add(1);
        self.sb.put_u16(0x34, mounts);
        let state = self.sb.u16_at(0x3A) & !1;
        self.sb.put_u16(0x3A, state);
        if self.journal.is_some() {
            let v = self.sb.u32_at(0x60) | IN_RECOVER;
            self.sb.put_u32(0x60, v);
        }
        self.write_sb_direct()
    }

    /// Finishes deletions that a crash interrupted.
    fn process_orphans(&mut self) -> Result<()> {
        let mut ino = self.sb.u32_at(0xE8);
        let mut steps = 0;
        while ino != 0 {
            steps += 1;
            if steps > self.g.inodes {
                return corrupt("orphan list has a cycle");
            }
            let mut raw = self.inode(ino)?;
            let next = raw.u32_at(0x14);
            raw.put_u32(0x14, 0);
            if raw.links() == 0 {
                self.notes.push(format!("finished deleting orphaned inode {ino}"));
                self.drop_inode(ino, &mut raw)?;
            } else if raw.flags() & F_INLINE == 0 {
                let size = raw.size();
                self.truncate_to(ino, &mut raw, size)?;
                self.put_inode(ino, &mut raw)?;
            }
            ino = next;
        }
        if self.sb.u32_at(0xE8) != 0 {
            self.sb.put_u32(0xE8, 0);
            self.commit()?;
        }
        Ok(())
    }

    /// Commits the running transaction.
    pub fn commit(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        let r = self.commit_inner();
        if let Err(e) = &r {
            // The disk is in an unknown state: refuse further writes rather than guess.
            self.read_only = true;
            self.ro_reasons.push(format!("a write failed and the volume was switched to read-only: {e}"));
        }
        r
    }

    fn commit_inner(&mut self) -> Result<()> {
        let budget = self.commit_budget();
        loop {
            if self.dirty.is_empty() && self.pending_free.is_empty() && self.touched.is_empty() {
                return Ok(());
            }
            self.apply_pending_frees(budget)?;
            self.flush_group_descriptors()?;
            let now = Time::now();
            self.sb.put_u32(0x30, now.sec as u32);
            self.sb.put_u8(0x274, (now.sec >> 32) as u8);
            self.stamp_superblock();
            let (blk, off) = self.sb_location();
            let sb = self.sb.clone();
            self.modify(blk)?[off..off + 1024].copy_from_slice(&sb);

            let mut blocks: Vec<(u64, Arc<[u8]>)> = self.dirty.drain().collect();
            blocks.sort_by_key(|b| b.0);
            // File data must be durable before metadata that points at it.
            self.dev.flush()?;
            if self.journal.is_some() {
                self.journal_commit(&blocks)?;
            } else {
                for (n, data) in &blocks {
                    self.dev.write_at(n * self.g.bs as u64, data)?;
                }
                self.dev.flush()?;
            }
            for (n, b) in blocks {
                self.cache.insert(n, b);
            }
        }
    }

    fn commit_budget(&self) -> usize {
        self.journal.as_ref().map_or(usize::MAX, |j| j.capacity() * 3 / 4)
    }

    /// Commits early when the transaction is approaching what the journal can hold.
    pub fn make_room(&mut self) -> Result<()> {
        if self.dirty.len() > self.commit_budget() / 2 {
            self.commit()?;
        }
        Ok(())
    }

    /// Clean shutdown: commit, then record that nothing needs recovery.
    pub fn clean_unmount(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.commit()?;
        let v = self.sb.u32_at(0x60) & !IN_RECOVER;
        self.sb.put_u32(0x60, v);
        let state = self.sb.u16_at(0x3A) | 1;
        self.sb.put_u16(0x3A, state);
        self.write_sb_direct()?;
        self.read_only = true;
        Ok(())
    }

    pub fn volume_info(&self) -> VolumeInfo {
        let label = self.sb[0x78..0x88].split(|b| *b == 0).next().unwrap_or(&[]);
        let overhead = self.g.groups as u64
            * ((self.g.ipg as u64 * self.g.isize as u64).div_ceil(self.g.bs as u64) + 2);
        VolumeInfo {
            fs_type: fscore::part::probe(self.dev.as_ref()).name(),
            label: String::from_utf8_lossy(label).into_owned(),
            uuid: fmt_uuid(&self.g.uuid),
            block_size: self.g.bs as u32,
            total_bytes: (self.g.blocks.saturating_sub(overhead)) * self.g.bs as u64,
            free_bytes: self.free_bytes(),
            read_only: self.read_only,
            ro_reasons: self.ro_reasons.clone(),
            notes: self.notes.clone(),
            features: self.features.clone(),
        }
    }
}
