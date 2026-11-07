//! Directories: linear blocks, the hashed htree index, and inline directories.
use crate::hash::dx_hash;
use crate::inode::{Inode, F_CASEFOLD, F_INDEX, F_INLINE, I_BLOCK};
use crate::{corrupt, Fs, Result};
use fscore::{crc32c_raw, FileKind, FsError, Le, LeMut};

const TAIL: usize = 12;

pub fn ftype(k: FileKind) -> u8 {
    match k {
        FileKind::File => 1,
        FileKind::Dir => 2,
        FileKind::CharDev => 3,
        FileKind::BlockDev => 4,
        FileKind::Fifo => 5,
        FileKind::Socket => 6,
        FileKind::Symlink => 7,
        FileKind::Unknown => 0,
    }
}

pub fn kind_of(t: u8) -> FileKind {
    match t {
        1 => FileKind::File,
        2 => FileKind::Dir,
        3 => FileKind::CharDev,
        4 => FileKind::BlockDev,
        5 => FileKind::Fifo,
        6 => FileKind::Socket,
        7 => FileKind::Symlink,
        _ => FileKind::Unknown,
    }
}

/// A decoded entry.
#[derive(Clone, Debug)]
pub struct Ent {
    pub off: usize,
    pub rec: usize,
    pub ino: u32,
    pub ftype: u8,
    pub name: Vec<u8>,
}

fn entry_size(name_len: usize) -> usize {
    (8 + name_len + 3) & !3
}

fn rec_len(b: &[u8], o: usize) -> usize {
    match b.u16_at(o + 4) as usize {
        0 | 65535 => b.len().min(65536),
        // On 64K-block volumes the low two bits carry the top of the length.
        r if b.len() >= 65536 => (r & 65532) | (r & 3) << 16,
        r => r,
    }
}

fn put_rec_len(b: &mut [u8], o: usize, r: usize) {
    let v = if r >= 65536 { if r == 65536 { 65535 } else { (r & 65532) | (r >> 16) } } else { r };
    b.put_u16(o + 4, v as u16);
}

impl Fs {
    fn name_len(&self, b: &[u8], o: usize) -> usize {
        if self.g.filetype {
            b.u8_at(o + 6) as usize
        } else {
            b.u16_at(o + 6) as usize & 0xFF
        }
    }

    /// Walks the entries of one leaf region, rejecting malformed records.
    pub fn parse_entries(&self, b: &[u8], start: usize, end: usize, f: &mut dyn FnMut(Ent) -> bool) -> Result<()> {
        let mut o = start;
        while o + 8 <= end {
            let rec = rec_len(b, o);
            let n = self.name_len(b, o);
            if rec < 8 || rec % 4 != 0 || o + rec > end || 8 + n > rec {
                return corrupt("malformed directory entry");
            }
            let ino = b.u32_at(o);
            if ino != 0 {
                let t = if self.g.filetype { b.u8_at(o + 7) } else { 0 };
                let e = Ent { off: o, rec, ino, ftype: t, name: b[o + 8..o + 8 + n].to_vec() };
                if !f(e) {
                    return Ok(());
                }
            }
            o += rec;
        }
        Ok(())
    }

    /// Bytes of a block available to entries.
    fn usable(&self) -> usize {
        self.g.bs - if self.g.metadata_csum { TAIL } else { 0 }
    }

    /// End of entries in a block, which excludes a checksum tail if one is present.
    fn leaf_end(&self, b: &[u8]) -> usize {
        let t = b.len() - TAIL;
        if b.u32_at(t) == 0 && b.u16_at(t + 4) == 12 && b.u8_at(t + 7) == 0xDE {
            t
        } else {
            b.len()
        }
    }

    fn seal_leaf(&mut self, dir: u32, gen: u32, blk: u64) -> Result<()> {
        if !self.g.metadata_csum {
            return Ok(());
        }
        let seed = self.inode_seed(dir, gen);
        let b = self.block(blk)?;
        let t = b.len() - TAIL;
        if self.leaf_end(&b) != t {
            return Ok(());
        }
        let c = crc32c_raw(seed, &b[..t]);
        self.modify(blk)?.put_u32(t + 8, c);
        Ok(())
    }

    fn init_tail(&self, b: &mut [u8]) {
        if self.g.metadata_csum {
            let t = b.len() - TAIL;
            b[t..].fill(0);
            b.put_u16(t + 4, 12);
            b.put_u8(t + 7, 0xDE);
        }
    }

    fn dir_phys(&self, dir: u32, raw: &[u8], lblk: u64) -> Result<u64> {
        match self.map(dir, raw, lblk)?.phys {
            Some(p) => Ok(p),
            None => corrupt(format!("hole in directory {dir}")),
        }
    }

    fn dir_blocks(&self, raw: &[u8]) -> u64 {
        raw.size().div_ceil(self.g.bs as u64)
    }

    fn is_inline(&self, raw: &[u8]) -> bool {
        raw.flags() & F_INLINE != 0
    }

    /// Inline directories keep their parent in the first four bytes of `i_block`,
    /// entries in the rest, and any overflow in the `system.data` xattr.
    fn inline_entries(&self, raw: &[u8], f: &mut dyn FnMut(Ent) -> bool) -> Result<()> {
        let mut stop = false;
        self.parse_entries(&raw[I_BLOCK + 4..I_BLOCK + 60], 0, 56, &mut |e| {
            stop = !f(e);
            !stop
        })?;
        if !stop {
            if let Some(v) = self.inline_xattr_data(raw)? {
                self.parse_entries(&v, 0, v.len(), f)?;
            }
        }
        Ok(())
    }

    /// Finds an entry by exact name (or case-folded in a casefold directory).
    pub fn dir_lookup(&self, dir: u32, raw: &[u8], name: &[u8]) -> Result<Option<Ent>> {
        if !raw.is_dir() {
            return Err(FsError::NotDir);
        }
        let fold = raw.flags() & F_CASEFOLD != 0;
        let found = std::cell::RefCell::new(None);
        let mut test = |e: Ent| {
            if e.name == name || (fold && same_folded(&e.name, name)) {
                *found.borrow_mut() = Some(e);
                return false;
            }
            true
        };
        if self.is_inline(raw) {
            self.inline_entries(raw, &mut test)?;
            return Ok(found.into_inner());
        }
        if raw.flags() & F_INDEX != 0 && self.g.dir_index && !fold {
            let hash = self.name_hash(dir, raw, name)?;
            if let Ok(path) = self.dx_descend(dir, raw, hash) {
                let p = self.dir_phys(dir, raw, path.leaf as u64)?;
                let b = self.block(p)?;
                let end = self.leaf_end(&b);
                self.parse_entries(&b, 0, end, &mut test)?;
                if found.borrow().is_some() {
                    return Ok(found.into_inner());
                }
                // A hash collision can continue into the next leaf, so only an
                // unambiguous miss is trusted.
                if !path.may_continue {
                    return Ok(None);
                }
            }
        }
        self.dir_scan(dir, raw, &mut test)?;
        Ok(found.into_inner())
    }

    fn dir_scan(&self, dir: u32, raw: &[u8], f: &mut dyn FnMut(Ent) -> bool) -> Result<()> {
        for lblk in 0..self.dir_blocks(raw) {
            let p = self.dir_phys(dir, raw, lblk)?;
            let b = self.block(p)?;
            let end = self.leaf_end(&b);
            let mut stop = false;
            self.parse_entries(&b, 0, end, &mut |e| {
                stop = !f(e);
                !stop
            })?;
            if stop {
                break;
            }
        }
        Ok(())
    }

    /// Lists entries from byte position `cookie`; `.` and `..` are skipped.
    pub fn dir_list(
        &self,
        dir: u32,
        raw: &[u8],
        cookie: u64,
        f: &mut dyn FnMut(u64, Ent) -> bool,
    ) -> Result<()> {
        let keep = |e: &Ent| e.name != b"." && e.name != b"..";
        if self.is_inline(raw) {
            let mut i = 0;
            return self.inline_entries(raw, &mut |e| {
                i += 1;
                if i <= cookie {
                    return true;
                }
                !keep(&e) || f(i, e)
            });
        }
        let bs = self.g.bs as u64;
        for lblk in cookie / bs..self.dir_blocks(raw) {
            let Some(p) = self.map(dir, raw, lblk)?.phys else { continue };
            let b = self.block(p)?;
            let end = self.leaf_end(&b);
            let base = lblk * bs;
            let mut stop = false;
            self.parse_entries(&b, 0, end, &mut |e| {
                let next = base + (e.off + e.rec) as u64;
                if next <= cookie || !keep(&e) {
                    return true;
                }
                stop = !f(next, e);
                !stop
            })?;
            if stop {
                break;
            }
        }
        Ok(())
    }

    pub fn dir_is_empty(&self, dir: u32, raw: &[u8]) -> Result<bool> {
        let mut empty = true;
        self.dir_list(dir, raw, 0, &mut |_, _| {
            empty = false;
            false
        })?;
        Ok(empty)
    }

    fn hash_version(&self, dir: u32, raw: &[u8]) -> Result<u8> {
        let b = self.block(self.dir_phys(dir, raw, 0)?)?;
        Ok(self.effective_hash(b.u8_at(28)))
    }

    fn effective_hash(&self, v: u8) -> u8 {
        if v <= 2 && self.g.hash_unsigned {
            v + 3
        } else {
            v
        }
    }

    fn name_hash(&self, dir: u32, raw: &[u8], name: &[u8]) -> Result<u32> {
        Ok(dx_hash(name, self.hash_version(dir, raw)?, &self.g.hash_seed))
    }

    fn dx_limit(&self, root: bool) -> usize {
        let base = if root { 32 } else { 8 };
        (self.g.bs - base) / 8 - self.g.metadata_csum as usize
    }

    /// Walks from the root to the leaf covering `hash`.
    fn dx_descend(&self, dir: u32, raw: &[u8], hash: u32) -> Result<DxPath> {
        let root = self.block(self.dir_phys(dir, raw, 0)?)?;
        let levels = root.u8_at(30) as usize;
        let info = root.u8_at(29) as usize;
        if levels > 2 || info != 8 || root.u32_at(24) != 0 {
            return corrupt("bad htree root");
        }
        let mut nodes = vec![];
        let (mut lblk, mut base, mut cur) = (0u32, 32usize, root);
        let mut may_continue = false;
        for level in 0..=levels {
            let count = cur.u16_at(base + 2) as usize;
            let limit = cur.u16_at(base) as usize;
            if count == 0 || count > limit || base + count * 8 > cur.len() {
                return corrupt("bad htree node");
            }
            let mut i = 0;
            while i + 1 < count && cur.u32_at(base + (i + 1) * 8) <= hash {
                i += 1;
            }
            if i + 1 < count {
                may_continue |= cur.u32_at(base + (i + 1) * 8) & !1 == hash & !1;
            } else {
                may_continue |= level < levels;
            }
            nodes.push(DxNode { lblk, base, idx: i });
            let child = cur.u32_at(base + i * 8 + 4);
            if level == levels {
                return Ok(DxPath { nodes, leaf: child, may_continue });
            }
            lblk = child;
            cur = self.block(self.dir_phys(dir, raw, lblk as u64)?)?;
            base = 8;
        }
        corrupt("bad htree walk")
    }

    fn seal_dx(&mut self, dir: u32, gen: u32, blk: u64, base: usize) -> Result<()> {
        if !self.g.metadata_csum {
            return Ok(());
        }
        let b = self.block(blk)?;
        let (limit, count) = (b.u16_at(base) as usize, b.u16_at(base + 2) as usize);
        let t = base + limit * 8;
        if t + 8 > b.len() {
            return Ok(());
        }
        let c = crc32c_raw(self.inode_seed(dir, gen), &b[..base + count * 8]);
        let c = crc32c_raw(c, &b[t..t + 4]);
        let c = crc32c_raw(c, &[0; 4]);
        self.modify(blk)?.put_u32(t + 4, c);
        Ok(())
    }

    /// Adds an entry, growing or indexing the directory as needed.
    pub fn dir_add(&mut self, dir: u32, raw: &mut Vec<u8>, name: &[u8], ino: u32, ft: u8) -> Result<()> {
        if self.is_inline(raw) {
            return Err(FsError::ReadOnly);
        }
        if raw.flags() & F_INDEX != 0 && self.g.dir_index {
            return self.dx_add(dir, raw, name, ino, ft);
        }
        let gen = raw.generation();
        let blocks = self.dir_blocks(raw);
        for lblk in 0..blocks {
            let p = self.dir_phys(dir, raw, lblk)?;
            let b = self.block(p)?;
            let end = self.leaf_end(&b);
            let mut v = b.to_vec();
            if self.insert_in_leaf(&mut v, end, name, ino, ft)? {
                self.modify(p)?.copy_from_slice(&v);
                return self.seal_leaf(dir, gen, p);
            }
        }
        if self.g.dir_index && blocks == 1 {
            self.make_indexed(dir, raw)?;
            return self.dx_add(dir, raw, name, ino, ft);
        }
        let (_, p) = self.dir_grow(dir, raw)?;
        let mut v = self.block(p)?.to_vec();
        let end = self.leaf_end(&v);
        if !self.insert_in_leaf(&mut v, end, name, ino, ft)? {
            return corrupt("new directory block has no room");
        }
        self.modify(p)?.copy_from_slice(&v);
        self.seal_leaf(dir, gen, p)
    }

    /// Adds a block to a directory, formatted as one empty record.
    fn dir_grow(&mut self, dir: u32, raw: &mut Vec<u8>) -> Result<(u32, u64)> {
        let lblk = self.dir_blocks(raw);
        let p = self.alloc_file_block(dir, raw, lblk)?;
        let mut b = vec![0u8; self.g.bs];
        put_rec_len(&mut b, 0, self.usable());
        self.init_tail(&mut b);
        self.fresh(p)?.copy_from_slice(&b);
        crate::inode::set_size(raw, (lblk + 1) * self.g.bs as u64);
        self.seal_leaf(dir, raw.generation(), p)?;
        Ok((lblk as u32, p))
    }

    fn insert_in_leaf(&self, b: &mut [u8], end: usize, name: &[u8], ino: u32, ft: u8) -> Result<bool> {
        let need = entry_size(name.len());
        let mut o = 0;
        while o + 8 <= end {
            let rec = rec_len(b, o);
            if rec < 8 || o + rec > end {
                return corrupt("malformed directory entry");
            }
            let used = if b.u32_at(o) == 0 { 0 } else { entry_size(self.name_len(b, o)) };
            if rec >= used + need {
                let at = o + used;
                if used > 0 {
                    put_rec_len(b, o, used);
                }
                self.write_entry(b, at, rec - used, name, ino, ft);
                return Ok(true);
            }
            o += rec;
        }
        Ok(false)
    }

    fn write_entry(&self, b: &mut [u8], o: usize, rec: usize, name: &[u8], ino: u32, ft: u8) {
        b.put_u32(o, ino);
        put_rec_len(b, o, rec);
        b.put_u8(o + 6, name.len() as u8);
        b.put_u8(o + 7, if self.g.filetype { ft } else { 0 });
        b[o + 8..o + 8 + name.len()].copy_from_slice(name);
    }

    /// Writes `ents` into a fresh leaf image; the last record absorbs the remaining space.
    fn pack_leaf(&self, ents: &[Ent]) -> Vec<u8> {
        let mut b = vec![0u8; self.g.bs];
        let end = self.usable();
        let mut o = 0;
        for (i, e) in ents.iter().enumerate() {
            let size = entry_size(e.name.len());
            let rec = if i + 1 == ents.len() { end - o } else { size };
            self.write_entry(&mut b, o, rec, &e.name, e.ino, e.ftype);
            o += size;
        }
        if ents.is_empty() {
            put_rec_len(&mut b, 0, end);
        }
        self.init_tail(&mut b);
        b
    }

    /// Converts a full single-block directory into an htree.
    fn make_indexed(&mut self, dir: u32, raw: &mut Vec<u8>) -> Result<()> {
        let gen = raw.generation();
        let p0 = self.dir_phys(dir, raw, 0)?;
        let b = self.block(p0)?;
        let end = self.leaf_end(&b);
        let mut ents = vec![];
        self.parse_entries(&b, 0, end, &mut |e| {
            ents.push(e);
            true
        })?;
        let parent = ents.iter().find(|e| e.name == b"..").map_or(dir, |e| e.ino);
        ents.retain(|e| e.name != b"." && e.name != b"..");

        let (lblk, p1) = self.dir_grow(dir, raw)?;
        let leaf = self.pack_leaf(&ents);
        self.modify(p1)?.copy_from_slice(&leaf);
        self.seal_leaf(dir, gen, p1)?;

        let bs = self.g.bs;
        let mut r = vec![0u8; bs];
        self.write_entry(&mut r, 0, 12, b".", dir, 2);
        self.write_entry(&mut r, 12, bs - 12, b"..", parent, 2);
        r.put_u8(28, self.g.def_hash);
        r.put_u8(29, 8);
        r.put_u16(32, self.dx_limit(true) as u16);
        r.put_u16(34, 1);
        r.put_u32(36, lblk);
        self.modify(p0)?.copy_from_slice(&r);
        self.seal_dx(dir, gen, p0, 32)?;
        let flags = raw.flags() | F_INDEX;
        raw.put_u32(0x20, flags);
        Ok(())
    }

    fn dx_add(&mut self, dir: u32, raw: &mut Vec<u8>, name: &[u8], ino: u32, ft: u8) -> Result<()> {
        let gen = raw.generation();
        let hash = self.name_hash(dir, raw, name)?;
        // A name longer than half a leaf may need more than one split.
        for _ in 0..4 {
            let path = self.dx_descend(dir, raw, hash)?;
            let p = self.dir_phys(dir, raw, path.leaf as u64)?;
            let b = self.block(p)?;
            let end = self.leaf_end(&b);
            let mut v = b.to_vec();
            if self.insert_in_leaf(&mut v, end, name, ino, ft)? {
                self.modify(p)?.copy_from_slice(&v);
                return self.seal_leaf(dir, gen, p);
            }
            let (hash2, lblk) = self.split_leaf(dir, raw, p, end)?;
            self.dx_insert(dir, raw, path.nodes, hash2, lblk)?;
        }
        corrupt("directory leaf could not be split")
    }

    fn split_leaf(&mut self, dir: u32, raw: &mut Vec<u8>, p: u64, end: usize) -> Result<(u32, u32)> {
        let gen = raw.generation();
        let version = self.hash_version(dir, raw)?;
        let b = self.block(p)?;
        let mut ents = vec![];
        self.parse_entries(&b, 0, end, &mut |e| {
            ents.push((dx_hash(&e.name, version, &self.g.hash_seed), e));
            true
        })?;
        if ents.len() < 2 {
            return corrupt("cannot split a directory leaf with one entry");
        }
        ents.sort_by_key(|e| e.0);
        let total: usize = ents.iter().map(|e| entry_size(e.1.name.len())).sum();
        let (mut acc, mut split) = (0, 0);
        for (i, e) in ents.iter().enumerate() {
            acc += entry_size(e.1.name.len());
            if acc * 2 >= total {
                split = i + 1;
                break;
            }
        }
        let split = split.clamp(1, ents.len() - 1);
        let continued = ents[split].0 == ents[split - 1].0;
        let hash2 = ents[split].0 + continued as u32;
        let (lo, hi): (Vec<Ent>, Vec<Ent>) = (
            ents[..split].iter().map(|e| e.1.clone()).collect(),
            ents[split..].iter().map(|e| e.1.clone()).collect(),
        );
        let (lblk, np) = self.dir_grow(dir, raw)?;
        let (a, c) = (self.pack_leaf(&lo), self.pack_leaf(&hi));
        self.modify(p)?.copy_from_slice(&a);
        self.modify(np)?.copy_from_slice(&c);
        self.seal_leaf(dir, gen, p)?;
        self.seal_leaf(dir, gen, np)?;
        Ok((hash2, lblk))
    }

    /// Inserts `(hash, lblk)` after the path's last position, splitting index nodes.
    fn dx_insert(&mut self, dir: u32, raw: &mut Vec<u8>, mut nodes: Vec<DxNode>, hash: u32, lblk: u32) -> Result<()> {
        let gen = raw.generation();
        let n = nodes.pop().ok_or(FsError::Invalid("empty htree path"))?;
        let p = self.dir_phys(dir, raw, n.lblk as u64)?;
        let b = self.block(p)?;
        let (limit, count) = (b.u16_at(n.base) as usize, b.u16_at(n.base + 2) as usize);
        if count < limit {
            self.dx_put(p, n.base, n.idx + 1, hash, lblk)?;
            return self.seal_dx(dir, gen, p, n.base);
        }
        if n.lblk == 0 {
            // Root is full: move its entries down a level.
            let levels = b.u8_at(30);
            if levels >= if self.g.large_dir { 2 } else { 1 } {
                return Err(FsError::NoSpace);
            }
            let (nl, np) = self.dir_grow_node(dir, raw, count)?;
            let moved = b[n.base + 8..n.base + count * 8].to_vec();
            let child0 = b.u32_at(n.base + 4);
            let w = self.modify(np)?;
            w.put_u32(12, child0);
            w[16..16 + moved.len()].copy_from_slice(&moved);
            let r = self.modify(p)?;
            r.put_u8(30, levels + 1);
            r.put_u16(n.base + 2, 1);
            r.put_u32(n.base + 4, nl);
            self.seal_dx(dir, gen, p, n.base)?;
            self.seal_dx(dir, gen, np, 8)?;
            let root = DxNode { lblk: 0, base: n.base, idx: 0 };
            let child = DxNode { lblk: nl, base: 8, idx: n.idx };
            return self.dx_insert(dir, raw, vec![root, child], hash, lblk);
        }
        // Interior node is full: split it, and tell the parent about the new half.
        let half = count / 2;
        let (nl, np) = self.dir_grow_node(dir, raw, count - half)?;
        let first_hash = b.u32_at(n.base + half * 8);
        let child0 = b.u32_at(n.base + half * 8 + 4);
        let moved = b[n.base + (half + 1) * 8..n.base + count * 8].to_vec();
        let w = self.modify(np)?;
        w.put_u32(12, child0);
        w[16..16 + moved.len()].copy_from_slice(&moved);
        self.modify(p)?.put_u16(n.base + 2, half as u16);
        self.seal_dx(dir, gen, p, n.base)?;
        self.seal_dx(dir, gen, np, 8)?;
        self.dx_insert(dir, raw, nodes, first_hash, nl)?;
        let (tp, idx) = if n.idx >= half { (np, n.idx - half) } else { (p, n.idx) };
        self.dx_put(tp, 8, idx + 1, hash, lblk)?;
        self.seal_dx(dir, gen, tp, 8)
    }

    fn dx_put(&mut self, p: u64, base: usize, pos: usize, hash: u32, lblk: u32) -> Result<()> {
        let b = self.modify(p)?;
        let count = b.u16_at(base + 2) as usize;
        b.copy_within(base + pos * 8..base + count * 8, base + (pos + 1) * 8);
        b.put_u32(base + pos * 8, hash);
        b.put_u32(base + pos * 8 + 4, lblk);
        b.put_u16(base + 2, count as u16 + 1);
        Ok(())
    }

    fn dir_grow_node(&mut self, dir: u32, raw: &mut Vec<u8>, count: usize) -> Result<(u32, u64)> {
        let (lblk, p) = self.dir_grow(dir, raw)?;
        let limit = self.dx_limit(false);
        let bs = self.g.bs;
        let b = self.modify(p)?;
        b.fill(0);
        put_rec_len(b, 0, bs);
        b.put_u16(8, limit as u16);
        b.put_u16(10, count as u16);
        Ok((lblk, p))
    }

    /// Removes an entry by name.
    pub fn dir_remove(&mut self, dir: u32, raw: &[u8], name: &[u8]) -> Result<()> {
        if self.is_inline(raw) {
            return Err(FsError::ReadOnly);
        }
        let gen = raw.generation();
        for lblk in 0..self.dir_blocks(raw) {
            let p = self.dir_phys(dir, raw, lblk)?;
            let b = self.block(p)?;
            let end = self.leaf_end(&b);
            let (mut prev, mut hit) = (None, None);
            let mut last = None;
            self.parse_entries(&b, 0, end, &mut |e| {
                if e.name == name {
                    prev = last;
                    hit = Some(e);
                    return false;
                }
                last = Some(e.off);
                true
            })?;
            let Some(e) = hit else { continue };
            // A preceding free record can sit between `prev` and the entry, so walk it.
            let mut before = prev.unwrap_or(0);
            if e.off > 0 {
                while before + rec_len(&b, before) < e.off {
                    before += rec_len(&b, before);
                }
            }
            let w = self.modify(p)?;
            if e.off == 0 {
                w.put_u32(0, 0);
            } else {
                let merged = rec_len(w, before) + e.rec;
                put_rec_len(w, before, merged);
            }
            return self.seal_leaf(dir, gen, p);
        }
        Err(FsError::NotFound)
    }

    /// A directory's parent. `..` is read in place: in an htree directory it sits in the
    /// root block, where a hashed lookup would never find it.
    pub fn dir_parent(&self, dir: u32, raw: &[u8]) -> Result<u32> {
        if self.is_inline(raw) {
            return Ok(raw.u32_at(I_BLOCK));
        }
        Ok(self.block(self.dir_phys(dir, raw, 0)?)?.u32_at(12))
    }

    /// Points a directory's `..` at a new parent.
    pub fn dir_set_parent(&mut self, dir: u32, raw: &[u8], parent: u32) -> Result<()> {
        let p = self.dir_phys(dir, raw, 0)?;
        self.modify(p)?.put_u32(12, parent);
        if raw.flags() & F_INDEX != 0 {
            self.seal_dx(dir, raw.generation(), p, 32)
        } else {
            self.seal_leaf(dir, raw.generation(), p)
        }
    }

    /// Fills the first block of a new directory.
    pub fn dir_init(&mut self, dir: u32, raw: &mut Vec<u8>, parent: u32) -> Result<()> {
        let (_, p) = self.dir_grow(dir, raw)?;
        let mut b = self.block(p)?.to_vec();
        let end = self.usable();
        self.write_entry(&mut b, 0, 12, b".", dir, 2);
        self.write_entry(&mut b, 12, end - 12, b"..", parent, 2);
        self.modify(p)?.copy_from_slice(&b);
        self.seal_leaf(dir, raw.generation(), p)
    }

    /// Verifies the checksums of every block in a directory.
    pub fn dir_verify(&self, dir: u32, raw: &[u8]) -> Result<()> {
        if !self.g.metadata_csum || self.is_inline(raw) {
            return Ok(());
        }
        let seed = self.inode_seed(dir, raw.generation());
        for lblk in 0..self.dir_blocks(raw) {
            let Some(p) = self.map(dir, raw, lblk)?.phys else { continue };
            let b = self.block(p)?;
            let t = b.len() - TAIL;
            if self.leaf_end(&b) == t && b.u32_at(t + 8) != crc32c_raw(seed, &b[..t]) {
                return corrupt(format!("directory {dir} block {lblk} failed its checksum"));
            }
        }
        Ok(())
    }
}

struct DxNode {
    lblk: u32,
    base: usize,
    idx: usize,
}

struct DxPath {
    nodes: Vec<DxNode>,
    leaf: u32,
    may_continue: bool,
}

/// Approximates the kernel's Unicode casefold for read-only lookups.
fn same_folded(a: &[u8], b: &[u8]) -> bool {
    match (std::str::from_utf8(a), std::str::from_utf8(b)) {
        (Ok(x), Ok(y)) => x.to_lowercase() == y.to_lowercase(),
        _ => false,
    }
}
