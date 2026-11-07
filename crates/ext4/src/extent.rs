//! The extent tree: lookups, insertion with node splitting, and truncation.
use crate::inode::{Inode, I_BLOCK};
use crate::{corrupt, Fs, Result};
use fscore::{crc32c_raw, FsError, Le, LeMut};

const MAGIC: u16 = 0xF30A;
const HDR: usize = 12;
const ENT: usize = 12;
const MAX_DEPTH: u16 = 5;
pub const MAX_LEN: u32 = 32768;
const MAX_UNWRITTEN: u32 = 32767;

/// A contiguous stretch of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub lblk: u32,
    pub phys: u64,
    pub len: u32,
    pub unwritten: bool,
}

/// One answer from a block lookup. `phys` is None for a hole.
#[derive(Clone, Copy, Debug)]
pub struct Run {
    pub phys: Option<u64>,
    pub len: u64,
    pub unwritten: bool,
}

fn read_extent(b: &[u8], i: usize) -> Extent {
    let o = HDR + i * ENT;
    let raw_len = b.u16_at(o + 4) as u32;
    let unwritten = raw_len > MAX_LEN;
    Extent {
        lblk: b.u32_at(o),
        phys: (b.u16_at(o + 6) as u64) << 32 | b.u32_at(o + 8) as u64,
        len: if unwritten { raw_len - MAX_LEN } else { raw_len },
        unwritten,
    }
}

fn write_extent(b: &mut [u8], i: usize, e: Extent) {
    let o = HDR + i * ENT;
    b.put_u32(o, e.lblk);
    b.put_u16(o + 4, (if e.unwritten { e.len + MAX_LEN } else { e.len }) as u16);
    b.put_u16(o + 6, (e.phys >> 32) as u16);
    b.put_u32(o + 8, e.phys as u32);
}

fn idx_at(b: &[u8], i: usize) -> (u32, u64) {
    let o = HDR + i * ENT;
    (b.u32_at(o), b.u32_at(o + 4) as u64 | (b.u16_at(o + 8) as u64) << 32)
}

fn put_idx(b: &mut [u8], i: usize, lblk: u32, child: u64) {
    let o = HDR + i * ENT;
    b.put_u32(o, lblk);
    b.put_u32(o + 4, child as u32);
    b.put_u16(o + 8, (child >> 32) as u16);
    b.put_u16(o + 10, 0);
}

fn entries(b: &[u8]) -> usize {
    b.u16_at(2) as usize
}
fn max_entries(b: &[u8]) -> usize {
    b.u16_at(4) as usize
}
fn depth(b: &[u8]) -> u16 {
    b.u16_at(6)
}
fn set_entries(b: &mut [u8], n: usize) {
    b.put_u16(2, n as u16);
}

fn check_header(b: &[u8], want_depth: Option<u16>) -> Result<()> {
    let room = (b.len() - HDR) / ENT;
    if b.u16_at(0) != MAGIC || entries(b) > max_entries(b) || max_entries(b) > room || depth(b) > MAX_DEPTH {
        return corrupt("bad extent header");
    }
    if want_depth.is_some_and(|d| d != depth(b)) {
        return corrupt("extent tree depth mismatch");
    }
    Ok(())
}

/// Largest index whose first logical block is `<= lblk`, if any.
fn find(b: &[u8], lblk: u32) -> Option<usize> {
    let n = entries(b);
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if b.u32_at(HDR + mid * ENT) <= lblk {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo.checked_sub(1)
}

impl Fs {
    fn ext_tail_csum(&self, ino: u32, gen: u32, b: &[u8]) -> u32 {
        let end = HDR + max_entries(b) * ENT;
        crc32c_raw(self.inode_seed(ino, gen), &b[..end.min(b.len())])
    }

    fn ext_block(&self, ino: u32, gen: u32, n: u64, want: u16) -> Result<std::sync::Arc<[u8]>> {
        let b = self.block(n)?;
        check_header(&b, Some(want))?;
        if self.g.metadata_csum {
            let end = HDR + max_entries(&b) * ENT;
            if b.u32_at(end) != self.ext_tail_csum(ino, gen, &b) {
                return corrupt(format!("extent block {n} of inode {ino} failed its checksum"));
            }
        }
        Ok(b)
    }

    fn seal_ext_block(&mut self, ino: u32, gen: u32, n: u64) -> Result<()> {
        if self.g.metadata_csum {
            let b = self.block(n)?;
            let c = self.ext_tail_csum(ino, gen, &b);
            let end = HDR + max_entries(&b) * ENT;
            self.modify(n)?.put_u32(end, c);
        }
        Ok(())
    }

    /// Finds what backs logical block `lblk`.
    pub fn ext_map(&self, ino: u32, raw: &[u8], lblk: u32) -> Result<Run> {
        let root = &raw[I_BLOCK..I_BLOCK + 60];
        check_header(root, None)?;
        let mut d = depth(root);
        let mut cur: std::sync::Arc<[u8]> = root.into();
        // The start of the next extent bounds a hole.
        let mut next = u32::MAX as u64 + 1;
        while d > 0 {
            let Some(i) = find(&cur, lblk) else {
                let (first, _) = idx_at(&cur, 0);
                return Ok(hole(lblk, if entries(&cur) > 0 { first as u64 } else { next }));
            };
            if i + 1 < entries(&cur) {
                next = idx_at(&cur, i + 1).0 as u64;
            }
            let (_, child) = idx_at(&cur, i);
            d -= 1;
            cur = self.ext_block(ino, raw.generation(), child, d)?;
        }
        match find(&cur, lblk) {
            Some(i) => {
                let e = read_extent(&cur, i);
                let in_ext = lblk as u64 - e.lblk as u64;
                if in_ext < e.len as u64 {
                    Ok(Run { phys: Some(e.phys + in_ext), len: e.len as u64 - in_ext, unwritten: e.unwritten })
                } else {
                    let n = if i + 1 < entries(&cur) { read_extent(&cur, i + 1).lblk as u64 } else { next };
                    Ok(hole(lblk, n))
                }
            }
            None => {
                let n = if entries(&cur) > 0 { read_extent(&cur, 0).lblk as u64 } else { next };
                Ok(hole(lblk, n))
            }
        }
    }

    /// Adds a mapping for a range that is currently a hole.
    pub fn ext_insert(&mut self, ino: u32, raw: &mut [u8], e: Extent) -> Result<()> {
        loop {
            let root_depth = depth(&raw[I_BLOCK..I_BLOCK + 60]);
            let split = self.ext_insert_root(ino, raw, e, root_depth)?;
            match split {
                Inserted::Done => return Ok(()),
                Inserted::Grow => self.ext_grow(ino, raw)?,
            }
        }
    }

    fn ext_insert_root(&mut self, ino: u32, raw: &mut [u8], e: Extent, d: u16) -> Result<Inserted> {
        let gen = raw.generation();
        let mut root = raw[I_BLOCK..I_BLOCK + 60].to_vec();
        check_header(&root, None)?;
        if d == 0 {
            if insert_leaf(&mut root, e) {
                raw[I_BLOCK..I_BLOCK + 60].copy_from_slice(&root);
                return Ok(Inserted::Done);
            }
            return Ok(Inserted::Grow);
        }
        if entries(&root) == 0 {
            return corrupt("empty extent index");
        }
        // A full root can't take a split from below, so make room first.
        let i = find(&root, e.lblk).unwrap_or(0);
        if entries(&root) >= max_entries(&root) {
            let (_, child) = idx_at(&root, i);
            if self.subtree_full(ino, gen, child, d - 1)? {
                return Ok(Inserted::Grow);
            }
        }
        let (first, child) = idx_at(&root, i);
        if e.lblk < first {
            put_idx(&mut root, i, e.lblk, child);
        }
        let split = self.ext_insert_node(ino, raw, child, d - 1, e)?;
        if let Some((lblk, blk)) = split {
            insert_idx(&mut root, i + 1, lblk, blk);
        }
        raw[I_BLOCK..I_BLOCK + 60].copy_from_slice(&root);
        Ok(Inserted::Done)
    }

    /// True if inserting below `n` could propagate a split all the way up.
    fn subtree_full(&self, ino: u32, gen: u32, n: u64, d: u16) -> Result<bool> {
        let b = self.ext_block(ino, gen, n, d)?;
        Ok(entries(&b) >= max_entries(&b))
    }

    /// Inserts into the subtree at block `n`. On a split, returns the new sibling.
    fn ext_insert_node(&mut self, ino: u32, raw: &mut [u8], n: u64, d: u16, e: Extent) -> Result<Option<(u32, u64)>> {
        let gen = raw.generation();
        let mut b = self.ext_block(ino, gen, n, d)?.to_vec();
        if d == 0 {
            if insert_leaf(&mut b, e) {
                self.modify(n)?.copy_from_slice(&b);
                self.seal_ext_block(ino, gen, n)?;
                return Ok(None);
            }
            let (lblk, blk) = self.split_node(ino, raw, n, &mut b, e.lblk)?;
            let target = if e.lblk >= lblk { blk } else { n };
            let mut t = self.block(target)?.to_vec();
            if !insert_leaf(&mut t, e) {
                return corrupt("extent leaf split left no room");
            }
            self.modify(target)?.copy_from_slice(&t);
            self.seal_ext_block(ino, gen, target)?;
            return Ok(Some((lblk, blk)));
        }
        let i = find(&b, e.lblk).unwrap_or(0);
        let (first, child) = idx_at(&b, i);
        if e.lblk < first {
            put_idx(&mut b, i, e.lblk, child);
            self.modify(n)?.copy_from_slice(&b);
            self.seal_ext_block(ino, gen, n)?;
        }
        let Some((lblk, blk)) = self.ext_insert_node(ino, raw, child, d - 1, e)? else {
            return Ok(None);
        };
        if entries(&b) < max_entries(&b) {
            insert_idx(&mut b, i + 1, lblk, blk);
            self.modify(n)?.copy_from_slice(&b);
            self.seal_ext_block(ino, gen, n)?;
            return Ok(None);
        }
        let (slblk, sblk) = self.split_node(ino, raw, n, &mut b, lblk)?;
        let target = if lblk >= slblk { sblk } else { n };
        let mut t = self.block(target)?.to_vec();
        let pos = find(&t, lblk).map_or(0, |p| p + 1);
        insert_idx(&mut t, pos, lblk, blk);
        self.modify(target)?.copy_from_slice(&t);
        self.seal_ext_block(ino, gen, target)?;
        Ok(Some((slblk, sblk)))
    }

    /// Moves the upper part of node `n` into a new block. Appending workloads split at
    /// the end so nodes stay full.
    fn split_node(&mut self, ino: u32, raw: &mut [u8], n: u64, b: &mut [u8], new_lblk: u32) -> Result<(u32, u64)> {
        let gen = raw.generation();
        let count = entries(b);
        let last = b.u32_at(HDR + (count - 1) * ENT);
        let keep = if new_lblk > last { count } else { count / 2 };
        let (nb, _) = self.alloc_blocks(n, 1)?;
        self.add_i_blocks(raw, 1);
        let bs = self.g.bs;
        let mut s = vec![0u8; bs];
        s[..HDR].copy_from_slice(&b[..HDR]);
        s.put_u16(4, ((bs - HDR - 4) / ENT) as u16);
        let moved = count - keep;
        set_entries(&mut s, moved);
        s[HDR..HDR + moved * ENT].copy_from_slice(&b[HDR + keep * ENT..HDR + count * ENT]);
        set_entries(b, keep);
        self.fresh(nb)?.copy_from_slice(&s);
        self.seal_ext_block(ino, gen, nb)?;
        self.modify(n)?.copy_from_slice(b);
        self.seal_ext_block(ino, gen, n)?;
        let first = if moved > 0 { s.u32_at(HDR) } else { new_lblk };
        Ok((first, nb))
    }

    /// Adds a tree level: the root's contents move into a new block.
    fn ext_grow(&mut self, ino: u32, raw: &mut [u8]) -> Result<()> {
        let gen = raw.generation();
        let root = raw[I_BLOCK..I_BLOCK + 60].to_vec();
        if depth(&root) >= MAX_DEPTH {
            return Err(FsError::Unsupported("extent tree too deep".into()));
        }
        let goal = self.g.group_start(self.inode_group(ino));
        let (nb, _) = self.alloc_blocks(goal, 1)?;
        self.add_i_blocks(raw, 1);
        let bs = self.g.bs;
        let mut b = vec![0u8; bs];
        b[..HDR + entries(&root) * ENT].copy_from_slice(&root[..HDR + entries(&root) * ENT]);
        b.put_u16(4, ((bs - HDR - 4) / ENT) as u16);
        self.fresh(nb)?.copy_from_slice(&b);
        self.seal_ext_block(ino, gen, nb)?;
        let first = root.u32_at(HDR);
        let r = &mut raw[I_BLOCK..I_BLOCK + 60];
        r.put_u16(6, depth(&root) + 1);
        set_entries(r, 1);
        put_idx(r, 0, first, nb);
        Ok(())
    }

    /// Frees all blocks at or past `from`. Returns blocks released.
    pub fn ext_truncate(&mut self, ino: u32, raw: &mut [u8], from: u32) -> Result<u64> {
        let gen = raw.generation();
        let mut root = raw[I_BLOCK..I_BLOCK + 60].to_vec();
        check_header(&root, None)?;
        let d = depth(&root);
        let mut freed = 0;
        self.trunc_node(ino, gen, &mut root, d, from, &mut freed)?;
        if entries(&root) == 0 {
            root.put_u16(6, 0);
        }
        raw[I_BLOCK..I_BLOCK + 60].copy_from_slice(&root);
        self.add_i_blocks(raw, -(freed as i64));
        Ok(freed)
    }

    fn trunc_node(&mut self, ino: u32, gen: u32, b: &mut [u8], d: u16, from: u32, freed: &mut u64) -> Result<()> {
        if d == 0 {
            let mut keep = entries(b);
            while keep > 0 {
                let mut e = read_extent(b, keep - 1);
                let end = e.lblk as u64 + e.len as u64;
                if end <= from as u64 {
                    break;
                }
                if e.lblk >= from {
                    self.free_blocks(e.phys, e.len)?;
                    *freed += e.len as u64;
                    keep -= 1;
                } else {
                    let cut = (end - from as u64) as u32;
                    self.free_blocks(e.phys + (e.len - cut) as u64, cut)?;
                    *freed += cut as u64;
                    e.len -= cut;
                    write_extent(b, keep - 1, e);
                    break;
                }
            }
            set_entries(b, keep);
            return Ok(());
        }
        let mut keep = entries(b);
        while keep > 0 {
            let (first, child) = idx_at(b, keep - 1);
            let mut c = self.ext_block(ino, gen, child, d - 1)?.to_vec();
            self.trunc_node(ino, gen, &mut c, d - 1, from, freed)?;
            if entries(&c) == 0 {
                self.free_blocks(child, 1)?;
                *freed += 1;
                keep -= 1;
            } else {
                self.modify(child)?.copy_from_slice(&c);
                self.seal_ext_block(ino, gen, child)?;
            }
            if first < from {
                break;
            }
        }
        set_entries(b, keep);
        Ok(())
    }

    /// Marks `[lblk, lblk+len)` as written. The range must lie within one unwritten
    /// extent, which is split as needed.
    pub fn ext_mark_written(&mut self, ino: u32, raw: &mut [u8], lblk: u32, len: u32) -> Result<()> {
        let gen = raw.generation();
        let mut root = raw[I_BLOCK..I_BLOCK + 60].to_vec();
        let d = depth(&root);
        let mut loc = None;
        let mut cur = root.clone();
        for level in (0..d).rev() {
            let i = find(&cur, lblk).ok_or_else(|| FsError::Corrupt("extent index gap".into()))?;
            let (_, child) = idx_at(&cur, i);
            cur = self.ext_block(ino, gen, child, level)?.to_vec();
            loc = Some(child);
        }
        let i = find(&cur, lblk).ok_or_else(|| FsError::Corrupt("unwritten extent missing".into()))?;
        let e = read_extent(&cur, i);
        let head = lblk - e.lblk;
        let tail = e.len - head - len;
        let mid = Extent { lblk, phys: e.phys + head as u64, len, unwritten: false };
        let tail_e = Extent { lblk: lblk + len, phys: mid.phys + len as u64, len: tail, unwritten: true };
        // Overwrite the original entry with the first piece, then add the remainder.
        let first = if head > 0 { Extent { len: head, ..e } } else { mid };
        write_extent(&mut cur, i, first);
        match loc {
            Some(n) => {
                self.modify(n)?.copy_from_slice(&cur);
                self.seal_ext_block(ino, gen, n)?;
            }
            None => {
                root.copy_from_slice(&cur);
                raw[I_BLOCK..I_BLOCK + 60].copy_from_slice(&root);
            }
        }
        if head > 0 {
            self.ext_insert(ino, raw, mid)?;
        }
        if tail > 0 {
            self.ext_insert(ino, raw, tail_e)?;
        }
        Ok(())
    }

    /// Visits every extent-tree node block of the file.
    pub fn ext_verify(&self, ino: u32, raw: &[u8]) -> Result<()> {
        let root = &raw[I_BLOCK..I_BLOCK + 60];
        check_header(root, None)?;
        self.verify_node(ino, raw.generation(), root, depth(root))
    }

    fn verify_node(&self, ino: u32, gen: u32, b: &[u8], d: u16) -> Result<()> {
        for i in 0..entries(b) {
            if d > 0 {
                let (_, child) = idx_at(b, i);
                let c = self.ext_block(ino, gen, child, d - 1)?;
                self.verify_node(ino, gen, &c, d - 1)?;
            } else {
                let e = read_extent(b, i);
                if e.len == 0 || e.phys.checked_add(e.len as u64).is_none_or(|end| end > self.g.blocks) {
                    return corrupt(format!("inode {ino} has an extent outside the volume"));
                }
            }
        }
        Ok(())
    }
}

enum Inserted {
    Done,
    Grow,
}

fn hole(lblk: u32, next: u64) -> Run {
    Run { phys: None, len: next.saturating_sub(lblk as u64).max(1), unwritten: false }
}

fn insert_idx(b: &mut [u8], pos: usize, lblk: u32, child: u64) {
    let n = entries(b);
    b.copy_within(HDR + pos * ENT..HDR + n * ENT, HDR + (pos + 1) * ENT);
    put_idx(b, pos, lblk, child);
    set_entries(b, n + 1);
}

/// Inserts into a leaf node, merging with the left neighbour when physically adjacent.
/// Returns false if the node has no room.
fn insert_leaf(b: &mut [u8], e: Extent) -> bool {
    let n = entries(b);
    let pos = find(b, e.lblk).map_or(0, |p| p + 1);
    if pos > 0 {
        let mut p = read_extent(b, pos - 1);
        let limit = if e.unwritten { MAX_UNWRITTEN } else { MAX_LEN };
        if p.unwritten == e.unwritten
            && p.lblk as u64 + p.len as u64 == e.lblk as u64
            && p.phys + p.len as u64 == e.phys
            && p.len + e.len <= limit
        {
            p.len += e.len;
            write_extent(b, pos - 1, p);
            return true;
        }
    }
    if n >= max_entries(b) {
        return false;
    }
    b.copy_within(HDR + pos * ENT..HDR + n * ENT, HDR + (pos + 1) * ENT);
    write_extent(b, pos, e);
    set_entries(b, n + 1);
    true
}

/// Initial, empty extent root for a new inode.
pub fn init_root(raw: &mut [u8]) {
    let r = &mut raw[I_BLOCK..I_BLOCK + 60];
    r.fill(0);
    r.put_u16(0, MAGIC);
    r.put_u16(4, 4);
}
