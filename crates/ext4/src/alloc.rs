//! Group descriptors plus block and inode allocation.
use crate::{corrupt, Fs, Result};
use fscore::{crc32c_raw, FsError, Le, LeMut};

pub const BG_INODE_UNINIT: u16 = 1;
pub const BG_BLOCK_UNINIT: u16 = 2;

/// CRC-16 (reflected 0x8005) used by the older `uninit_bg` group checksum.
pub fn crc16(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xA001 } else { crc >> 1 };
        }
    }
    crc
}

impl Fs {
    pub fn gd(&self, g: u32) -> &[u8] {
        let o = g as usize * self.g.desc_size;
        &self.gds[o..o + self.g.desc_size]
    }

    fn gd_mut(&mut self, g: u32) -> &mut [u8] {
        self.touched.insert(g);
        let o = g as usize * self.g.desc_size;
        let n = self.g.desc_size;
        if let Some(u) = &mut self.undo {
            u.gds.entry(g).or_insert_with(|| self.gds[o..o + n].to_vec());
        }
        &mut self.gds[o..o + n]
    }

    fn gd_u64(&self, g: u32, lo: usize, hi: usize) -> u64 {
        let d = self.gd(g);
        d.u32_at(lo) as u64 | if self.g.desc_size >= 64 { (d.u32_at(hi) as u64) << 32 } else { 0 }
    }

    fn gd_u32(&self, g: u32, lo: usize, hi: usize) -> u32 {
        let d = self.gd(g);
        d.u16_at(lo) as u32 | if self.g.desc_size >= 64 { (d.u16_at(hi) as u32) << 16 } else { 0 }
    }

    fn set_gd_u32(&mut self, g: u32, lo: usize, hi: usize, v: u32) {
        let wide = self.g.desc_size >= 64;
        let d = self.gd_mut(g);
        d.put_u16(lo, v as u16);
        if wide {
            d.put_u16(hi, (v >> 16) as u16);
        }
    }

    pub fn block_bitmap_loc(&self, g: u32) -> u64 {
        self.gd_u64(g, 0, 0x20)
    }
    pub fn inode_bitmap_loc(&self, g: u32) -> u64 {
        self.gd_u64(g, 4, 0x24)
    }
    pub fn inode_table(&self, g: u32) -> u64 {
        self.gd_u64(g, 8, 0x28)
    }
    pub fn free_blocks_in(&self, g: u32) -> u32 {
        self.gd_u32(g, 0xC, 0x2C)
    }
    pub fn free_inodes_in(&self, g: u32) -> u32 {
        self.gd_u32(g, 0xE, 0x2E)
    }
    fn used_dirs_in(&self, g: u32) -> u32 {
        self.gd_u32(g, 0x10, 0x30)
    }
    fn itable_unused(&self, g: u32) -> u32 {
        self.gd_u32(g, 0x1C, 0x32)
    }
    pub fn gd_flags(&self, g: u32) -> u16 {
        self.gd(g).u16_at(0x12)
    }
    pub fn inode_group(&self, ino: u32) -> u32 {
        (ino - 1) / self.g.ipg
    }

    /// Computes the stored checksum of descriptor `g`.
    pub fn gd_csum(&self, g: u32) -> u16 {
        let mut d = self.gd(g).to_vec();
        d.put_u16(0x1E, 0);
        if self.g.metadata_csum {
            let c = crc32c_raw(self.g.csum_seed, &g.to_le_bytes());
            return crc32c_raw(c, &d) as u16;
        }
        if self.g.gdt_csum {
            let c = crc16(0xFFFF, &self.g.uuid);
            let c = crc16(c, &g.to_le_bytes());
            let c = crc16(c, &d[..0x1E]);
            return if d.len() > 0x20 { crc16(c, &d[0x20..]) } else { c };
        }
        0
    }

    /// Where descriptor block `i` lives, honouring `meta_bg`.
    pub fn gd_block(&self, i: u64) -> u64 {
        let base = self.g.first_data + 1;
        if !self.g.meta_bg || i < self.g.first_meta_bg as u64 {
            return base + i;
        }
        let g = (i * self.g.gd_per_block() as u64) as u32;
        let has = self.g.has_super(g);
        self.g.group_start(g) + has as u64
    }

    /// Stamps checksums for all groups touched by this transaction into their blocks.
    pub fn flush_group_descriptors(&mut self) -> Result<()> {
        let groups: Vec<u32> = self.touched.iter().copied().collect();
        for g in groups {
            if self.g.metadata_csum {
                self.stamp_bitmap_csums(g)?;
            }
            let c = self.gd_csum(g);
            self.gd_mut(g).put_u16(0x1E, c);
            let per = self.g.gd_per_block();
            let (blk, off) = (self.gd_block((g / per) as u64), (g % per) as usize * self.g.desc_size);
            let src = self.gd(g).to_vec();
            self.modify(blk)?[off..off + src.len()].copy_from_slice(&src);
        }
        self.touched.clear();
        Ok(())
    }

    fn stamp_bitmap_csums(&mut self, g: u32) -> Result<()> {
        let wide = self.g.desc_size >= 64;
        if self.gd_flags(g) & BG_BLOCK_UNINIT == 0 {
            let b = self.block(self.block_bitmap_loc(g))?;
            let c = crc32c_raw(self.g.csum_seed, &b[..(self.g.cpg / 8) as usize]);
            let d = self.gd_mut(g);
            d.put_u16(0x18, c as u16);
            if wide {
                d.put_u16(0x38, (c >> 16) as u16);
            }
        }
        if self.gd_flags(g) & BG_INODE_UNINIT == 0 {
            let b = self.block(self.inode_bitmap_loc(g))?;
            let c = crc32c_raw(self.g.csum_seed, &b[..(self.g.ipg / 8) as usize]);
            let d = self.gd_mut(g);
            d.put_u16(0x1A, c as u16);
            if wide {
                d.put_u16(0x3A, (c >> 16) as u16);
            }
        }
        Ok(())
    }

    /// Materialises the bitmap of a never-used group, which exists only implicitly.
    fn init_block_bitmap(&mut self, g: u32) -> Result<()> {
        let bs = self.g.bs;
        let start = self.g.group_start(g);
        let span = self.g.group_blocks(g) as u64;
        let mut b = vec![0u8; bs];
        let mut mark = |blk: u64| {
            if blk >= start && blk < start + span {
                let i = (blk - start) as usize;
                b[i / 8] |= 1 << (i % 8);
            }
        };
        if self.g.has_super(g) {
            mark(start);
            if !self.g.meta_bg {
                for i in 0..self.g.gd_blocks() + self.g.reserved_gdt as u64 {
                    mark(start + 1 + i);
                }
            }
        }
        if self.g.meta_bg {
            let per = self.g.gd_per_block() as u64;
            let meta_group = g as u64 / per;
            if meta_group >= self.g.first_meta_bg as u64 {
                let first = meta_group * per;
                let last = first + per - 1;
                if [first, first + 1, last].contains(&(g as u64)) {
                    mark(start + self.g.has_super(g) as u64);
                }
            } else if self.g.has_super(g) {
                for i in 0..self.g.first_meta_bg as u64 {
                    mark(start + 1 + i);
                }
            }
        }
        mark(self.block_bitmap_loc(g));
        mark(self.inode_bitmap_loc(g));
        let itable_blocks = (self.g.ipg as u64 * self.g.isize as u64).div_ceil(bs as u64);
        let t = self.inode_table(g);
        for i in 0..itable_blocks {
            mark(t + i);
        }
        for i in span as usize..bs * 8 {
            b[i / 8] |= 1 << (i % 8);
        }
        self.fresh(self.block_bitmap_loc(g))?.copy_from_slice(&b);
        let flags = self.gd_flags(g) & !BG_BLOCK_UNINIT;
        self.gd_mut(g).put_u16(0x12, flags);
        Ok(())
    }

    fn free_total(&self) -> u64 {
        self.sb.u32_at(0xC) as u64 | if self.g.is_64bit { (self.sb.u32_at(0x158) as u64) << 32 } else { 0 }
    }

    fn set_free_total(&mut self, v: u64) {
        self.sb.put_u32(0xC, v as u32);
        if self.g.is_64bit {
            self.sb.put_u32(0x158, (v >> 32) as u32);
        }
    }

    pub fn reserved_blocks(&self) -> u64 {
        self.sb.u32_at(8) as u64 | if self.g.is_64bit { (self.sb.u32_at(0x154) as u64) << 32 } else { 0 }
    }

    /// Bytes usable by a normal user, which excludes the root reservation.
    pub fn free_bytes(&self) -> u64 {
        let pending: u64 = self.pending_free.iter().map(|p| p.1 as u64).sum();
        (self.free_total() + pending).saturating_sub(self.reserved_blocks()) * self.g.bs as u64
    }

    /// Allocates up to `want` contiguous blocks near `goal`. Returns (start, count).
    pub fn alloc_blocks(&mut self, goal: u64, want: u32) -> Result<(u64, u32)> {
        let avail = self.free_total().saturating_sub(self.reserved_blocks());
        if avail == 0 {
            return Err(FsError::NoSpace);
        }
        let want = want.clamp(1, crate::extent::MAX_LEN).min(avail.min(u32::MAX as u64) as u32);
        let groups = self.g.groups;
        let g0 = self.g.group_of(goal.max(self.g.first_data));
        for i in 0..groups {
            let g = (g0 + i) % groups;
            if self.free_blocks_in(g) == 0 {
                continue;
            }
            if self.gd_flags(g) & BG_BLOCK_UNINIT != 0 {
                self.init_block_bitmap(g)?;
            }
            let loc = self.block_bitmap_loc(g);
            let bm = self.block(loc)?;
            let span = self.g.group_blocks(g) as usize;
            let from = if i == 0 { (goal.saturating_sub(self.g.group_start(g))) as usize } else { 0 };
            let Some((s, n)) = find_run(&bm, from.min(span), span, want as usize)
                .or_else(|| find_run(&bm, 0, span, want as usize))
            else {
                continue;
            };
            let m = self.modify(loc)?;
            for b in s..s + n {
                m[b / 8] |= 1 << (b % 8);
            }
            let free = self.free_blocks_in(g) - n as u32;
            self.set_gd_u32(g, 0xC, 0x2C, free);
            let total = self.free_total().saturating_sub(n as u64);
            self.set_free_total(total);
            return Ok((self.g.group_start(g) + s as u64, n as u32));
        }
        Err(FsError::NoSpace)
    }

    /// Queues blocks for release at the next commit.
    pub fn free_blocks(&mut self, start: u64, len: u32) -> Result<()> {
        if start < self.g.first_data || start.checked_add(len as u64).is_none_or(|e| e > self.g.blocks) {
            return corrupt(format!("attempt to free blocks {start}+{len} outside the volume"));
        }
        for b in start..start + len as u64 {
            self.note_undo(b);
            self.dirty.remove(&b);
            self.cache.remove(b);
        }
        self.pending_free.push((start, len));
        Ok(())
    }

    /// Clears bitmap bits queued by [`Self::free_blocks`], stopping once `budget` blocks
    /// are dirty so a huge delete can't outgrow the journal.
    pub fn apply_pending_frees(&mut self, budget: usize) -> Result<()> {
        while let Some((mut start, mut len)) = self.pending_free.pop() {
            if self.dirty.len() >= budget {
                self.pending_free.push((start, len));
                return Ok(());
            }
            while len > 0 {
                let g = self.g.group_of(start);
                let off = (start - self.g.group_start(g)) as usize;
                let n = len.min(self.g.group_blocks(g) - off as u32);
                let loc = self.block_bitmap_loc(g);
                let m = self.modify(loc)?;
                let mut released = 0;
                for b in off..off + n as usize {
                    if m[b / 8] & (1 << (b % 8)) != 0 {
                        m[b / 8] &= !(1 << (b % 8));
                        released += 1;
                    }
                }
                let free = self.free_blocks_in(g) + released;
                self.set_gd_u32(g, 0xC, 0x2C, free);
                let total = self.free_total() + released as u64;
                self.set_free_total(total);
                start += n as u64;
                len -= n;
            }
        }
        Ok(())
    }

    fn free_inode_total(&self) -> u32 {
        self.sb.u32_at(0x10)
    }

    /// Picks a group for a new inode: directories spread out, files stay with their parent.
    fn inode_goal_group(&self, parent: u32, dir: bool) -> u32 {
        let pg = self.inode_group(parent);
        if dir {
            let mut best = pg;
            let mut score = 0u64;
            for g in 0..self.g.groups {
                let s = self.free_inodes_in(g) as u64 * (self.free_blocks_in(g) as u64 + 1);
                if s > score {
                    (best, score) = (g, s);
                }
            }
            return best;
        }
        pg
    }

    pub fn alloc_inode(&mut self, parent: u32, dir: bool) -> Result<u32> {
        if self.free_inode_total() == 0 {
            return Err(FsError::NoSpace);
        }
        let g0 = self.inode_goal_group(parent, dir);
        for i in 0..self.g.groups {
            let g = (g0 + i) % self.g.groups;
            if self.free_inodes_in(g) == 0 {
                continue;
            }
            let loc = self.inode_bitmap_loc(g);
            if self.gd_flags(g) & BG_INODE_UNINIT != 0 {
                let ipg = self.g.ipg as usize;
                let bm = self.fresh(loc)?;
                for b in ipg..bm.len() * 8 {
                    bm[b / 8] |= 1 << (b % 8);
                }
                let flags = self.gd_flags(g) & !BG_INODE_UNINIT;
                self.gd_mut(g).put_u16(0x12, flags);
            }
            let bm = self.block(loc)?;
            // Group 0 holds the reserved inodes.
            let first = if g == 0 { self.g.first_ino as usize - 1 } else { 0 };
            let Some(bit) = (first..self.g.ipg as usize).find(|b| bm[b / 8] & (1 << (b % 8)) == 0) else {
                continue;
            };
            self.modify(loc)?[bit / 8] |= 1 << (bit % 8);
            let free = self.free_inodes_in(g) - 1;
            self.set_gd_u32(g, 0xE, 0x2E, free);
            if dir {
                let used = self.used_dirs_in(g) + 1;
                self.set_gd_u32(g, 0x10, 0x30, used);
            }
            if self.g.gdt_csum || self.g.metadata_csum {
                let unused = self.itable_unused(g).min(self.g.ipg - bit as u32 - 1);
                self.set_gd_u32(g, 0x1C, 0x32, unused);
            }
            let total = self.free_inode_total() - 1;
            self.sb.put_u32(0x10, total);
            return Ok(g * self.g.ipg + bit as u32 + 1);
        }
        Err(FsError::NoSpace)
    }

    pub fn free_inode(&mut self, ino: u32, dir: bool) -> Result<()> {
        let g = self.inode_group(ino);
        let bit = ((ino - 1) % self.g.ipg) as usize;
        let loc = self.inode_bitmap_loc(g);
        let m = self.modify(loc)?;
        if m[bit / 8] & (1 << (bit % 8)) == 0 {
            return corrupt(format!("inode {ino} is already free"));
        }
        m[bit / 8] &= !(1 << (bit % 8));
        let free = self.free_inodes_in(g) + 1;
        self.set_gd_u32(g, 0xE, 0x2E, free);
        if dir {
            let used = self.used_dirs_in(g).saturating_sub(1);
            self.set_gd_u32(g, 0x10, 0x30, used);
        }
        let total = self.free_inode_total() + 1;
        self.sb.put_u32(0x10, total);
        Ok(())
    }
}

/// Finds the first free run in `[from, end)`, up to `want` bits long, preferring not to
/// settle for a tiny fragment when a full-length run exists further on.
fn find_run(bm: &[u8], from: usize, end: usize, want: usize) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut i = from;
    while i < end {
        if bm[i / 8] == 0xFF && i % 8 == 0 {
            i += 8;
            continue;
        }
        if bm[i / 8] & (1 << (i % 8)) != 0 {
            i += 1;
            continue;
        }
        let s = i;
        while i < end && i - s < want && bm[i / 8] & (1 << (i % 8)) == 0 {
            i += 1;
        }
        let n = i - s;
        if n >= want {
            return Some((s, n));
        }
        if best.is_none_or(|b| n > b.1) {
            best = Some((s, n));
        }
    }
    best
}
