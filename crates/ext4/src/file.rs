//! File contents: block mapping, reads, ordered writes and truncation.
use crate::extent::{Extent, Run};
use crate::inode::{set_size, Inode, F_ENCRYPT, F_EXTENTS, F_INLINE, I_BLOCK};
use crate::{Fs, Result};
use fscore::FsError;

/// Largest single device read, keeping buffers bounded for huge extents.
const MAX_IO: usize = 8 << 20;

impl Fs {
    pub fn map(&self, ino: u32, raw: &[u8], lblk: u64) -> Result<Run> {
        if raw.flags() & F_EXTENTS != 0 {
            if lblk > u32::MAX as u64 {
                return Ok(Run { phys: None, len: 1 << 32, unwritten: false });
            }
            self.ext_map(ino, raw, lblk as u32)
        } else {
            self.ind_map(raw, lblk)
        }
    }

    /// Reads file contents; holes and unwritten extents read as zeroes.
    pub fn read_data(&self, ino: u32, raw: &[u8], off: u64, buf: &mut [u8]) -> Result<usize> {
        let size = raw.size();
        if off >= size {
            return Ok(0);
        }
        let want = buf.len().min((size - off).min(usize::MAX as u64) as usize);
        if raw.flags() & F_ENCRYPT != 0 {
            return Err(FsError::Unsupported("file is encrypted".into()));
        }
        if raw.flags() & F_INLINE != 0 {
            return self.read_inline(raw, off, &mut buf[..want]);
        }
        let bs = self.g.bs as u64;
        let mut done = 0;
        while done < want {
            let pos = off + done as u64;
            let (lblk, in_blk) = (pos / bs, pos % bs);
            let run = self.map(ino, raw, lblk)?;
            let avail = run.len.saturating_mul(bs).saturating_sub(in_blk);
            let n = avail.min((want - done) as u64).min(MAX_IO as u64) as usize;
            let dst = &mut buf[done..done + n];
            match run.phys {
                Some(p) if !run.unwritten => {
                    self.check_block(p)?;
                    self.dev.read_at(p * bs + in_blk, dst)?;
                }
                _ => dst.fill(0),
            }
            done += n;
        }
        Ok(done)
    }

    fn read_inline(&self, raw: &[u8], off: u64, buf: &mut [u8]) -> Result<usize> {
        let mut data = raw[I_BLOCK..I_BLOCK + 60].to_vec();
        if let Some(v) = self.inline_xattr_data(raw)? {
            data.extend_from_slice(&v);
        }
        let s = (off as usize).min(data.len());
        let n = buf.len().min(data.len() - s);
        buf[..n].copy_from_slice(&data[s..s + n]);
        buf[n..].fill(0);
        Ok(buf.len())
    }

    /// Where to allocate the next blocks of a file: right after what precedes them.
    fn goal(&self, ino: u32, raw: &[u8], lblk: u64) -> u64 {
        if lblk > 0 {
            if let Ok(Run { phys: Some(p), .. }) = self.map(ino, raw, lblk - 1) {
                return p + 1;
            }
        }
        self.g.group_start(self.inode_group(ino))
    }

    /// Allocates and maps up to `want` blocks at `lblk` (a hole). Returns (phys, count).
    fn alloc_file(&mut self, ino: u32, raw: &mut Vec<u8>, lblk: u64, want: u64) -> Result<(u64, u32)> {
        let goal = self.goal(ino, raw, lblk);
        if raw.flags() & F_EXTENTS != 0 {
            let (p, n) = self.alloc_blocks(goal, want.min(u32::MAX as u64) as u32)?;
            let e = Extent { lblk: lblk as u32, phys: p, len: n, unwritten: false };
            if let Err(err) = self.ext_insert(ino, raw, e) {
                // The tree needed a block the volume doesn't have. A write that already made
                // progress keeps this transaction, so these blocks must not leak into it.
                self.free_blocks(p, n)?;
                return Err(err);
            }
            self.add_i_blocks(raw, n as i64);
            Ok((p, n))
        } else {
            let (p, n) = self.alloc_blocks(goal, want.min(1024) as u32)?;
            for i in 0..n as u64 {
                if let Err(err) = self.ind_set(raw, lblk + i, p + i) {
                    if i == 0 {
                        self.free_blocks(p, n)?;
                        return Err(err);
                    }
                    // The first `i` blocks are mapped: keep those and hand back the rest.
                    self.free_blocks(p + i, n - i as u32)?;
                    self.add_i_blocks(raw, i as i64);
                    return Ok((p, i as u32));
                }
            }
            self.add_i_blocks(raw, n as i64);
            Ok((p, n))
        }
    }

    /// Maps a single new block and returns it.
    pub fn alloc_file_block(&mut self, ino: u32, raw: &mut Vec<u8>, lblk: u64) -> Result<u64> {
        Ok(self.alloc_file(ino, raw, lblk, 1)?.0)
    }

    /// Writes `data` at `off`, allocating as needed. Data goes straight to its final
    /// location, ahead of the commit that publishes the metadata (ordered mode).
    /// Returns bytes written; a short count means the volume filled up part way.
    pub fn write_data(&mut self, ino: u32, raw: &mut Vec<u8>, off: u64, data: &[u8]) -> Result<usize> {
        let bs = self.g.bs as u64;
        let max = if raw.flags() & F_EXTENTS != 0 { (1u64 << 32) * bs } else { self.ind_limit() };
        if off.checked_add(data.len() as u64).is_none_or(|e| e > max) {
            return Err(FsError::Invalid("file would exceed the maximum size"));
        }
        let old = raw.size();
        if off > old {
            self.zero_tail(ino, raw, old)?;
        }
        let mut done = 0usize;
        while done < data.len() {
            let pos = off + done as u64;
            let (lblk, in_blk) = (pos / bs, (pos % bs) as usize);
            let want = (in_blk as u64 + (data.len() - done) as u64).div_ceil(bs);
            let run = self.map(ino, raw, lblk)?;
            let (phys, avail, fresh) = match run {
                Run { phys: Some(p), unwritten: false, len } => (p, len.min(want), false),
                Run { phys: Some(p), unwritten: true, len } => {
                    let n = len.min(want).min(u32::MAX as u64) as u32;
                    self.ext_mark_written(ino, raw, lblk as u32, n)?;
                    (p, n as u64, true)
                }
                Run { phys: None, len, .. } => match self.alloc_file(ino, raw, lblk, len.min(want)) {
                    Ok((p, n)) => (p, n as u64, true),
                    Err(FsError::NoSpace) if done > 0 => break,
                    Err(e) => return Err(e),
                },
            };
            let n = (avail * bs - in_blk as u64).min((data.len() - done) as u64) as usize;
            self.write_blocks(phys, in_blk, &data[done..done + n], fresh)?;
            done += n;
        }
        if off + done as u64 > raw.size() {
            set_size(raw, off + done as u64);
            if off + done as u64 >= 1 << 31 {
                self.mark_large_file();
            }
        }
        Ok(done)
    }

    fn mark_large_file(&mut self) {
        use fscore::{Le, LeMut};
        let v = self.sb.u32_at(0x64) | 2;
        self.sb.put_u32(0x64, v);
    }

    fn ind_limit(&self) -> u64 {
        let p = self.g.bs as u64 / 4;
        (12 + p + p * p + p * p * p).min(u32::MAX as u64) * self.g.bs as u64
    }

    /// Writes bytes at `in_blk` within the run at `phys`. Partial end blocks are merged
    /// with what's there, or zero-filled when the blocks are new.
    fn write_blocks(&mut self, phys: u64, in_blk: usize, data: &[u8], fresh: bool) -> Result<()> {
        let bs = self.g.bs;
        self.check_block(phys)?;
        let base = phys * bs as u64;
        if in_blk == 0 && data.len() % bs == 0 {
            return self.dev.write_at(base, data);
        }
        let total = (in_blk + data.len()).div_ceil(bs) * bs;
        let mut head = data;
        let mut pos = 0usize;
        let mut at = in_blk;
        while !head.is_empty() {
            let n = head.len().min(bs - at % bs);
            if at % bs == 0 && n == bs {
                let whole = head.len() / bs * bs;
                self.dev.write_at(base + at as u64, &head[..whole])?;
                head = &head[whole..];
                pos += whole;
                at += whole;
                continue;
            }
            let blk = at / bs * bs;
            let mut b = vec![0u8; bs];
            if !fresh {
                self.dev.read_at(base + blk as u64, &mut b)?;
            }
            b[at % bs..at % bs + n].copy_from_slice(&head[..n]);
            self.dev.write_at(base + blk as u64, &b)?;
            head = &head[n..];
            pos += n;
            at += n;
        }
        debug_assert!(at <= total && pos == data.len());
        Ok(())
    }

    /// Clears bytes past `size` in the last block so old data can't reappear on extension.
    fn zero_tail(&mut self, ino: u32, raw: &[u8], size: u64) -> Result<()> {
        let bs = self.g.bs as u64;
        let in_blk = (size % bs) as usize;
        if in_blk == 0 {
            return Ok(());
        }
        if let Run { phys: Some(p), unwritten: false, .. } = self.map(ino, raw, size / bs)? {
            let zeros = vec![0u8; bs as usize - in_blk];
            self.dev.write_at(p * bs + in_blk as u64, &zeros)?;
        }
        Ok(())
    }

    /// Sets the file size, releasing blocks when shrinking.
    pub fn truncate_to(&mut self, ino: u32, raw: &mut Vec<u8>, size: u64) -> Result<()> {
        let bs = self.g.bs as u64;
        let old = raw.size();
        if size < old {
            self.zero_tail(ino, raw, size)?;
            let from = size.div_ceil(bs);
            if raw.flags() & F_EXTENTS != 0 {
                self.ext_truncate(ino, raw, from.min(u32::MAX as u64) as u32)?;
            } else {
                self.ind_truncate(raw, from)?;
            }
        } else if size > old {
            self.zero_tail(ino, raw, old)?;
        }
        set_size(raw, size);
        Ok(())
    }
}
