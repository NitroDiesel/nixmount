//! File extents: reading through checksums and decompression, and the write path.
use crate::inode::*;
use crate::*;
use fscore::{Ino, Le, LeMut, Time};

pub const E_INLINE: u8 = 0;
pub const E_REG: u8 = 1;
pub const E_PREALLOC: u8 = 2;
const E_HDR: usize = 21;
const E_SIZE: usize = 53;
/// Largest data extent the format's tools expect from one allocation.
const MAX_EXTENT: u64 = 128 << 20;
/// Checksum batch size: small enough that a retry on another mirror stays cheap.
const VERIFY_SPAN: usize = 1 << 20;

/// A decoded EXTENT_DATA item.
#[derive(Clone, Debug)]
pub struct FileExtent {
    pub generation: u64,
    pub ram_bytes: u64,
    pub compression: u8,
    pub kind: u8,
    pub disk_bytenr: u64,
    pub disk_bytes: u64,
    pub offset: u64,
    pub num_bytes: u64,
    pub inline: Vec<u8>,
}

impl FileExtent {
    pub fn parse(b: &[u8]) -> Result<FileExtent> {
        if b.len() < E_HDR {
            return bad("file extent too short");
        }
        let kind = b.u8_at(20);
        if b.u8_at(17) != 0 || b.u16_at(18) != 0 {
            return Err(FsError::Unsupported("encrypted file extent".into()));
        }
        let (generation, ram_bytes, compression) = (b.u64_at(0), b.u64_at(8), b.u8_at(16));
        if kind == E_INLINE {
            return Ok(FileExtent {
                generation,
                ram_bytes,
                compression,
                kind,
                disk_bytenr: 0,
                disk_bytes: 0,
                offset: 0,
                num_bytes: ram_bytes,
                inline: b[E_HDR..].to_vec(),
            });
        }
        if b.len() < E_SIZE || kind > E_PREALLOC {
            return bad("bad file extent");
        }
        Ok(FileExtent {
            generation,
            ram_bytes,
            compression,
            kind,
            disk_bytenr: b.u64_at(21),
            disk_bytes: b.u64_at(29),
            offset: b.u64_at(37),
            num_bytes: b.u64_at(45),
            inline: vec![],
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; E_SIZE];
        b.put_u64(0, self.generation);
        b.put_u64(8, self.ram_bytes);
        b.put_u8(16, self.compression);
        b.put_u8(20, self.kind);
        b.put_u64(21, self.disk_bytenr);
        b.put_u64(29, self.disk_bytes);
        b.put_u64(37, self.offset);
        b.put_u64(45, self.num_bytes);
        b
    }

    pub fn is_hole(&self) -> bool {
        self.kind != E_INLINE && self.disk_bytenr == 0
    }
}

impl Fs {
    /// Checksums covering `[start, start+len)`, or None for sectors with no entry.
    fn csums_for(&self, start: u64, len: usize) -> Result<Vec<Option<Vec<u8>>>> {
        let ss = self.sectorsize as u64;
        let mut out = vec![None; len / self.sectorsize];
        let root = self.tree(CSUM_TREE)?;
        let first = Key::new(CSUM_OBJECTID, K_EXTENT_CSUM, start);
        let cs = self.csum_size;
        let mut fill = |k: Key, d: &[u8]| {
            let count = (d.len() / cs) as u64;
            for i in 0..count {
                let at = k.off + i * ss;
                if at >= start && at < start + len as u64 {
                    let dst = ((at - start) / ss) as usize;
                    out[dst] = Some(d[i as usize * cs..(i as usize + 1) * cs].to_vec());
                }
            }
        };
        if let Some((k, d)) = self.find_le(root, first)? {
            if k.obj == CSUM_OBJECTID && k.ty == K_EXTENT_CSUM {
                fill(k, &d);
            }
        }
        self.scan(root, first, &mut |k, d| {
            if k.obj != CSUM_OBJECTID || k.ty != K_EXTENT_CSUM || k.off >= start + len as u64 {
                return Ok(false);
            }
            fill(k, d);
            Ok(true)
        })?;
        Ok(out)
    }

    /// Reads sector-aligned data, trying other copies if a checksum fails.
    pub fn read_data(&self, logical: u64, buf: &mut [u8], verify: bool) -> Result<()> {
        if !verify {
            return self.read_verified(logical, buf, &|_| true);
        }
        let ss = self.sectorsize;
        for (i, part) in buf.chunks_mut(VERIFY_SPAN).enumerate() {
            let at = logical + (i * VERIFY_SPAN) as u64;
            let sums = self.csums_for(at, part.len())?;
            let check = |b: &[u8]| {
                b.chunks(ss).zip(&sums).all(|(s, c)| c.as_ref().is_none_or(|c| self.csum_matches(s, c)))
            };
            self.read_verified(at, part, &check)?;
        }
        Ok(())
    }

    /// Copies bytes `[from, from+dst.len())` of one extent's uncompressed content.
    fn read_extent(&self, e: &FileExtent, from: u64, dst: &mut [u8], verify: bool) -> Result<()> {
        if e.kind == E_INLINE {
            let data = if e.compression != 0 {
                compress::decompress(e.compression, &e.inline, e.ram_bytes.min(1 << 20) as usize, self.sectorsize)?
            } else {
                e.inline.clone()
            };
            let s = (from as usize).min(data.len());
            let n = dst.len().min(data.len() - s);
            dst[..n].copy_from_slice(&data[s..s + n]);
            dst[n..].fill(0);
            return Ok(());
        }
        if e.is_hole() || e.kind == E_PREALLOC {
            dst.fill(0);
            return Ok(());
        }
        if e.compression != 0 {
            if e.disk_bytes > 1 << 24 || e.ram_bytes > 1 << 24 {
                return bad("compressed extent too large");
            }
            let mut z = vec![0u8; e.disk_bytes as usize];
            self.read_data(e.disk_bytenr, &mut z, verify)?;
            let plain = compress::decompress(e.compression, &z, e.ram_bytes as usize, self.sectorsize)?;
            let s = (e.offset + from) as usize;
            match plain.get(s..s + dst.len()) {
                Some(v) => dst.copy_from_slice(v),
                None => return bad("extent range outside its decompressed data"),
            }
            return Ok(());
        }
        let ss = self.sectorsize as u64;
        let at = e.offset + from;
        let lo = at / ss * ss;
        let hi = (at + dst.len() as u64).div_ceil(ss) * ss;
        if lo == at && hi == at + dst.len() as u64 {
            return self.read_data(e.disk_bytenr + lo, dst, verify);
        }
        let mut tmp = vec![0u8; (hi - lo) as usize];
        self.read_data(e.disk_bytenr + lo, &mut tmp, verify)?;
        dst.copy_from_slice(&tmp[(at - lo) as usize..(at - lo) as usize + dst.len()]);
        Ok(())
    }

    /// Reads file contents; gaps between extents are holes.
    pub fn read_file(&self, ino: Ino, item: &[u8], off: u64, buf: &mut [u8]) -> Result<usize> {
        let size = item.u64_at(O_SIZE);
        if off >= size {
            return Ok(0);
        }
        let verify = item.u64_at(O_FLAGS) & NODATASUM == 0;
        let want = buf.len().min((size - off).min(usize::MAX as u64) as usize);
        let buf = &mut buf[..want];
        buf.fill(0);
        let root = self.tree(ino.tree)?;
        let end = off + want as u64;
        let mut start = Key::new(ino.id, K_EXTENT_DATA, off);
        if let Some((k, _)) = self.find_le(root, start)? {
            if k.obj == ino.id && k.ty == K_EXTENT_DATA {
                start = k;
            }
        }
        self.scan(root, start, &mut |k, d| {
            if k.obj != ino.id || k.ty != K_EXTENT_DATA || k.off >= end {
                return Ok(false);
            }
            let e = FileExtent::parse(d)?;
            let (s, t) = (k.off.max(off), k.off.saturating_add(e.num_bytes).min(end));
            if s < t {
                let dst = &mut buf[(s - off) as usize..(t - off) as usize];
                self.read_extent(&e, s - k.off, dst, verify)?;
            }
            Ok(true)
        })?;
        Ok(want)
    }

    fn has_no_holes(&self) -> bool {
        self.incompat & mount::IN_NO_HOLES != 0
    }

    fn data_ref(&mut self, tree: u64, ino: u64, key_off: u64, e: &FileExtent, delta: i64) {
        self.queue_data_ref(e.disk_bytenr, e.disk_bytes, tree, ino, key_off - e.offset, delta);
    }

    /// Removes file extents in `[start, end)`, keeping the outer parts of any that straddle
    /// the boundaries. Adjusts `nbytes`.
    pub fn drop_extents(&mut self, ino: Ino, item: &mut [u8], start: u64, end: u64) -> Result<()> {
        let mut pos = Key::new(ino.id, K_EXTENT_DATA, start);
        let root = self.tree(ino.tree)?;
        if let Some((k, _)) = self.find_le(root, pos)? {
            if k.obj == ino.id && k.ty == K_EXTENT_DATA {
                pos = k;
            }
        }
        let mut found: Vec<(Key, FileExtent)> = vec![];
        self.scan(root, pos, &mut |k, d| {
            if k.obj != ino.id || k.ty != K_EXTENT_DATA || k.off >= end {
                return Ok(false);
            }
            found.push((k, FileExtent::parse(d)?));
            Ok(true)
        })?;
        let mut nbytes = item.u64_at(O_NBYTES);
        for (k, e) in found {
            let last = k.off.saturating_add(e.num_bytes);
            if last <= start {
                continue;
            }
            let (keep_head, keep_tail) = (k.off < start, last > end);
            if e.kind == E_INLINE && (keep_head || keep_tail) {
                return bad("inline extent straddles a write");
            }
            self.delete_item(ino.tree, k)?;
            let cut = last.min(end) - k.off.max(start);
            if !e.is_hole() {
                nbytes = nbytes.saturating_sub(cut);
            }
            if keep_head {
                let head = FileExtent { num_bytes: start - k.off, ..e.clone() };
                self.insert_item(ino.tree, k, &head.encode())?;
            }
            if keep_tail {
                let skip = end - k.off;
                let tail = FileExtent { offset: e.offset + skip, num_bytes: e.num_bytes - skip, ..e.clone() };
                self.insert_item(ino.tree, Key::new(ino.id, K_EXTENT_DATA, end), &tail.encode())?;
            }
            if e.kind != E_INLINE && !e.is_hole() {
                // Both ends surviving means one reference became two; neither means zero.
                match (keep_head, keep_tail) {
                    (true, true) => self.data_ref(ino.tree, ino.id, k.off, &e, 1),
                    (false, false) => self.data_ref(ino.tree, ino.id, k.off, &e, -1),
                    _ => {}
                }
            }
        }
        item.put_u64(O_NBYTES, nbytes);
        Ok(())
    }

    /// An inline extent can't coexist with others: rewrite it as a regular one.
    fn uninline(&mut self, ino: Ino, item: &mut [u8]) -> Result<()> {
        let root = self.tree(ino.tree)?;
        let key = Key::new(ino.id, K_EXTENT_DATA, 0);
        let Some(d) = self.get(root, key)? else { return Ok(()) };
        let e = FileExtent::parse(&d)?;
        if e.kind != E_INLINE {
            return Ok(());
        }
        let n = e.ram_bytes.min(item.u64_at(O_SIZE)) as usize;
        let mut plain = vec![0u8; n];
        self.read_extent(&e, 0, &mut plain, false)?;
        self.delete_item(ino.tree, key)?;
        let nb = item.u64_at(O_NBYTES).saturating_sub(e.ram_bytes);
        item.put_u64(O_NBYTES, nb);
        if n > 0 {
            self.write_range(ino, item, 0, &plain)?;
        }
        Ok(())
    }

    /// Records an explicit hole, which volumes without `no_holes` require.
    fn insert_hole(&mut self, ino: Ino, start: u64, end: u64) -> Result<()> {
        if self.has_no_holes() || start >= end {
            return Ok(());
        }
        let e = FileExtent {
            generation: self.txn.gen,
            ram_bytes: end - start,
            compression: 0,
            kind: E_REG,
            disk_bytenr: 0,
            disk_bytes: 0,
            offset: 0,
            num_bytes: end - start,
            inline: vec![],
        };
        self.insert_item(ino.tree, Key::new(ino.id, K_EXTENT_DATA, start), &e.encode())
    }

    /// Copy-on-write of an aligned range. `data` is padded to whole sectors by the caller.
    fn write_range(&mut self, ino: Ino, item: &mut [u8], off: u64, data: &[u8]) -> Result<()> {
        let ss = self.sectorsize as u64;
        let nosum = item.u64_at(O_FLAGS) & NODATASUM != 0;
        let padded = (data.len() as u64).div_ceil(ss) * ss;
        self.drop_extents(ino, item, off, off + padded)?;
        let mut done = 0u64;
        while done < padded {
            let want = (padded - done).min(MAX_EXTENT);
            let (start, got) = self.alloc_data(want)?;
            let s = done as usize;
            let t = ((done + got) as usize).min(data.len());
            let mut buf = data[s.min(data.len())..t.max(s.min(data.len()))].to_vec();
            buf.resize(got as usize, 0);
            self.write_logical(start, &buf)?;
            if !nosum {
                self.insert_csums(start, &buf)?;
            }
            let e = FileExtent {
                generation: self.txn.gen,
                ram_bytes: got,
                compression: 0,
                kind: E_REG,
                disk_bytenr: start,
                disk_bytes: got,
                offset: 0,
                num_bytes: got,
                inline: vec![],
            };
            let key = Key::new(ino.id, K_EXTENT_DATA, off + done);
            self.insert_item(ino.tree, key, &e.encode())?;
            self.queue_new_data(start, got, ino.tree, ino.id, off + done);
            let nb = item.u64_at(O_NBYTES) + got;
            item.put_u64(O_NBYTES, nb);
            done += got;
        }
        Ok(())
    }

    /// Writes `data` at `off`, merging partial first and last sectors with existing bytes.
    pub fn write_file(&mut self, ino: Ino, item: &mut [u8], off: u64, data: &[u8]) -> Result<()> {
        self.uninline(ino, item)?;
        let ss = self.sectorsize as u64;
        let size = item.u64_at(O_SIZE);
        let end = off + data.len() as u64;
        let lo = off / ss * ss;
        let hi = end.div_ceil(ss) * ss;
        // The sector-rounded end of the old content, where a gap would start.
        let old_end = size.div_ceil(ss) * ss;
        if lo > old_end {
            self.insert_hole(ino, old_end, lo)?;
        }
        let mut buf = vec![0u8; (hi - lo) as usize];
        if lo < off && lo < size {
            let n = (off - lo) as usize;
            self.read_file(ino, item, lo, &mut buf[..n])?;
        }
        if end < hi && end < size {
            let s = (end - lo) as usize;
            self.read_file(ino, item, end, &mut buf[s..])?;
        }
        buf[(off - lo) as usize..(end - lo) as usize].copy_from_slice(data);
        self.write_range(ino, item, lo, &buf)?;
        if end > size {
            item.put_u64(O_SIZE, end);
        }
        let now = Time::now();
        put_time(item, O_MTIME, now);
        put_time(item, O_CTIME, now);
        Ok(())
    }

    /// Changes a file's size.
    pub fn truncate_file(&mut self, ino: Ino, item: &mut [u8], size: u64) -> Result<()> {
        let old = item.u64_at(O_SIZE);
        if size == old {
            return Ok(());
        }
        self.uninline(ino, item)?;
        let ss = self.sectorsize as u64;
        if size < old {
            let lo = size / ss * ss;
            let tail = (size - lo) as usize;
            let mut keep = vec![0u8; tail];
            if tail > 0 {
                self.read_file(ino, item, lo, &mut keep)?;
            }
            self.drop_extents(ino, item, lo, u64::MAX)?;
            if tail > 0 {
                self.write_range(ino, item, lo, &keep)?;
            }
        } else {
            self.insert_hole(ino, old.div_ceil(ss) * ss, size.div_ceil(ss) * ss)?;
        }
        item.put_u64(O_SIZE, size);
        let now = Time::now();
        put_time(item, O_MTIME, now);
        put_time(item, O_CTIME, now);
        Ok(())
    }

    /// Stores checksums for freshly written data, one item per leaf-friendly batch.
    fn insert_csums(&mut self, start: u64, data: &[u8]) -> Result<()> {
        let per_item = (self.nodesize / 4 / self.csum_size).max(1);
        for (i, group) in data.chunks(per_item * self.sectorsize).enumerate() {
            let mut sums = Vec::with_capacity(per_item * self.csum_size);
            for s in group.chunks(self.sectorsize) {
                sums.extend_from_slice(&self.csum(s)[..self.csum_size]);
            }
            let at = start + (i * per_item * self.sectorsize) as u64;
            self.insert_item(CSUM_TREE, Key::new(CSUM_OBJECTID, K_EXTENT_CSUM, at), &sums)?;
        }
        Ok(())
    }

    /// Removes checksums for a freed range. Items can span more than the range, so
    /// overlapping ones are cut and any surviving pieces put back.
    pub fn delete_csums(&mut self, start: u64, len: u64) -> Result<()> {
        let ss = self.sectorsize as u64;
        let cs = self.csum_size;
        let end = start + len;
        loop {
            let root = self.tree(CSUM_TREE)?;
            let probe = Key::new(CSUM_OBJECTID, K_EXTENT_CSUM, end - 1);
            let Some((k, d)) = self.find_le(root, probe)? else { return Ok(()) };
            if k.obj != CSUM_OBJECTID || k.ty != K_EXTENT_CSUM {
                return Ok(());
            }
            let item_end = k.off + (d.len() / cs) as u64 * ss;
            if item_end <= start {
                return Ok(());
            }
            self.delete_item(CSUM_TREE, k)?;
            if k.off < start {
                let n = ((start - k.off) / ss) as usize * cs;
                self.insert_item(CSUM_TREE, k, &d[..n])?;
            }
            if item_end > end {
                let n = ((end - k.off) / ss) as usize * cs;
                self.insert_item(CSUM_TREE, Key::new(CSUM_OBJECTID, K_EXTENT_CSUM, end), &d[n..])?;
            }
        }
    }
}
