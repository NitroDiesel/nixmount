//! Scrub: reads every copy of all metadata and checksummed data, and rewrites bad copies
//! from a good one when the volume is writable.
use crate::tree::*;
use crate::*;
use fscore::{CheckReport, Le};
use std::collections::HashSet;

/// Sectors read at once when checking data: a megabyte at the usual sector size.
const RUN: usize = 256;

impl Fs {
    /// Writes one copy of a logical range, used to repair a single mirror in place.
    fn write_mirror(&self, logical: u64, data: &[u8], mirror: usize) -> Result<()> {
        let c = self.chunk_at(logical)?;
        let off = logical - c.start;
        let (copies, _) = c.locate(off);
        let (i, phys) = copies[mirror % copies.len()];
        let d = self.devs.get(&c.stripes[i].devid).ok_or(FsError::ReadOnly)?;
        d.write_at(phys, data)
    }

    /// Checks each copy of a range. Parity profiles have one direct copy, so a bad block
    /// there is reported rather than repaired.
    fn scrub_range(&self, logical: u64, len: usize, ok: &dyn Fn(&[u8]) -> bool, rep: &mut CheckReport) -> Result<()> {
        let c = self.chunk_at(logical)?;
        let mirrors = if c.is_parity() { 1 } else { c.mirrors() };
        let mut good: Option<Vec<u8>> = None;
        let mut bad_copies = vec![];
        for m in 0..mirrors {
            let mut b = vec![0u8; len];
            if self.read_mirror(logical, &mut b, m).is_ok() && ok(&b) {
                good.get_or_insert(b);
            } else {
                bad_copies.push(m);
            }
        }
        rep.scanned_bytes += (len * mirrors) as u64;
        if bad_copies.is_empty() {
            return Ok(());
        }
        let Some(good) = good else {
            rep.errors.push(format!("{logical:#x}: no good copy of {len} bytes"));
            return Ok(());
        };
        for m in bad_copies {
            if self.read_only {
                rep.errors.push(format!("{logical:#x}: copy {m} is bad (mount read-write to repair)"));
            } else {
                self.write_mirror(logical, &good, m)?;
                rep.repaired += 1;
            }
        }
        Ok(())
    }

    fn scrub_tree(&self, root: Root, seen: &mut HashSet<u64>, rep: &mut CheckReport) -> Result<()> {
        let mut stack = vec![(root.bytenr, root.level)];
        while let Some((logical, lvl)) = stack.pop() {
            if !seen.insert(logical) {
                continue;
            }
            let check = |b: &[u8]| {
                b.u64_at(0x30) == logical && self.csum_matches(&b[0x20..], &b[..self.csum_size])
            };
            self.scrub_range(logical, self.nodesize, &check, rep)?;
            if lvl == 0 {
                continue;
            }
            match self.node(logical, Some(lvl)) {
                Ok(b) => stack.extend((0..nritems(&b)).map(|i| (node_ptr(&b, i), lvl - 1))),
                Err(e) => rep.errors.push(format!("{logical:#x}: {e}")),
            }
        }
        Ok(())
    }

    pub fn scrub_all(&self, progress: &mut dyn FnMut(u64, u64)) -> Result<CheckReport> {
        let mut rep = CheckReport::default();
        let total = self.sb.u64_at(0x78).max(1);
        let mut seen = HashSet::new();
        self.scrub_tree(self.chunk_tree, &mut seen, &mut rep)?;
        self.scrub_tree(self.root_tree, &mut seen, &mut rep)?;
        let mut roots = vec![];
        self.scan(self.root_tree, Key::new(0, K_ROOT_ITEM, 0), &mut |k, d| {
            if k.ty == K_ROOT_ITEM {
                roots.push(Root { bytenr: d.u64_at(176), level: d.u8_at(238) });
            }
            Ok(true)
        })?;
        for r in roots {
            self.scrub_tree(r, &mut seen, &mut rep)?;
            progress(rep.scanned_bytes.min(total), total);
        }
        let (ss, cs) = (self.sectorsize, self.csum_size);
        let csums = self.tree(CSUM_TREE)?;
        // Checksums are taken a part at a time: a large volume has hundreds of megabytes.
        let mut next = Some(0);
        while let Some(from) = next.take() {
            let mut items: Vec<(u64, Vec<u8>)> = vec![];
            let mut held = 0;
            self.scan(csums, Key::new(CSUM_OBJECTID, K_EXTENT_CSUM, from), &mut |k, d| {
                if k.obj == CSUM_OBJECTID && k.ty == K_EXTENT_CSUM {
                    held += d.len();
                    items.push((k.off, d.to_vec()));
                    next = Some(k.off + 1);
                }
                Ok(held < 1 << 20)
            })?;
            if items.is_empty() {
                break;
            }
            for (start, sums) in items {
                let mut done = 0;
                while done < sums.len() / cs {
                    let at = start + (done * ss) as u64;
                    let c = self.chunk_at(at)?;
                    let room = ((c.start + c.len - at) / ss as u64).max(1) as usize;
                    let n = (sums.len() / cs - done).min(RUN).min(room);
                    self.scrub_sectors(at, &sums[done * cs..(done + n) * cs], &mut rep)?;
                    done += n;
                }
                progress(rep.scanned_bytes.min(total), total);
            }
        }
        progress(total, total);
        Ok(rep)
    }

    /// Checks a run of sectors inside one chunk against their checksums, reading each copy
    /// in one go. Only a sector that fails, or a run that won't read, is then gone over
    /// copy by copy, which is where a repair happens.
    fn scrub_sectors(&self, logical: u64, sums: &[u8], rep: &mut CheckReport) -> Result<()> {
        let (ss, cs) = (self.sectorsize, self.csum_size);
        let c = self.chunk_at(logical)?;
        let mirrors = if c.is_parity() { 1 } else { c.mirrors() };
        let mut bad = vec![false; sums.len() / cs];
        let mut buf = vec![0u8; bad.len() * ss];
        for m in 0..mirrors {
            if self.read_mirror(logical, &mut buf, m).is_err() {
                bad.fill(true);
                break;
            }
            for (i, (sector, sum)) in buf.chunks(ss).zip(sums.chunks(cs)).enumerate() {
                bad[i] |= !self.csum_matches(sector, sum);
            }
        }
        for (i, sum) in sums.chunks(cs).enumerate() {
            if bad[i] {
                self.scrub_range(logical + (i * ss) as u64, ss, &|b| self.csum_matches(b, sum), rep)?;
            } else {
                rep.scanned_bytes += (ss * mirrors) as u64;
            }
        }
        Ok(())
    }
}
