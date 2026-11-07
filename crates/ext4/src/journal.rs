//! jbd2: replaying the log at mount, and committing transactions through it.
//!
//! Commits are checkpointed immediately, so the log is empty between transactions.
//! That removes the need for revoke records on the write side and means the log never
//! wraps, while replay still handles everything Linux may have left behind.
use crate::extent::Run;
use crate::inode::Inode;
use crate::{corrupt, Fs, Result};
use fscore::{crc32c_raw, FsError, Time};
use std::collections::HashMap;
use std::sync::Arc;

const MAGIC: u32 = 0xC03B_3998;
const T_DESCRIPTOR: u32 = 1;
const T_COMMIT: u32 = 2;
const T_SB_V1: u32 = 3;
const T_SB_V2: u32 = 4;
const T_REVOKE: u32 = 5;

const F_REVOKE: u32 = 1;
const F_64BIT: u32 = 2;
const F_ASYNC_COMMIT: u32 = 4;
const F_CSUM_V2: u32 = 8;
const F_CSUM_V3: u32 = 0x10;
const F_FAST_COMMIT: u32 = 0x20;
const F_KNOWN: u32 = F_REVOKE | F_64BIT | F_ASYNC_COMMIT | F_CSUM_V2 | F_CSUM_V3 | F_FAST_COMMIT;

const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;

fn be32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map_or(0, |v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}
fn be16(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 2).map_or(0, |v| u16::from_be_bytes([v[0], v[1]]) as u32)
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}
fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_be_bytes());
}

/// An internal journal: its location, format and current sequence.
pub struct Journal {
    /// Physical runs of the journal file: (first logical block, physical, length).
    runs: Vec<(u64, u64, u64)>,
    bs: usize,
    maxlen: u32,
    first: u32,
    pub sequence: u32,
    start: u32,
    incompat: u32,
    seed: u32,
    sb: Vec<u8>,
}

impl Journal {
    fn v3(&self) -> bool {
        self.incompat & F_CSUM_V3 != 0
    }
    fn v2(&self) -> bool {
        self.incompat & F_CSUM_V2 != 0
    }
    fn wide(&self) -> bool {
        self.incompat & F_64BIT != 0
    }
    fn csummed(&self) -> bool {
        self.v2() || self.v3()
    }
    fn tag_size(&self) -> usize {
        if self.v3() {
            16
        } else {
            8 + if self.wide() { 4 } else { 0 }
        }
    }
    fn phys(&self, l: u32) -> Result<u64> {
        let l = l as u64;
        let i = self.runs.partition_point(|r| r.0 <= l);
        match i.checked_sub(1).map(|i| self.runs[i]) {
            Some((s, p, n)) if l < s + n => Ok(p + l - s),
            _ => corrupt("journal block is not mapped"),
        }
    }
    /// Log positions wrap from the end back to `first`.
    fn next(&self, l: u32) -> u32 {
        if l + 1 >= self.maxlen {
            self.first
        } else {
            l + 1
        }
    }
    /// Blocks one transaction may occupy, leaving room for descriptors and the commit.
    pub fn capacity(&self) -> usize {
        let room = (self.maxlen - self.first) as usize;
        let tags = (self.bs - 12 - 4 - 16) / self.tag_size();
        room.saturating_sub(room / tags + 4)
    }
    /// Clean-state flag: Linux won't replay when this is zero.
    pub fn is_clean(&self) -> bool {
        self.start == 0
    }
    pub fn has_fast_commit(&self) -> bool {
        self.incompat & F_FAST_COMMIT != 0
    }

    fn block_csum(&self, b: &[u8]) -> u32 {
        crc32c_raw(self.seed, b)
    }

    fn tag_csum(&self, seq: u32, data: &[u8]) -> u32 {
        crc32c_raw(crc32c_raw(self.seed, &seq.to_be_bytes()), data)
    }

    fn seal_sb(&mut self) {
        if self.csummed() {
            put32(&mut self.sb, 0xFC, 0);
            let c = crc32c_raw(!0, &self.sb[..1024]);
            put32(&mut self.sb, 0xFC, c);
        }
    }
}

struct Tag {
    block: u64,
    flags: u32,
    csum: u32,
}

impl Fs {
    /// Locates and validates the internal journal. Returns None if there is none.
    pub fn open_journal(&self, ino: u32) -> Result<Journal> {
        let raw = self.inode(ino)?;
        let bs = self.g.bs as u64;
        let blocks = raw.size() / bs;
        let mut runs: Vec<(u64, u64, u64)> = vec![];
        let mut l = 0;
        while l < blocks {
            let Run { phys, len, .. } = self.map(ino, &raw, l)?;
            let Some(p) = phys else { return corrupt("hole in journal") };
            let n = len.min(blocks - l);
            match runs.last_mut() {
                Some(r) if r.1 + r.2 == p => r.2 += n,
                _ => runs.push((l, p, n)),
            }
            l += n;
        }
        let Some(&(_, p0, _)) = runs.first() else { return corrupt("empty journal") };
        let mut sb = vec![0u8; self.g.bs.max(1024)];
        self.dev.read_at(p0 * bs, &mut sb[..self.g.bs])?;
        if let Some(b) = self.overlay.get(&p0) {
            sb[..self.g.bs].copy_from_slice(b);
        }
        let ty = be32(&sb, 4);
        if be32(&sb, 0) != MAGIC || (ty != T_SB_V1 && ty != T_SB_V2) {
            return corrupt("bad journal superblock");
        }
        let incompat = if ty == T_SB_V2 { be32(&sb, 0x28) } else { 0 };
        if incompat & !F_KNOWN != 0 {
            return Err(FsError::Unsupported(format!("unknown journal features {incompat:#x}")));
        }
        if be32(&sb, 0xC) as usize != self.g.bs {
            return corrupt("journal block size differs from the filesystem");
        }
        let (maxlen, first) = (be32(&sb, 0x10), be32(&sb, 0x14));
        if maxlen as u64 > blocks || first == 0 || first >= maxlen {
            return corrupt("bad journal geometry");
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&sb[0x30..0x40]);
        Ok(Journal {
            runs,
            bs: self.g.bs,
            maxlen,
            first,
            sequence: be32(&sb, 0x18),
            start: be32(&sb, 0x1C),
            incompat,
            seed: crc32c_raw(!0, &uuid),
            sb,
        })
    }

    fn jblock(&self, j: &Journal, l: u32) -> Result<Vec<u8>> {
        let mut b = vec![0u8; self.g.bs];
        self.dev.read_at(j.phys(l)? * self.g.bs as u64, &mut b)?;
        Ok(b)
    }

    fn parse_tags(&self, j: &Journal, b: &[u8]) -> Vec<Tag> {
        let tail = if j.csummed() { 4 } else { 0 };
        let end = b.len() - tail;
        let mut o = 12;
        let mut out = vec![];
        let size = j.tag_size();
        while o + size <= end {
            let (lo, flags, hi, csum);
            if j.v3() {
                (lo, flags, hi, csum) = (be32(b, o), be32(b, o + 4), be32(b, o + 8), be32(b, o + 12));
            } else {
                lo = be32(b, o);
                csum = be16(b, o + 4);
                flags = be16(b, o + 6);
                hi = if j.wide() { be32(b, o + 8) } else { 0 };
            }
            o += size;
            if flags & TAG_SAME_UUID == 0 {
                o += 16;
            }
            let block = lo as u64 | if j.wide() { (hi as u64) << 32 } else { 0 };
            out.push(Tag { block, flags, csum });
            if flags & TAG_LAST != 0 {
                break;
            }
        }
        out
    }

    fn check_tail(&self, j: &Journal, b: &[u8]) -> bool {
        if !j.csummed() {
            return true;
        }
        let t = b.len() - 4;
        let mut c = b.to_vec();
        put32(&mut c, t, 0);
        be32(b, t) == j.block_csum(&c)
    }

    fn check_commit(&self, j: &Journal, b: &[u8]) -> bool {
        if !j.csummed() {
            return true;
        }
        let mut c = b.to_vec();
        put32(&mut c, 0x10, 0);
        be32(b, 0x10) == j.block_csum(&c)
    }

    /// Reads the committed transactions in the log. The result maps each block to the
    /// contents replay would write. Nothing on disk changes.
    pub fn scan_journal(&self, j: &Journal) -> Result<HashMap<u64, Arc<[u8]>>> {
        // Pass 1: find the last complete commit and collect revocations.
        let mut revoked: HashMap<u64, u32> = HashMap::new();
        let (mut pos, mut seq) = (j.start, j.sequence);
        let mut end_seq = seq;
        let limit = j.maxlen as u64 * 2;
        let mut steps = 0u64;
        'scan: loop {
            let mut txn_revokes: Vec<u64> = vec![];
            loop {
                steps += 1;
                if steps > limit {
                    break 'scan;
                }
                let b = self.jblock(j, pos)?;
                if be32(&b, 0) != MAGIC || be32(&b, 8) != seq {
                    break 'scan;
                }
                pos = j.next(pos);
                match be32(&b, 4) {
                    T_DESCRIPTOR => {
                        if !self.check_tail(j, &b) {
                            break 'scan;
                        }
                        for _ in self.parse_tags(j, &b) {
                            pos = j.next(pos);
                        }
                    }
                    T_REVOKE => {
                        if !self.check_tail(j, &b) {
                            break 'scan;
                        }
                        let w = if j.wide() { 8 } else { 4 };
                        let count = (be32(&b, 12) as usize).min(b.len());
                        let mut o = 16;
                        while o + w <= count {
                            let v = if w == 8 {
                                (be32(&b, o) as u64) << 32 | be32(&b, o + 4) as u64
                            } else {
                                be32(&b, o) as u64
                            };
                            txn_revokes.push(v);
                            o += w;
                        }
                    }
                    T_COMMIT => {
                        if !self.check_commit(j, &b) {
                            break 'scan;
                        }
                        break;
                    }
                    _ => break 'scan,
                }
            }
            for r in txn_revokes {
                let e = revoked.entry(r).or_insert(seq);
                *e = (*e).max(seq);
            }
            seq = seq.wrapping_add(1);
            end_seq = seq;
        }
        // Pass 2: collect block images, skipping anything revoked by a later transaction.
        let mut out: HashMap<u64, Arc<[u8]>> = HashMap::new();
        let (mut pos, mut seq) = (j.start, j.sequence);
        while seq != end_seq {
            let b = self.jblock(j, pos)?;
            pos = j.next(pos);
            match be32(&b, 4) {
                T_DESCRIPTOR => {
                    for t in self.parse_tags(j, &b) {
                        let mut data = self.jblock(j, pos)?;
                        pos = j.next(pos);
                        if revoked.get(&t.block).is_some_and(|r| !seq_before(*r, seq)) {
                            continue;
                        }
                        if t.flags & TAG_ESCAPE != 0 {
                            data[..4].copy_from_slice(&MAGIC.to_be_bytes());
                        }
                        if j.csummed() {
                            let c = j.tag_csum(seq, &data);
                            let ok = if j.v3() { c == t.csum } else { c & 0xFFFF == t.csum };
                            if !ok {
                                return corrupt(format!("journal block for {} failed its checksum", t.block));
                            }
                        }
                        self.check_block(t.block)?;
                        out.insert(t.block, data.into());
                    }
                }
                T_COMMIT => seq = seq.wrapping_add(1),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Applies recovered blocks to disk and marks the log empty.
    pub fn replay_to_disk(&mut self, j: &mut Journal, blocks: &HashMap<u64, Arc<[u8]>>) -> Result<()> {
        for (n, b) in blocks {
            self.dev.write_at(n * self.g.bs as u64, b)?;
        }
        self.dev.flush()?;
        j.sequence = j.sequence.wrapping_add(1);
        self.write_jsb(j, 0)?;
        self.dev.flush()
    }

    fn write_jsb(&self, j: &mut Journal, start: u32) -> Result<()> {
        j.start = start;
        let seq = j.sequence;
        put32(&mut j.sb, 0x18, seq);
        put32(&mut j.sb, 0x1C, start);
        j.seal_sb();
        self.dev.write_at(j.phys(0)? * self.g.bs as u64, &j.sb[..self.g.bs])
    }

    /// Writes one transaction to the log, then to its final location, with barriers
    /// between each stage. Crash before the commit block lands: the transaction never
    /// happened. Crash after: replay finishes it.
    pub fn journal_commit(&mut self, blocks: &[(u64, Arc<[u8]>)]) -> Result<()> {
        let mut j = self.journal.take().ok_or(FsError::Invalid("no journal"))?;
        let r = self.journal_commit_inner(&mut j, blocks);
        self.journal = Some(j);
        r
    }

    fn journal_commit_inner(&mut self, j: &mut Journal, blocks: &[(u64, Arc<[u8]>)]) -> Result<()> {
        let bs = self.g.bs;
        let seq = j.sequence;
        let mut pos = j.first;
        let tag_size = j.tag_size();
        let room = bs - 12 - if j.csummed() { 4 } else { 0 };
        for group in blocks.chunks((room - 16) / tag_size) {
            let mut d = vec![0u8; bs];
            put32(&mut d, 0, MAGIC);
            put32(&mut d, 4, T_DESCRIPTOR);
            put32(&mut d, 8, seq);
            let desc_pos = pos;
            pos += 1;
            let mut o = 12;
            for (i, (n, data)) in group.iter().enumerate() {
                let mut flags = if i > 0 { TAG_SAME_UUID } else { 0 };
                if i + 1 == group.len() {
                    flags |= TAG_LAST;
                }
                let escaped = be32(data, 0) == MAGIC;
                let image: Vec<u8> = if escaped {
                    flags |= TAG_ESCAPE;
                    let mut c = data.to_vec();
                    c[..4].fill(0);
                    c
                } else {
                    vec![]
                };
                // The checksum covers the real contents, before escaping.
                let csum = if j.csummed() { j.tag_csum(seq, data) } else { 0 };
                if j.v3() {
                    put32(&mut d, o, *n as u32);
                    put32(&mut d, o + 4, flags);
                    put32(&mut d, o + 8, (*n >> 32) as u32);
                    put32(&mut d, o + 12, csum);
                } else {
                    put32(&mut d, o, *n as u32);
                    put16(&mut d, o + 4, csum as u16);
                    put16(&mut d, o + 6, flags as u16);
                    if j.wide() {
                        put32(&mut d, o + 8, (*n >> 32) as u32);
                    }
                }
                o += tag_size;
                if i == 0 {
                    d[o..o + 16].copy_from_slice(&j.sb[0x30..0x40]);
                    o += 16;
                }
                let out: &[u8] = if escaped { &image } else { data };
                self.dev.write_at(j.phys(pos)? * bs as u64, out)?;
                pos += 1;
            }
            if j.csummed() {
                let c = j.block_csum(&d);
                put32(&mut d, bs - 4, c);
            }
            self.dev.write_at(j.phys(desc_pos)? * bs as u64, &d)?;
        }
        // Publish the log start together with the log contents.
        let first = j.first;
        self.write_jsb(j, first)?;
        self.dev.flush()?;

        let mut c = vec![0u8; bs];
        put32(&mut c, 0, MAGIC);
        put32(&mut c, 4, T_COMMIT);
        put32(&mut c, 8, seq);
        let now = Time::now();
        c[0x30..0x38].copy_from_slice(&(now.sec as u64).to_be_bytes());
        put32(&mut c, 0x38, now.nsec);
        if j.csummed() {
            let s = j.block_csum(&c);
            put32(&mut c, 0x10, s);
        }
        self.dev.write_at(j.phys(pos)? * bs as u64, &c)?;
        self.dev.flush()?;

        for (n, data) in blocks {
            self.dev.write_at(*n * bs as u64, data)?;
        }
        self.dev.flush()?;
        j.sequence = seq.wrapping_add(1);
        self.write_jsb(j, 0)
    }
}

/// True if sequence `a` precedes `b`, allowing for wraparound.
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
