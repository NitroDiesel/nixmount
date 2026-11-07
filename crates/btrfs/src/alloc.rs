//! Space allocation: block groups, chunk creation and the free space tree.
use crate::chunk::*;
use crate::mount::{RO_BLOCK_GROUP_TREE, RO_FREE_SPACE_TREE, SB_OFFSETS};
use crate::*;
use fscore::{Le, LeMut};
use std::collections::BTreeSet;

/// One block group's in-memory state.
pub struct Group {
    pub start: u64,
    pub len: u64,
    pub ty: u64,
    pub used: u64,
    /// Free ranges (start to length), built on first use.
    pub free: Option<BTreeMap<u64, u64>>,
}

#[derive(Default)]
pub struct Allocator {
    pub groups: BTreeMap<u64, Group>,
    /// Extent tree of the last commit, which free-space scans read.
    pub committed_extents: Option<Root>,
    /// Handed out in this transaction, not yet visible in the committed tree.
    pub allocated: Vec<(u64, u64)>,
    /// Released in this transaction, reusable only after the commit lands.
    pub pending_free: Vec<(u64, u64)>,
    pub dirty_groups: BTreeSet<u64>,
    /// Queued free-space-tree edits: (start, len, now free).
    pub fst_ops: Vec<(u64, u64, bool)>,
}

fn add_range(m: &mut BTreeMap<u64, u64>, start: u64, len: u64) {
    let (mut s, mut l) = (start, len);
    if let Some((&ps, &pl)) = m.range(..=s).next_back() {
        if ps + pl == s {
            m.remove(&ps);
            s = ps;
            l += pl;
        }
    }
    if let Some(nl) = m.remove(&(s + l)) {
        l += nl;
    }
    m.insert(s, l);
}

fn remove_range(m: &mut BTreeMap<u64, u64>, start: u64, len: u64) {
    let end = start + len;
    let hits: Vec<(u64, u64)> = m
        .range(..end)
        .rev()
        .take_while(|(s, l)| *s + *l > start)
        .map(|(s, l)| (*s, *l))
        .collect();
    for (s, l) in hits {
        m.remove(&s);
        if s < start {
            m.insert(s, start - s);
        }
        if s + l > end {
            m.insert(end, s + l - end);
        }
    }
}

impl Fs {
    fn group_tree(&self) -> u64 {
        if self.compat_ro & RO_BLOCK_GROUP_TREE != 0 {
            BLOCK_GROUP_TREE
        } else {
            EXTENT_TREE
        }
    }

    /// Loads block groups and prepares for the first transaction.
    pub fn begin_writes(&mut self) -> Result<()> {
        let tree = self.tree(self.group_tree())?;
        let chunks: Vec<(u64, u64, u64)> = self.chunks.values().map(|c| (c.start, c.len, c.ty)).collect();
        for (start, len, ty) in chunks {
            let Some(item) = self.get(tree, Key::new(start, K_BLOCK_GROUP_ITEM, len))? else {
                return bad(format!("chunk {start:#x} has no block group"));
            };
            self.alloc.groups.insert(start, Group { start, len, ty, used: item.u64_at(0), free: None });
        }
        self.alloc.committed_extents = Some(self.tree(EXTENT_TREE)?);
        self.txn.gen = self.sb.u64_at(0x48) + 1;
        Ok(())
    }

    /// Logical ranges of a group that hold superblock copies and must stay unused.
    fn super_ranges(&self, g: &Group) -> Vec<(u64, u64)> {
        let mut out = vec![];
        let Some(c) = self.chunks.get(&g.start) else { return out };
        for s in &c.stripes {
            for at in SB_OFFSETS {
                for l in c.logical_of(s.devid, at) {
                    let chunk_off = l.saturating_sub(c.start);
                    let start = c.start + chunk_off / 65536 * 65536;
                    out.push((start, 65536));
                }
            }
        }
        out
    }

    /// Builds a group's free map from the committed extent tree.
    fn load_group(&mut self, start: u64) -> Result<()> {
        let Some(g) = self.alloc.groups.get(&start) else { return bad("unknown block group") };
        if g.free.is_some() {
            return Ok(());
        }
        let (gs, ge) = (g.start, g.start + g.len);
        let excluded = self.super_ranges(g);
        let root = self.alloc.committed_extents.ok_or(FsError::ReadOnly)?;
        let mut free = BTreeMap::new();
        let mut cursor = gs;
        let node = self.nodesize as u64;
        self.scan(root, Key::new(gs, 0, 0), &mut |k, _| {
            if k.obj >= ge {
                return Ok(false);
            }
            let size = match k.ty {
                K_EXTENT_ITEM => k.off,
                K_METADATA_ITEM => node,
                _ => return Ok(true),
            };
            if k.obj > cursor {
                free.insert(cursor, k.obj - cursor);
            }
            cursor = cursor.max(k.obj + size);
            Ok(true)
        })?;
        if cursor < ge {
            free.insert(cursor, ge - cursor);
        }
        for (s, l) in excluded {
            remove_range(&mut free, s, l);
        }
        for &(s, l) in &self.alloc.allocated {
            if s >= gs && s < ge {
                remove_range(&mut free, s, l);
            }
        }
        if let Some(g) = self.alloc.groups.get_mut(&start) {
            g.free = Some(free);
        }
        Ok(())
    }

    fn take_from(&mut self, start: u64, want: u64, align: u64, whole: bool) -> Result<Option<(u64, u64)>> {
        self.load_group(start)?;
        let Some(g) = self.alloc.groups.get_mut(&start) else { return Ok(None) };
        let Some(free) = g.free.as_mut() else { return Ok(None) };
        let mut best: Option<(u64, u64)> = None;
        for (&s, &l) in free.iter() {
            let a = s.div_ceil(align) * align;
            if a >= s + l {
                continue;
            }
            let usable = (s + l - a) / align * align;
            if usable >= want {
                best = Some((a, want));
                break;
            }
            if !whole && usable > 0 && best.is_none_or(|b| usable > b.1) {
                best = Some((a, usable));
            }
        }
        let Some((a, n)) = best else { return Ok(None) };
        remove_range(free, a, n);
        self.alloc.allocated.push((a, n));
        Ok(Some((a, n)))
    }

    fn groups_of(&self, ty: u64) -> Vec<u64> {
        self.alloc.groups.values().filter(|g| g.ty & ty != 0).map(|g| g.start).collect()
    }

    pub fn alloc_tree_block(&mut self, tree: u64) -> Result<u64> {
        let ty = if tree == CHUNK_TREE { T_SYSTEM } else { T_METADATA };
        let node = self.nodesize as u64;
        for g in self.groups_of(ty) {
            if let Some((a, _)) = self.take_from(g, node, node, true)? {
                return Ok(a);
            }
        }
        Err(FsError::NoSpace)
    }

    /// Allocates up to `want` bytes of contiguous data space.
    pub fn alloc_data(&mut self, want: u64) -> Result<(u64, u64)> {
        let ss = self.sectorsize as u64;
        for g in self.groups_of(T_DATA) {
            if let Some(r) = self.take_from(g, want, ss, true)? {
                return Ok(r);
            }
        }
        for g in self.groups_of(T_DATA) {
            if let Some(r) = self.take_from(g, want, ss, false)? {
                return Ok(r);
            }
        }
        Err(FsError::NoSpace)
    }

    fn free_of(&mut self, ty: u64) -> Result<u64> {
        let mut total = 0;
        for g in self.groups_of(ty) {
            self.load_group(g)?;
            if let Some(f) = self.alloc.groups.get(&g).and_then(|g| g.free.as_ref()) {
                total += f.values().sum::<u64>();
            }
        }
        Ok(total)
    }

    /// Guarantees room for an operation before it changes anything, creating chunks
    /// while that is still safe. Failing here leaves the transaction untouched.
    pub fn ensure_space(&mut self, data: u64) -> Result<()> {
        let node = self.nodesize as u64;
        let margin = (256 + 3 * self.txn.nodes.len() as u64) * node;
        while self.free_of(T_SYSTEM)? < 32 * node {
            if !self.alloc_chunk(T_SYSTEM)? {
                break;
            }
        }
        while self.free_of(T_METADATA)? < margin {
            if !self.alloc_chunk(T_METADATA)? {
                if self.free_of(T_METADATA)? < margin / 4 {
                    return Err(FsError::NoSpace);
                }
                break;
            }
        }
        while self.free_of(T_DATA)? < data {
            if !self.alloc_chunk(T_DATA)? {
                return Err(FsError::NoSpace);
            }
        }
        Ok(())
    }

    /// Records an extent appearing or disappearing, for block group, superblock and
    /// free-space-tree accounting.
    pub fn account_extent(&mut self, bytenr: u64, size: u64, created: bool) -> Result<()> {
        let Some((_, g)) = self.alloc.groups.range_mut(..=bytenr).next_back() else {
            return bad("extent outside every block group");
        };
        if bytenr + size > g.start + g.len {
            return bad("extent crosses a block group");
        }
        g.used = if created { g.used + size } else { g.used.saturating_sub(size) };
        let start = g.start;
        self.alloc.dirty_groups.insert(start);
        self.alloc.fst_ops.push((bytenr, size, !created));
        let total = self.sb.u64_at(0x78);
        let v = if created { total + size } else { total.saturating_sub(size) };
        self.sb.put_u64(0x78, v);
        if !created {
            self.alloc.pending_free.push((bytenr, size));
        }
        Ok(())
    }

    /// Makes space freed by a landed commit available again.
    pub fn release_pending(&mut self) {
        for (s, l) in std::mem::take(&mut self.alloc.pending_free) {
            if let Some((_, g)) = self.alloc.groups.range_mut(..=s).next_back() {
                if let Some(f) = g.free.as_mut() {
                    add_range(f, s, l);
                }
            }
        }
        self.alloc.allocated.clear();
    }

    pub fn flush_group_items(&mut self) -> Result<bool> {
        let tree = self.group_tree();
        let dirty = std::mem::take(&mut self.alloc.dirty_groups);
        let any = !dirty.is_empty();
        for start in dirty {
            let Some(g) = self.alloc.groups.get(&start) else { continue };
            let (len, used) = (g.len, g.used);
            self.update_item(tree, Key::new(start, K_BLOCK_GROUP_ITEM, len), |d| d.put_u64(0, used))?;
        }
        Ok(any)
    }

    fn fst_enabled(&self) -> bool {
        self.compat_ro & RO_FREE_SPACE_TREE != 0
    }

    fn group_at(&self, addr: u64) -> Result<(u64, u64)> {
        match self.alloc.groups.range(..=addr).next_back() {
            Some((_, g)) if addr < g.start + g.len => Ok((g.start, g.len)),
            _ => bad("address outside every block group"),
        }
    }

    /// Applies queued edits to the free space tree.
    pub fn flush_free_space(&mut self) -> Result<bool> {
        let ops = std::mem::take(&mut self.alloc.fst_ops);
        if !self.fst_enabled() {
            return Ok(false);
        }
        let any = !ops.is_empty();
        for (start, len, free) in ops {
            let (gs, gl) = self.group_at(start)?;
            let info = Key::new(gs, K_FREE_SPACE_INFO, gl);
            let root = self.tree(FREE_SPACE_TREE)?;
            let Some(v) = self.get(root, info)? else { return bad("block group has no free space info") };
            if v.u32_at(4) & 1 != 0 {
                self.fst_unbitmap(gs, gl)?;
            }
            let delta = if free { self.fst_add(gs, gl, start, len)? } else { self.fst_remove(start, len)? };
            self.update_item(FREE_SPACE_TREE, info, |d| {
                let c = (d.u32_at(0) as i64 + delta).max(0) as u32;
                d.put_u32(0, c);
            })?;
        }
        Ok(any)
    }

    fn fst_remove(&mut self, start: u64, len: u64) -> Result<i64> {
        let root = self.tree(FREE_SPACE_TREE)?;
        let probe = Key::new(start, K_FREE_SPACE_EXTENT, u64::MAX);
        let Some((k, _)) = self.find_le(root, probe)? else { return bad("free space tree has no entry") };
        if k.ty != K_FREE_SPACE_EXTENT || k.obj + k.off < start + len || k.obj > start {
            return bad(format!("allocated range {start:#x}+{len:#x} isn't free in the free space tree"));
        }
        self.delete_item(FREE_SPACE_TREE, k)?;
        let mut delta = -1;
        if k.obj < start {
            self.insert_item(FREE_SPACE_TREE, Key::new(k.obj, K_FREE_SPACE_EXTENT, start - k.obj), &[])?;
            delta += 1;
        }
        let end = start + len;
        if k.obj + k.off > end {
            let rest = k.obj + k.off - end;
            self.insert_item(FREE_SPACE_TREE, Key::new(end, K_FREE_SPACE_EXTENT, rest), &[])?;
            delta += 1;
        }
        Ok(delta)
    }

    fn fst_add(&mut self, gs: u64, gl: u64, start: u64, len: u64) -> Result<i64> {
        let root = self.tree(FREE_SPACE_TREE)?;
        let (mut s, mut e) = (start, start + len);
        let mut delta = 1;
        if s > gs {
            let probe = Key::new(s - 1, K_FREE_SPACE_EXTENT, u64::MAX);
            if let Some((k, _)) = self.find_le(root, probe)? {
                if k.ty == K_FREE_SPACE_EXTENT && k.obj + k.off == s {
                    self.delete_item(FREE_SPACE_TREE, k)?;
                    s = k.obj;
                    delta -= 1;
                }
            }
        }
        if e < gs + gl {
            let root = self.tree(FREE_SPACE_TREE)?;
            let mut next = None;
            self.scan(root, Key::new(e, K_FREE_SPACE_EXTENT, 0), &mut |k, _| {
                if k.obj == e && k.ty == K_FREE_SPACE_EXTENT {
                    next = Some(k);
                }
                Ok(false)
            })?;
            if let Some(k) = next {
                self.delete_item(FREE_SPACE_TREE, k)?;
                e = k.obj + k.off;
                delta -= 1;
            }
        }
        self.insert_item(FREE_SPACE_TREE, Key::new(s, K_FREE_SPACE_EXTENT, e - s), &[])?;
        Ok(delta)
    }

    /// Rewrites a group stored as bitmaps into plain extents, the form edited here.
    fn fst_unbitmap(&mut self, gs: u64, gl: u64) -> Result<()> {
        let ss = self.sectorsize as u64;
        let root = self.tree(FREE_SPACE_TREE)?;
        let mut bitmaps: Vec<(Key, Vec<u8>)> = vec![];
        self.scan(root, Key::new(gs, K_FREE_SPACE_BITMAP, 0), &mut |k, d| {
            if k.obj >= gs + gl {
                return Ok(false);
            }
            if k.ty == K_FREE_SPACE_BITMAP {
                bitmaps.push((k, d.to_vec()));
            }
            Ok(true)
        })?;
        let mut free = BTreeMap::new();
        for (k, bits) in &bitmaps {
            for i in 0..k.off / ss {
                let (byte, bit) = ((i / 8) as usize, i % 8);
                if bits.get(byte).is_some_and(|b| b & (1 << bit) != 0) {
                    add_range(&mut free, k.obj + i * ss, ss);
                }
            }
        }
        for (k, _) in bitmaps {
            self.delete_item(FREE_SPACE_TREE, k)?;
        }
        let count = free.len() as u32;
        for (s, l) in free {
            self.insert_item(FREE_SPACE_TREE, Key::new(s, K_FREE_SPACE_EXTENT, l), &[])?;
        }
        self.update_item(FREE_SPACE_TREE, Key::new(gs, K_FREE_SPACE_INFO, gl), |d| {
            d.put_u32(0, count);
            d.put_u32(4, 0);
        })
    }

    /// Free areas of a device, from its dev extents.
    fn dev_holes(&self, devid: u64, total: u64) -> Result<Vec<(u64, u64)>> {
        let root = self.tree(DEV_TREE)?;
        let mut cursor = 1 << 20;
        let mut holes = vec![];
        self.scan(root, Key::new(devid, K_DEV_EXTENT, 0), &mut |k, d| {
            if k.obj != devid || k.ty != K_DEV_EXTENT {
                return Ok(false);
            }
            if k.off > cursor {
                holes.push((cursor, k.off - cursor));
            }
            cursor = cursor.max(k.off + d.u64_at(24));
            Ok(true)
        })?;
        if cursor < total {
            holes.push((cursor, total - cursor));
        }
        Ok(holes)
    }

    /// Creates a chunk in the same profile as existing ones of its type. Returns false
    /// when the devices have no room left.
    pub fn alloc_chunk(&mut self, ty: u64) -> Result<bool> {
        let Some(sample) = self.chunks.values().find(|c| c.ty & ty != 0) else {
            return bad("no chunk of this type to copy a profile from");
        };
        let profile = sample.ty & PROFILE_MASK;
        let (flags, stripe_len, sub) = (sample.ty, sample.stripe_len, sample.sub_stripes);
        let stripes_wanted = match profile {
            DUP | RAID1 => 2,
            RAID1C3 => 3,
            RAID1C4 => 4,
            RAID0 | RAID10 => sample.stripes.len(),
            0 => 1,
            _ => return Ok(false),
        };
        let total = self.sb.u64_at(0x70);
        let target: u64 = match ty {
            T_DATA => (1 << 30).min(total / 10),
            T_SYSTEM => (32 << 20).min(total / 50),
            _ => (256 << 20).min(total / 10),
        };
        // Largest hole on each present device.
        let root = self.chunk_tree;
        let mut devices: Vec<(u64, u64)> = vec![];
        self.scan(root, Key::new(1, K_DEV_ITEM, 0), &mut |k, d| {
            if k.ty != K_DEV_ITEM {
                return Ok(false);
            }
            devices.push((k.off, d.u64_at(8)));
            Ok(true)
        })?;
        let mut best: Vec<(u64, u64, u64)> = vec![];
        for (devid, size) in devices {
            if !self.devs.contains_key(&devid) {
                continue;
            }
            if let Some(h) = self.dev_holes(devid, size)?.into_iter().max_by_key(|h| h.1) {
                best.push((devid, h.0, h.1));
            }
        }
        best.sort_by_key(|b| std::cmp::Reverse(b.2));
        let mb = 1u64 << 20;
        let mut stripes: Vec<(u64, u64)> = vec![];
        let stripe_size;
        if profile == DUP {
            let Some(&(devid, at, len)) = best.first() else { return Ok(false) };
            stripe_size = target.min(len / 2) / mb * mb;
            stripes.push((devid, at));
            stripes.push((devid, at + stripe_size));
        } else {
            if best.len() < stripes_wanted {
                return Ok(false);
            }
            let holes = &best[..stripes_wanted];
            let smallest = holes.iter().map(|h| h.2).min().unwrap_or(0);
            let per = match profile {
                RAID0 => target / stripes_wanted as u64,
                RAID10 => target / (stripes_wanted as u64 / sub),
                _ => target,
            };
            stripe_size = per.min(smallest) / mb * mb;
            stripes.extend(holes.iter().map(|h| (h.0, h.1)));
        }
        if stripe_size < 4 * mb {
            return Ok(false);
        }
        let n = stripes.len() as u64;
        let logical_len = match profile {
            RAID0 => stripe_size * n,
            RAID10 => stripe_size * (n / sub),
            _ => stripe_size,
        };
        let start = self.chunks.values().map(|c| c.start + c.len).max().unwrap_or(1 << 20);

        let mut item = vec![0u8; 48 + stripes.len() * 32];
        item.put_u64(0, logical_len);
        item.put_u64(8, 2);
        item.put_u64(16, stripe_len);
        item.put_u64(24, flags);
        item.put_u32(32, stripe_len as u32);
        item.put_u32(36, stripe_len as u32);
        item.put_u32(40, self.sectorsize as u32);
        item.put_u16(44, stripes.len() as u16);
        item.put_u16(46, sub as u16);
        let mut uuids = vec![];
        for (i, (devid, phys)) in stripes.iter().enumerate() {
            let uuid = self.dev_uuid(*devid)?;
            let o = 48 + i * 32;
            item.put_u64(o, *devid);
            item.put_u64(o + 8, *phys);
            item[o + 16..o + 32].copy_from_slice(&uuid);
            uuids.push(uuid);
        }
        let key = Key::new(256, K_CHUNK_ITEM, start);
        self.insert_item(CHUNK_TREE, key, &item)?;
        if ty == T_SYSTEM {
            self.append_sys_chunk(key, &item)?;
        }
        let chunk_uuid = self.chunk_tree_uuid();
        for (devid, phys) in &stripes {
            let mut e = vec![0u8; 48];
            e.put_u64(0, CHUNK_TREE);
            e.put_u64(8, 256);
            e.put_u64(16, start);
            e.put_u64(24, stripe_size);
            e[32..48].copy_from_slice(&chunk_uuid);
            self.insert_item(DEV_TREE, Key::new(*devid, K_DEV_EXTENT, *phys), &e)?;
            self.update_item(CHUNK_TREE, Key::new(1, K_DEV_ITEM, *devid), |d| {
                let v = d.u64_at(16) + stripe_size;
                d.put_u64(16, v);
            })?;
        }
        let mut bg = vec![0u8; 24];
        bg.put_u64(8, 256);
        bg.put_u64(16, flags);
        self.insert_item(self.group_tree(), Key::new(start, K_BLOCK_GROUP_ITEM, logical_len), &bg)?;
        if self.fst_enabled() {
            let mut info = vec![0u8; 8];
            info.put_u32(0, 1);
            self.insert_item(FREE_SPACE_TREE, Key::new(start, K_FREE_SPACE_INFO, logical_len), &info)?;
            self.insert_item(FREE_SPACE_TREE, Key::new(start, K_FREE_SPACE_EXTENT, logical_len), &[])?;
        }
        let chunk = parse_chunk(start, &item)?;
        self.chunks.insert(start, chunk);
        let group = Group { start, len: logical_len, ty: flags, used: 0, free: None };
        let excluded = self.super_ranges(&group);
        let mut free = BTreeMap::new();
        free.insert(start, logical_len);
        for (s, l) in excluded {
            remove_range(&mut free, s, l);
        }
        self.alloc.groups.insert(start, Group { free: Some(free), ..group });
        self.notes.dedup();
        Ok(true)
    }

    fn dev_uuid(&self, devid: u64) -> Result<[u8; 16]> {
        let Some(d) = self.get(self.chunk_tree, Key::new(1, K_DEV_ITEM, devid))? else {
            return bad("device item missing");
        };
        let mut u = [0u8; 16];
        u.copy_from_slice(&d[66..82]);
        Ok(u)
    }

    fn append_sys_chunk(&mut self, key: Key, item: &[u8]) -> Result<()> {
        let size = self.sb.u32_at(0xA0) as usize;
        let need = 17 + item.len();
        if size + need > 2048 {
            return Err(FsError::NoSpace);
        }
        let o = 0x32B + size;
        self.sb.put_u64(o, key.obj);
        self.sb.put_u8(o + 8, key.ty);
        self.sb.put_u64(o + 9, key.off);
        self.sb[o + 17..o + need].copy_from_slice(item);
        self.sb.put_u32(0xA0, (size + need) as u32);
        Ok(())
    }
}
