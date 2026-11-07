//! Modifying B-trees. Blocks reachable from the last commit are never written: the first
//! change to one copies it to a new address, and the copy is then edited in place until
//! the transaction commits.
use crate::tree::*;
use crate::*;
use fscore::{Le, LeMut};

/// Flags value for a current-format tree block (mixed backrefs, revision 1).
const HEADER_FLAGS: u64 = 1 << 56;

/// Positions from root to leaf. Every block on it is writable in this transaction.
struct MutPath {
    nodes: Vec<(u64, usize)>,
}

impl Fs {
    fn max_ptrs(&self) -> usize {
        (self.nodesize - HDR) / KEY_PTR
    }

    fn leaf_data_size(&self) -> usize {
        self.nodesize - HDR
    }

    fn leaf_free(&self, b: &[u8]) -> usize {
        let n = nritems(b);
        let used: usize = (0..n).map(|i| LEAF_ITEM + item_range(b, i).len()).sum();
        self.leaf_data_size().saturating_sub(used)
    }

    /// Writable view of a block owned by this transaction.
    fn edit(&mut self, logical: u64) -> Result<&mut [u8]> {
        let b = self.txn.nodes.get_mut(&logical).ok_or_else(|| FsError::Corrupt("edit of a clean block".into()))?;
        Ok(Arc::make_mut(b))
    }

    fn new_block(&mut self, tree: u64, level: u8) -> Result<u64> {
        let logical = self.alloc_tree_block(tree)?;
        let mut b = vec![0u8; self.nodesize];
        b[0x20..0x30].copy_from_slice(&self.fsid);
        b.put_u64(0x30, logical);
        b.put_u64(0x38, HEADER_FLAGS);
        let chunk_uuid = self.chunk_tree_uuid();
        b[0x40..0x50].copy_from_slice(&chunk_uuid);
        b.put_u64(0x50, self.txn.gen);
        b.put_u64(0x58, tree);
        b.put_u8(0x64, level);
        self.txn.nodes.insert(logical, b.into());
        self.queue_new_tree_block(logical, tree, level);
        Ok(logical)
    }

    /// Returns a writable copy of `logical`, which the caller must link in.
    fn cow(&mut self, tree: u64, logical: u64, level: u8) -> Result<u64> {
        if self.txn.nodes.contains_key(&logical) {
            return Ok(logical);
        }
        let old = self.node(logical, Some(level))?;
        let new = self.new_block(tree, level)?;
        self.update_refs_for_cow(tree, &old, new)?;
        let header_flags = old.u64_at(0x38) & !1;
        let dst = self.edit(new)?;
        let keep_new = dst[..0x65].to_vec();
        dst.copy_from_slice(&old);
        dst[..0x60].copy_from_slice(&keep_new[..0x60]);
        dst.put_u64(0x38, header_flags & !2 | HEADER_FLAGS);
        self.cache.remove(logical);
        Ok(new)
    }

    pub fn cow_root(&mut self, tree: u64) -> Result<Root> {
        let r = self.tree_for_write(tree)?;
        let new = self.cow(tree, r.bytenr, r.level)?;
        let root = Root { bytenr: new, level: r.level };
        self.set_root(tree, root);
        Ok(root)
    }

    fn set_ptr(&mut self, parent: u64, slot: usize, child: u64) -> Result<()> {
        let gen = self.txn.gen;
        let b = self.edit(parent)?;
        b.put_u64(HDR + slot * KEY_PTR + 17, child);
        b.put_u64(HDR + slot * KEY_PTR + 25, gen);
        Ok(())
    }

    fn put_key(b: &mut [u8], o: usize, k: Key) {
        b.put_u64(o, k.obj);
        b.put_u8(o + 8, k.ty);
        b.put_u64(o + 9, k.off);
    }

    /// Adds a level above the current root.
    fn grow_root(&mut self, tree: u64, root: Root) -> Result<Root> {
        let child = self.node(root.bytenr, Some(root.level))?;
        let first = if root.level == 0 { item_key(&child, 0) } else { node_key(&child, 0) };
        let new = self.new_block(tree, root.level + 1)?;
        let gen = self.txn.gen;
        let b = self.edit(new)?;
        b.put_u32(0x60, 1);
        Self::put_key(b, HDR, first);
        b.put_u64(HDR + 17, root.bytenr);
        b.put_u64(HDR + 25, gen);
        let r = Root { bytenr: new, level: root.level + 1 };
        self.set_root(tree, r);
        Ok(r)
    }

    /// Moves the upper half of interior node `n` into a new sibling linked after it.
    fn split_node(&mut self, tree: u64, parent: u64, pslot: usize, n: u64) -> Result<u64> {
        let b = self.txn.nodes[&n].to_vec();
        let count = nritems(&b);
        let mid = count / 2;
        let lvl = level(&b);
        let right = self.new_block(tree, lvl)?;
        let moved = &b[HDR + mid * KEY_PTR..HDR + count * KEY_PTR];
        let first = key_at(moved, 0);
        let r = self.edit(right)?;
        r[HDR..HDR + moved.len()].copy_from_slice(moved);
        r.put_u32(0x60, (count - mid) as u32);
        self.edit(n)?.put_u32(0x60, mid as u32);
        self.insert_ptr(parent, pslot + 1, first, right)?;
        Ok(right)
    }

    fn insert_ptr(&mut self, parent: u64, slot: usize, key: Key, child: u64) -> Result<()> {
        let gen = self.txn.gen;
        let max = self.max_ptrs();
        let b = self.edit(parent)?;
        let n = nritems(b);
        if n >= max {
            return bad("node overflow");
        }
        b.copy_within(HDR + slot * KEY_PTR..HDR + n * KEY_PTR, HDR + (slot + 1) * KEY_PTR);
        let o = HDR + slot * KEY_PTR;
        Self::put_key(b, o, key);
        b.put_u64(o + 17, child);
        b.put_u64(o + 25, gen);
        b.put_u32(0x60, n as u32 + 1);
        Ok(())
    }

    /// Descends to `key`, copying blocks on the way. With `need > 0` it guarantees that
    /// much free space in the final leaf, splitting preemptively so that a split can
    /// never have to propagate up through a full node.
    fn descend(&mut self, tree: u64, key: Key, need: usize) -> Result<(MutPath, bool)> {
        if need + LEAF_ITEM > self.leaf_data_size() {
            return bad("item larger than a leaf");
        }
        'retry: loop {
            let mut root = self.cow_root(tree)?;
            if root.level > 0 && need > 0 && nritems(&self.txn.nodes[&root.bytenr]) + 2 >= self.max_ptrs() {
                root = self.grow_root(tree, root)?;
            }
            let mut nodes: Vec<(u64, usize)> = vec![];
            let mut cur = root.bytenr;
            for lvl in (1..=root.level).rev() {
                let b = &self.txn.nodes[&cur];
                let n = nritems(b);
                if n == 0 {
                    return bad("empty interior node");
                }
                let slot = (0..n).rev().find(|i| node_key(b, *i) <= key).unwrap_or(0);
                let child = node_ptr(b, slot);
                let copied = self.cow(tree, child, lvl - 1)?;
                if copied != child {
                    self.set_ptr(cur, slot, copied)?;
                }
                if need > 0 && lvl > 1 && nritems(&self.txn.nodes[&copied]) + 2 >= self.max_ptrs() {
                    self.split_node(tree, cur, slot, copied)?;
                    continue 'retry;
                }
                nodes.push((cur, slot));
                cur = copied;
            }
            let b = &self.txn.nodes[&cur];
            let n = nritems(b);
            let (mut lo, mut hi) = (0, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if item_key(b, mid) < key {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let found = lo < n && item_key(b, lo) == key;
            if need > 0 && !found && self.leaf_free(b) < need + LEAF_ITEM {
                if root.level == 0 {
                    self.grow_root(tree, root)?;
                    continue 'retry;
                }
                let (parent, pslot) = nodes[nodes.len() - 1];
                self.split_leaf(tree, parent, pslot, cur, lo, key)?;
                continue 'retry;
            }
            nodes.push((cur, lo));
            return Ok((MutPath { nodes }, found));
        }
    }

    /// Splits leaf `n`, keeping `slot`'s side lighter so the pending insert will fit.
    fn split_leaf(&mut self, tree: u64, parent: u64, pslot: usize, n: u64, slot: usize, key: Key) -> Result<()> {
        let b = self.txn.nodes[&n].to_vec();
        let count = nritems(&b);
        let mut mid = count / 2;
        if slot >= count {
            mid = count;
        } else if slot == 0 {
            mid = 0;
        } else {
            let half = self.leaf_data_size() / 2;
            let mut acc = 0;
            for i in 0..count {
                acc += LEAF_ITEM + item_range(&b, i).len();
                if acc >= half {
                    mid = (i + 1).clamp(1, count - 1);
                    break;
                }
            }
        }
        let right = self.new_block(tree, 0)?;
        let mut rb = self.txn.nodes[&right].to_vec();
        let mut lb = b.clone();
        rebuild_leaf(&b, mid..count, &mut rb);
        rebuild_leaf(&b, 0..mid, &mut lb);
        let first = if mid < count { item_key(&b, mid) } else { key };
        self.txn.nodes.insert(right, rb.into());
        self.txn.nodes.insert(n, lb.into());
        // An empty right leaf is indexed by the key about to land in it.
        self.insert_ptr(parent, pslot + 1, first, right)
    }

    /// Pushes a leaf's or node's new first key up through its ancestors.
    fn fix_keys(&mut self, path: &MutPath, key: Key) -> Result<()> {
        for &(n, slot) in path.nodes.iter().rev().skip(1) {
            let b = self.edit(n)?;
            Self::put_key(b, HDR + slot * KEY_PTR, key);
            if slot != 0 {
                break;
            }
        }
        Ok(())
    }

    /// Inserts an item. The key must not exist.
    pub fn insert_item(&mut self, tree: u64, key: Key, data: &[u8]) -> Result<()> {
        let (path, found) = self.descend(tree, key, data.len())?;
        if found {
            return bad(format!("duplicate key {key:?} in tree {tree}"));
        }
        let (leaf, slot) = path.nodes[path.nodes.len() - 1];
        let data_end = self.leaf_data_size();
        let b = self.edit(leaf)?;
        let n = nritems(b);
        let low = (0..n).map(|i| b.u32_at(HDR + i * LEAF_ITEM + 17) as usize).min().unwrap_or(data_end);
        let tail_off = if slot == 0 { data_end } else { b.u32_at(HDR + (slot - 1) * LEAF_ITEM + 17) as usize };
        // Item data grows down from the end: shift everything after this slot's position.
        let new_off = tail_off - data.len();
        if low < tail_off {
            b.copy_within(HDR + low..HDR + tail_off, HDR + low - data.len());
        }
        for i in slot..n {
            let o = HDR + i * LEAF_ITEM + 17;
            let v = b.u32_at(o) - data.len() as u32;
            b.put_u32(o, v);
        }
        b.copy_within(HDR + slot * LEAF_ITEM..HDR + n * LEAF_ITEM, HDR + (slot + 1) * LEAF_ITEM);
        let o = HDR + slot * LEAF_ITEM;
        Self::put_key(b, o, key);
        b.put_u32(o + 17, new_off as u32);
        b.put_u32(o + 21, data.len() as u32);
        b[HDR + new_off..HDR + new_off + data.len()].copy_from_slice(data);
        b.put_u32(0x60, n as u32 + 1);
        if slot == 0 {
            self.fix_keys(&path, key)?;
        }
        Ok(())
    }

    /// Removes an item, which must exist.
    pub fn delete_item(&mut self, tree: u64, key: Key) -> Result<()> {
        let (path, found) = self.descend(tree, key, 0)?;
        if !found {
            return bad(format!("missing key {key:?} in tree {tree}"));
        }
        let (leaf, slot) = path.nodes[path.nodes.len() - 1];
        let b = self.edit(leaf)?;
        let n = nritems(b);
        let r = item_range(b, slot);
        let size = r.len();
        let low = (0..n).map(|i| b.u32_at(HDR + i * LEAF_ITEM + 17) as usize).min().unwrap_or(0);
        b.copy_within(HDR + low..r.start, HDR + low + size);
        b.copy_within(HDR + (slot + 1) * LEAF_ITEM..HDR + n * LEAF_ITEM, HDR + slot * LEAF_ITEM);
        for i in slot..n - 1 {
            let o = HDR + i * LEAF_ITEM + 17;
            let v = b.u32_at(o) + size as u32;
            b.put_u32(o, v);
        }
        b.put_u32(0x60, n as u32 - 1);
        if n == 1 {
            if path.nodes.len() > 1 {
                return self.unlink_empty(tree, &path);
            }
            return Ok(());
        }
        if slot == 0 {
            let first = item_key(&self.txn.nodes[&leaf], 0);
            self.fix_keys(&path, first)?;
        }
        Ok(())
    }

    /// Detaches an empty leaf, and any interior node that empties as a result.
    fn unlink_empty(&mut self, tree: u64, path: &MutPath) -> Result<()> {
        let mut depth = path.nodes.len() - 1;
        loop {
            let (victim, _) = path.nodes[depth];
            let lvl = level(&self.txn.nodes[&victim]);
            self.drop_tree_block(tree, victim, lvl);
            depth -= 1;
            let (parent, slot) = path.nodes[depth];
            let b = self.edit(parent)?;
            let n = nritems(b);
            b.copy_within(HDR + (slot + 1) * KEY_PTR..HDR + n * KEY_PTR, HDR + slot * KEY_PTR);
            b.put_u32(0x60, n as u32 - 1);
            if n > 1 {
                if slot == 0 {
                    let first = node_key(b, 0);
                    let up = MutPath { nodes: path.nodes[..=depth].to_vec() };
                    self.fix_keys(&up, first)?;
                }
                return self.collapse_root(tree);
            }
            if depth == 0 {
                // The whole tree emptied: the root becomes an empty leaf.
                let b = self.edit(parent)?;
                b.put_u8(0x64, 0);
                self.set_root(tree, Root { bytenr: parent, level: 0 });
                return Ok(());
            }
        }
    }

    /// Replaces a root with a single child by that child.
    fn collapse_root(&mut self, tree: u64) -> Result<()> {
        loop {
            let r = self.tree_for_write(tree)?;
            if r.level == 0 {
                return Ok(());
            }
            let Some(b) = self.txn.nodes.get(&r.bytenr) else { return Ok(()) };
            if nritems(b) != 1 {
                return Ok(());
            }
            let child = node_ptr(b, 0);
            let copied = self.cow(tree, child, r.level - 1)?;
            self.drop_tree_block(tree, r.bytenr, r.level);
            self.set_root(tree, Root { bytenr: copied, level: r.level - 1 });
        }
    }

    /// Edits an item's bytes without changing its size.
    pub fn update_item(&mut self, tree: u64, key: Key, f: impl FnOnce(&mut [u8])) -> Result<()> {
        let (path, found) = self.descend(tree, key, 0)?;
        if !found {
            return bad(format!("missing key {key:?} in tree {tree}"));
        }
        let (leaf, slot) = path.nodes[path.nodes.len() - 1];
        let b = self.edit(leaf)?;
        let r = item_range(b, slot);
        f(&mut b[r]);
        Ok(())
    }

    /// Replaces an item's contents, inserting it if absent.
    pub fn put_item(&mut self, tree: u64, key: Key, data: &[u8]) -> Result<()> {
        let root = self.tree_for_write(tree)?;
        match self.get(root, key)? {
            Some(old) if old.len() == data.len() => self.update_item(tree, key, |d| d.copy_from_slice(data)),
            Some(_) => {
                self.delete_item(tree, key)?;
                self.insert_item(tree, key, data)
            }
            None => self.insert_item(tree, key, data),
        }
    }
}

/// Packs the items in `range` of `src` into `dst`, which keeps its header.
fn rebuild_leaf(src: &[u8], range: std::ops::Range<usize>, dst: &mut [u8]) {
    let mut end = dst.len() - HDR;
    let items: Vec<(Key, Vec<u8>)> = range.map(|i| (item_key(src, i), item_data(src, i).to_vec())).collect();
    dst[HDR..].fill(0);
    for (i, (k, d)) in items.iter().enumerate() {
        end -= d.len();
        let o = HDR + i * LEAF_ITEM;
        Fs::put_key(dst, o, *k);
        dst.put_u32(o + 17, end as u32);
        dst.put_u32(o + 21, d.len() as u32);
        dst[HDR + end..HDR + end + d.len()].copy_from_slice(d);
    }
    dst.put_u32(0x60, items.len() as u32);
}

impl Fs {
    /// Starts a new tree with an empty leaf as its root.
    pub fn new_leaf_block(&mut self, tree: u64) -> Result<u64> {
        self.new_block(tree, 0)
    }

    /// Readies a tree's root for snapshotting: a block owned by this transaction.
    pub fn cow_root_for_snapshot(&mut self, tree: u64) -> Result<Root> {
        self.cow_root(tree)
    }

    /// Copies a root block under a new tree id, as the root of a snapshot.
    pub fn copy_root(&mut self, tree: u64, src: Root) -> Result<Root> {
        let body = self.node(src.bytenr, Some(src.level))?;
        let new = self.new_block(tree, src.level)?;
        let dst = self.edit(new)?;
        let keep = dst[..0x60].to_vec();
        dst.copy_from_slice(&body);
        dst[..0x60].copy_from_slice(&keep);
        let r = Root { bytenr: new, level: src.level };
        self.set_root(tree, r);
        Ok(r)
    }
}
