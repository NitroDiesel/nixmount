//! Reading B-trees. Every node is checksum-verified and structurally validated before
//! any field in it is used.
use crate::{bad, Fs, Key, Root};
use fscore::{FsError, Le, Result};
use std::sync::Arc;

pub const HDR: usize = 0x65;
pub const LEAF_ITEM: usize = 25;
pub const KEY_PTR: usize = 33;

pub fn nritems(b: &[u8]) -> usize {
    b.u32_at(0x60) as usize
}
pub fn level(b: &[u8]) -> u8 {
    b.u8_at(0x64)
}
pub fn owner(b: &[u8]) -> u64 {
    b.u64_at(0x58)
}
pub fn generation(b: &[u8]) -> u64 {
    b.u64_at(0x50)
}

pub fn key_at(b: &[u8], o: usize) -> Key {
    Key { obj: b.u64_at(o), ty: b.u8_at(o + 8), off: b.u64_at(o + 9) }
}

pub fn item_key(b: &[u8], i: usize) -> Key {
    key_at(b, HDR + i * LEAF_ITEM)
}

/// Byte range of a leaf item's data within the node.
pub fn item_range(b: &[u8], i: usize) -> std::ops::Range<usize> {
    let o = HDR + i * LEAF_ITEM;
    let (off, size) = (b.u32_at(o + 17) as usize, b.u32_at(o + 21) as usize);
    HDR + off..HDR + off + size
}

pub fn item_data(b: &[u8], i: usize) -> &[u8] {
    &b[item_range(b, i)]
}

pub fn node_key(b: &[u8], i: usize) -> Key {
    key_at(b, HDR + i * KEY_PTR)
}

pub fn node_ptr(b: &[u8], i: usize) -> u64 {
    b.u64_at(HDR + i * KEY_PTR + 17)
}

/// Rejects a node whose structure could mislead later reads.
pub fn validate(b: &[u8], nodesize: usize) -> Result<()> {
    let n = nritems(b);
    if level(b) > 0 {
        if HDR + n * KEY_PTR > nodesize {
            return bad("too many pointers in node");
        }
        for i in 1..n {
            if node_key(b, i - 1) >= node_key(b, i) {
                return bad("node keys out of order");
            }
        }
        return Ok(());
    }
    if HDR + n * LEAF_ITEM > nodesize {
        return bad("too many items in leaf");
    }
    let mut prev_end = nodesize - HDR;
    for i in 0..n {
        let o = HDR + i * LEAF_ITEM;
        let (off, size) = (b.u32_at(o + 17) as usize, b.u32_at(o + 21) as usize);
        if off + size != prev_end || off < n * LEAF_ITEM {
            return bad("leaf item data overlaps");
        }
        prev_end = off;
        if i > 0 && item_key(b, i - 1) >= item_key(b, i) {
            return bad("leaf keys out of order");
        }
    }
    Ok(())
}

/// A position in a tree: one (node, slot) per level, root first, leaf last.
pub struct Path {
    pub nodes: Vec<(Arc<[u8]>, usize)>,
}

impl Path {
    pub fn leaf(&self) -> &[u8] {
        &self.nodes[self.nodes.len() - 1].0
    }
    pub fn slot(&self) -> usize {
        self.nodes[self.nodes.len() - 1].1
    }
    pub fn key(&self) -> Option<Key> {
        (self.slot() < nritems(self.leaf())).then(|| item_key(self.leaf(), self.slot()))
    }
    pub fn data(&self) -> &[u8] {
        item_data(self.leaf(), self.slot())
    }
}

impl Fs {
    /// Fetches and verifies a tree block.
    pub fn node(&self, logical: u64, want_level: Option<u8>) -> Result<Arc<[u8]>> {
        let b = if let Some(b) = self.txn_node(logical) {
            b
        } else if let Some(b) = self.cache.get(logical) {
            b
        } else {
            let mut v = vec![0u8; self.nodesize];
            let check = |b: &[u8]| {
                b.u64_at(0x30) == logical
                    && b[0x20..0x30] == self.fsid
                    && self.csum_matches(&b[0x20..], &b[..self.csum_size])
            };
            self.read_verified(logical, &mut v, &check)?;
            validate(&v, self.nodesize)?;
            let b: Arc<[u8]> = v.into();
            self.cache.insert(logical, b.clone());
            b
        };
        if want_level.is_some_and(|l| l != level(&b)) {
            return bad(format!("tree block {logical:#x} has the wrong level"));
        }
        Ok(b)
    }

    /// Finds the first item with key `>= key`.
    pub fn search(&self, root: Root, key: Key) -> Result<Path> {
        let mut nodes = vec![];
        let mut cur = self.node(root.bytenr, Some(root.level))?;
        for lvl in (0..=root.level).rev() {
            let n = nritems(&cur);
            if lvl == 0 {
                let (mut lo, mut hi) = (0, n);
                while lo < hi {
                    let mid = (lo + hi) / 2;
                    if item_key(&cur, mid) < key {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                nodes.push((cur.clone(), lo));
                break;
            }
            if n == 0 {
                return bad("empty interior node");
            }
            // The last child whose first key is <= key.
            let (mut lo, mut hi) = (0, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if node_key(&cur, mid) <= key {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let slot = lo.saturating_sub(1);
            let child = self.node(node_ptr(&cur, slot), Some(lvl - 1))?;
            nodes.push((cur, slot));
            cur = child;
        }
        let mut p = Path { nodes };
        if p.slot() >= nritems(p.leaf()) {
            self.next_leaf(&mut p)?;
        }
        Ok(p)
    }

    /// Moves to the following leaf. At the end of the tree the path stays past-the-end.
    fn next_leaf(&self, p: &mut Path) -> Result<bool> {
        let depth = p.nodes.len();
        for up in (0..depth.saturating_sub(1)).rev() {
            let (node, slot) = &p.nodes[up];
            if slot + 1 < nritems(node) {
                let start = slot + 1;
                p.nodes[up].1 = start;
                for d in up..depth - 1 {
                    let (n, s) = &p.nodes[d];
                    let lvl = level(n) - 1;
                    let child = self.node(node_ptr(n, *s), Some(lvl))?;
                    p.nodes[d + 1] = (child, 0);
                }
                return Ok(true);
            }
        }
        let n = nritems(p.leaf());
        let last = depth - 1;
        p.nodes[last].1 = n;
        Ok(false)
    }

    pub fn advance(&self, p: &mut Path) -> Result<bool> {
        let last = p.nodes.len() - 1;
        p.nodes[last].1 += 1;
        if p.slot() < nritems(p.leaf()) {
            return Ok(true);
        }
        self.next_leaf(p)
    }

    /// Exact-match lookup.
    pub fn get(&self, root: Root, key: Key) -> Result<Option<Vec<u8>>> {
        let p = self.search(root, key)?;
        Ok((p.key() == Some(key)).then(|| p.data().to_vec()))
    }

    /// Visits items from `start`, ascending, until `f` returns false.
    pub fn scan(&self, root: Root, start: Key, f: &mut dyn FnMut(Key, &[u8]) -> Result<bool>) -> Result<()> {
        let mut p = self.search(root, start)?;
        while let Some(k) = p.key() {
            if !f(k, p.data())? || !self.advance(&mut p)? {
                break;
            }
        }
        Ok(())
    }

    /// Last item with key `<= key`, searching back across leaves if needed.
    pub fn find_le(&self, root: Root, key: Key) -> Result<Option<(Key, Vec<u8>)>> {
        let p = self.search(root, key)?;
        if p.key() == Some(key) {
            return Ok(Some((key, p.data().to_vec())));
        }
        let last = p.nodes.len() - 1;
        if p.slot() > 0 && p.slot() <= nritems(p.leaf()) {
            let i = p.slot() - 1;
            return Ok(Some((item_key(p.leaf(), i), item_data(p.leaf(), i).to_vec())));
        }
        // `key` sorts before everything in this leaf: step to the previous leaf.
        for up in (0..last).rev() {
            let (node, slot) = &p.nodes[up];
            if *slot > 0 {
                let mut cur = self.node(node_ptr(node, slot - 1), Some(level(node) - 1))?;
                while level(&cur) > 0 {
                    let i = nritems(&cur).saturating_sub(1);
                    cur = self.node(node_ptr(&cur, i), Some(level(&cur) - 1))?;
                }
                let n = nritems(&cur);
                return Ok((n > 0).then(|| (item_key(&cur, n - 1), item_data(&cur, n - 1).to_vec())));
            }
        }
        Ok(None)
    }

    /// Reads a root item's tree location by subvolume id.
    pub fn root_item(&self, id: u64) -> Result<(Key, Vec<u8>)> {
        let mut out = None;
        let start = Key { obj: id, ty: crate::K_ROOT_ITEM, off: 0 };
        self.scan(self.root_tree, start, &mut |k, d| {
            if k.obj == id && k.ty == crate::K_ROOT_ITEM {
                out = Some((k, d.to_vec()));
            }
            Ok(false)
        })?;
        out.ok_or(FsError::NotFound)
    }

    /// Current root of tree `id`, seeing uncommitted changes.
    pub fn tree(&self, id: u64) -> Result<Root> {
        if let Some(r) = self.txn_root(id) {
            return Ok(r);
        }
        let (_, item) = self.root_item(id)?;
        Ok(Root { bytenr: item.u64_at(176), level: item.u8_at(238) })
    }
}
