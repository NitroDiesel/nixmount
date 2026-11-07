//! The transaction commit: the only moment anything becomes visible on disk.
use crate::mount::{RO_FREE_SPACE_TREE, SB_OFFSETS, SB_SIZE};
use crate::refs::Delayed;
use crate::tree::generation;
use crate::*;
use fscore::{Le, LeMut};
use std::collections::HashSet;

/// Node count at which a transaction commits on its own, bounding memory use.
const COMMIT_NODES: usize = 8192;

/// In-flight changes.
#[derive(Default)]
pub struct Txn {
    pub gen: u64,
    /// Tree blocks created in this transaction; these alone may be edited in place.
    pub nodes: HashMap<u64, Arc<[u8]>>,
    /// Current roots of trees changed in this transaction.
    pub roots: HashMap<u64, Root>,
    /// Roots already written into their root items.
    pub written: HashMap<u64, Root>,
    pub delayed: Vec<Delayed>,
    pub delta: HashMap<u64, i64>,
    pub full_backref: HashSet<u64>,
    /// Data was written, so a commit is needed even if no tree changed yet.
    pub touched: bool,
}

impl Fs {
    pub fn txn_node(&self, logical: u64) -> Option<Arc<[u8]>> {
        self.txn.nodes.get(&logical).cloned()
    }

    pub fn txn_root(&self, id: u64) -> Option<Root> {
        match id {
            ROOT_TREE => Some(self.root_tree),
            CHUNK_TREE => Some(self.chunk_tree),
            _ => self.txn.roots.get(&id).copied(),
        }
    }

    pub fn tree_for_write(&self, id: u64) -> Result<Root> {
        self.tree(id)
    }

    pub fn set_root(&mut self, id: u64, r: Root) {
        self.txn.touched = true;
        match id {
            ROOT_TREE => self.root_tree = r,
            CHUNK_TREE => self.chunk_tree = r,
            _ => {
                self.txn.roots.insert(id, r);
            }
        }
    }

    pub fn chunk_tree_uuid(&self) -> [u8; 16] {
        let mut u = [0u8; 16];
        if let Ok(b) = self.node(self.chunk_tree.bytenr, None) {
            u.copy_from_slice(&b[0x40..0x50]);
        }
        u
    }

    /// Writes each changed tree's location into its root item.
    fn flush_root_items(&mut self) -> Result<bool> {
        let pending: Vec<(u64, Root)> = self
            .txn
            .roots
            .iter()
            .filter(|(id, r)| self.txn.written.get(id) != Some(r))
            .map(|(id, r)| (*id, *r))
            .collect();
        let any = !pending.is_empty();
        let gen = self.txn.gen;
        let now = fscore::Time::now();
        for (id, r) in pending {
            let (key, _) = self.root_item(id)?;
            self.update_item(ROOT_TREE, key, |d| {
                d.put_u64(160, gen);
                d.put_u64(176, r.bytenr);
                d.put_u8(238, r.level);
                d.put_u64(239, gen);
                if id == FS_TREE || id >= FIRST_FREE {
                    d.put_u64(295, gen);
                    inode::put_time(d, 327, now);
                }
            })?;
            self.txn.written.insert(id, r);
        }
        Ok(any)
    }

    fn has_changes(&self) -> bool {
        self.txn.touched || !self.txn.nodes.is_empty() || !self.txn.delayed.is_empty()
    }

    /// Lands the transaction: new blocks first, then a barrier, then the superblocks that
    /// point at them. Power loss at any step leaves the previous transaction intact.
    pub fn commit(&mut self) -> Result<()> {
        if self.read_only || !self.has_changes() {
            return Ok(());
        }
        let r = self.commit_inner();
        if let Err(e) = &r {
            self.abort(e);
        }
        r
    }

    fn commit_inner(&mut self) -> Result<()> {
        // Editing the bookkeeping trees creates more bookkeeping: run until it settles.
        for _ in 0..64 {
            self.run_delayed()?;
            let a = self.flush_free_space()?;
            let b = self.flush_group_items()?;
            let c = self.flush_root_items()?;
            if !a && !b && !c && self.txn.delayed.is_empty() {
                return self.write_out();
            }
        }
        bad("transaction did not settle")
    }

    fn write_out(&mut self) -> Result<()> {
        let gen = self.txn.gen;
        let nodes: Vec<(u64, Arc<[u8]>)> = self.txn.nodes.drain().collect();
        let mut done = Vec::with_capacity(nodes.len());
        for (logical, b) in nodes {
            let mut v = b.to_vec();
            debug_assert_eq!(generation(&v), gen);
            let flags = v.u64_at(0x38) | 1;
            v.put_u64(0x38, flags);
            let c = self.csum(&v[0x20..]);
            v[..self.csum_size].copy_from_slice(&c[..self.csum_size]);
            self.write_logical(logical, &v)?;
            done.push((logical, v));
        }
        for d in self.devs.values() {
            d.flush()?;
        }
        self.sb.put_u64(0x48, gen);
        self.sb.put_u64(0x50, self.root_tree.bytenr);
        self.sb.put_u8(0xC6, self.root_tree.level);
        self.sb.put_u64(0x58, self.chunk_tree.bytenr);
        self.sb.put_u8(0xC7, self.chunk_tree.level);
        self.sb.put_u64(0xA4, gen);
        if self.compat_ro & RO_FREE_SPACE_TREE != 0 {
            self.sb.put_u64(0x22B, gen);
        } else {
            // Invalidates a v1 cache, which isn't maintained here.
            self.sb.put_u64(0x22B, u64::MAX);
        }
        self.sb.put_u64(0x233, gen);
        self.write_supers()?;
        for (logical, v) in done {
            self.cache.insert(logical, v.into());
        }
        self.release_pending();
        self.alloc.committed_extents = Some(self.tree(EXTENT_TREE)?);
        self.txn = Txn { gen: gen + 1, ..Txn::default() };
        Ok(())
    }

    fn write_supers(&mut self) -> Result<()> {
        // Secondary copies first, so the primary only changes once they are safe.
        let ids: Vec<u64> = self.devs.keys().copied().collect();
        for pass in [true, false] {
            for &id in &ids {
                let Some(item) = self.get(self.chunk_tree, Key::new(1, K_DEV_ITEM, id))? else {
                    return bad("device item missing");
                };
                let dev = self.devs[&id].clone();
                for at in SB_OFFSETS {
                    if (at == SB_OFFSETS[0]) == pass || at + SB_SIZE as u64 > dev.len() {
                        continue;
                    }
                    let mut b = self.sb.clone();
                    b[0xC9..0xC9 + 98].copy_from_slice(&item[..98]);
                    b.put_u64(0x30, at);
                    let c = self.csum(&b[0x20..SB_SIZE]);
                    b[..self.csum_size].copy_from_slice(&c[..self.csum_size]);
                    dev.write_at(at, &b)?;
                }
                dev.flush()?;
            }
        }
        Ok(())
    }

    /// Commits if the transaction has grown large.
    pub fn maybe_commit(&mut self) -> Result<()> {
        if self.txn.nodes.len() >= COMMIT_NODES {
            self.commit()?;
        }
        Ok(())
    }

    /// Gives up on the transaction after an internal failure. Nothing it did has been
    /// published, so the volume stays exactly as of the last commit.
    pub fn abort(&mut self, why: &FsError) {
        self.read_only = true;
        self.ro_reasons.push(format!("switched to read-only after an error: {why}"));
        self.txn = Txn::default();
        self.cache.clear();
        let sb = &self.sb;
        self.root_tree = Root { bytenr: sb.u64_at(0x50), level: sb.u8_at(0xC6) };
        self.chunk_tree = Root { bytenr: sb.u64_at(0x58), level: sb.u8_at(0xC7) };
    }
}
