//! A two-generation cache: O(1) operations with LRU-like behaviour and no unsafe.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct Gens {
    hot: HashMap<u64, Arc<[u8]>>,
    cold: HashMap<u64, Arc<[u8]>>,
}

/// Bounded block cache keyed by address. When the hot generation fills it becomes the
/// cold one and the old cold generation is dropped; a hit in cold promotes the entry.
pub struct BlockCache {
    gens: Mutex<Gens>,
    per_gen: usize,
}

impl BlockCache {
    /// `bytes` is the total budget, `item` the typical entry size.
    pub fn new(bytes: usize, item: usize) -> Self {
        let per_gen = (bytes / item.max(1) / 2).max(16);
        BlockCache { gens: Mutex::new(Gens { hot: HashMap::new(), cold: HashMap::new() }), per_gen }
    }

    pub fn get(&self, k: u64) -> Option<Arc<[u8]>> {
        let mut g = self.gens.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = g.hot.get(&k) {
            return Some(v.clone());
        }
        let v = g.cold.remove(&k)?;
        self.put(&mut g, k, v.clone());
        Some(v)
    }

    pub fn insert(&self, k: u64, v: Arc<[u8]>) {
        let mut g = self.gens.lock().unwrap_or_else(|e| e.into_inner());
        g.cold.remove(&k);
        self.put(&mut g, k, v);
    }

    pub fn remove(&self, k: u64) {
        let mut g = self.gens.lock().unwrap_or_else(|e| e.into_inner());
        g.hot.remove(&k);
        g.cold.remove(&k);
    }

    pub fn clear(&self) {
        let mut g = self.gens.lock().unwrap_or_else(|e| e.into_inner());
        g.hot.clear();
        g.cold.clear();
    }

    fn put(&self, g: &mut Gens, k: u64, v: Arc<[u8]>) {
        if g.hot.len() >= self.per_gen {
            g.cold = std::mem::take(&mut g.hot);
        }
        g.hot.insert(k, v);
    }
}
