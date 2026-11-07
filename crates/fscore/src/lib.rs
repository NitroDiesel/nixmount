//! Shared foundations for the filesystem engines: the [`BlockDev`] abstraction,
//! the [`Filesystem`] contract, partition/filesystem detection and small helpers.
#![forbid(unsafe_code)]

pub mod cache;
pub mod dev;
pub mod part;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod vfs;

pub use dev::{BlockDev, FileDev, MemDev, SliceDev};
pub use vfs::*;

/// Raw CRC-32C state update as Linux's `crc32c_le`: no pre/post inversion.
pub fn crc32c_raw(seed: u32, data: &[u8]) -> u32 {
    !crc32c::crc32c_append(!seed, data)
}

/// Little-endian field readers that return 0 past the end, so a short or hostile
/// on-disk structure can never cause a panic while being decoded.
pub trait Le {
    fn u8_at(&self, o: usize) -> u8;
    fn u16_at(&self, o: usize) -> u16;
    fn u32_at(&self, o: usize) -> u32;
    fn u64_at(&self, o: usize) -> u64;
}

impl Le for [u8] {
    fn u8_at(&self, o: usize) -> u8 {
        self.get(o).copied().unwrap_or(0)
    }
    fn u16_at(&self, o: usize) -> u16 {
        self.get(o..o.saturating_add(2)).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32_at(&self, o: usize) -> u32 {
        self.get(o..o.saturating_add(4)).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64_at(&self, o: usize) -> u64 {
        self.get(o..o.saturating_add(8))
            .map_or(0, |b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}

/// Little-endian field writers. Out-of-range writes are dropped: callers size their
/// buffers from validated geometry, and a silent no-op beats a panic in a mount.
pub trait LeMut {
    fn put_u8(&mut self, o: usize, v: u8);
    fn put_u16(&mut self, o: usize, v: u16);
    fn put_u32(&mut self, o: usize, v: u32);
    fn put_u64(&mut self, o: usize, v: u64);
}

impl LeMut for [u8] {
    fn put_u8(&mut self, o: usize, v: u8) {
        if let Some(b) = self.get_mut(o) {
            *b = v;
        }
    }
    fn put_u16(&mut self, o: usize, v: u16) {
        if let Some(b) = self.get_mut(o..o + 2) {
            b.copy_from_slice(&v.to_le_bytes());
        }
    }
    fn put_u32(&mut self, o: usize, v: u32) {
        if let Some(b) = self.get_mut(o..o + 4) {
            b.copy_from_slice(&v.to_le_bytes());
        }
    }
    fn put_u64(&mut self, o: usize, v: u64) {
        if let Some(b) = self.get_mut(o..o + 8) {
            b.copy_from_slice(&v.to_le_bytes());
        }
    }
}

/// Formats a 16-byte UUID in canonical 8-4-4-4-12 form.
pub fn fmt_uuid(u: &[u8]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in u.iter().take(16).enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}
