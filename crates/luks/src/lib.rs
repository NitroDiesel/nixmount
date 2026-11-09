//! LUKS1 and LUKS2, the standard Linux disk encryption: unlocking with a passphrase, and a
//! block device that decrypts and encrypts sectors exactly as Linux's dm-crypt does, so the
//! filesystem engines run on top of it unchanged.
#![forbid(unsafe_code)]

mod crypto;
mod header;

use fscore::{BlockDev, FsError, Result};
pub use header::Header;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// The volume key. Whoever holds it can read and write the volume, so it never appears in
/// debug output and is wiped from memory when dropped.
#[derive(Clone)]
pub struct Key(Zeroizing<Vec<u8>>);

impl Key {
    pub fn from_bytes(bytes: Vec<u8>) -> Key {
        Key(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// Reads the header of the LUKS volume on `dev`. Nothing secret is involved.
pub fn read_header(dev: &dyn BlockDev) -> Result<Header> {
    header::read(dev)
}

fn wrong_passphrase() -> FsError {
    FsError::Unsupported("that passphrase doesn't unlock this volume".into())
}

impl Header {
    /// How the volume is protected, for display alongside its LUKS version.
    pub fn summary(&self) -> Vec<String> {
        let mut v = vec![self.segment.spec.name.clone(), format!("{}-bit key", self.key_size * 8)];
        if let Some(s) = self.slots.first() {
            v.push(s.kdf.name().to_string());
        }
        v
    }

    /// Finds the keyslot `passphrase` opens and recovers the volume key from it. Each try
    /// costs what the keyslot's key derivation was tuned to cost, typically a second or two.
    pub fn unlock(&self, dev: &dyn BlockDev, passphrase: &[u8]) -> Result<Key> {
        for slot in &self.slots {
            let mut derived = Zeroizing::new(vec![0u8; slot.area_key]);
            match &slot.kdf {
                header::Kdf::Pbkdf2 { hash, iterations, salt } => hash.pbkdf2(passphrase, salt, *iterations, &mut derived),
                header::Kdf::Argon2 { id, time, memory_kib, lanes, salt } => {
                    crypto::argon2(*id, passphrase, salt, *time, *memory_kib, *lanes, &mut derived)?
                }
            }
            let len = self.key_size * slot.stripes;
            let mut material = Zeroizing::new(vec![0u8; len.div_ceil(512) * 512]);
            dev.read_at(slot.area_offset, &mut material)?;
            let cipher = slot.area_spec.cipher(&derived)?;
            for (i, sector) in material.chunks_mut(512).enumerate() {
                cipher.decrypt(i as u64, sector);
            }
            let key = crypto::af_merge(&material[..len], self.key_size, slot.af_hash);
            if self.digests.get(slot.digest).is_some_and(|d| key_matches(d, &key)) {
                return Ok(Key(key));
            }
        }
        Err(wrong_passphrase())
    }

    /// Presents the decrypted volume. The key is checked first: a wrong one would turn
    /// every write into garbage.
    pub fn open(&self, dev: Arc<dyn BlockDev>, key: &Key) -> Result<CryptDev> {
        if !self.digests.iter().any(|d| key_matches(d, key.as_bytes())) {
            return Err(FsError::Unsupported("the key doesn't belong to this volume".into()));
        }
        let s = &self.segment;
        Ok(CryptDev {
            inner: dev,
            cipher: s.spec.cipher(key.as_bytes())?,
            offset: s.offset,
            len: s.len,
            sector: s.sector,
            iv_tweak: s.iv_tweak,
            write: Mutex::new(()),
        })
    }
}

fn key_matches(d: &header::Digest, key: &[u8]) -> bool {
    let mut out = Zeroizing::new(vec![0u8; d.value.len()]);
    d.hash.pbkdf2(key, &d.salt, d.iterations, &mut out);
    !d.value.is_empty() && out.iter().zip(&d.value).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// The plaintext view of a LUKS volume's data area.
pub struct CryptDev {
    inner: Arc<dyn BlockDev>,
    cipher: crypto::Sector,
    offset: u64,
    len: u64,
    sector: u64,
    iv_tweak: u64,
    /// Serialises writes, so a partial-sector update can't race another write to the sector.
    write: Mutex<()>,
}

impl CryptDev {
    /// dm-crypt numbers sectors in 512-byte units whatever the encryption sector size.
    fn crypt(&self, at: u64, buf: &mut [u8], encrypt: bool) {
        for (i, s) in buf.chunks_mut(self.sector as usize).enumerate() {
            let n = (at + i as u64 * self.sector) / 512 + self.iv_tweak;
            if encrypt {
                self.cipher.encrypt(n, s);
            } else {
                self.cipher.decrypt(n, s);
            }
        }
    }

    fn check(&self, off: u64, n: usize) -> Result<()> {
        if off.checked_add(n as u64).is_none_or(|e| e > self.len) {
            return Err(FsError::Corrupt(format!("access at {off:#x} is outside the encrypted volume")));
        }
        Ok(())
    }

    /// The whole sectors covering `[off, off + n)`.
    fn span(&self, off: u64, n: usize) -> (u64, usize) {
        let start = off / self.sector * self.sector;
        let end = (off + n as u64).div_ceil(self.sector) * self.sector;
        (start, (end - start) as usize)
    }

    fn read_plain(&self, start: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(self.offset + start, buf)?;
        self.crypt(start, buf, false);
        Ok(())
    }
}

impl BlockDev for CryptDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.check(off, buf.len())?;
        let (start, len) = self.span(off, buf.len());
        if (start, len) == (off, buf.len()) {
            return self.read_plain(start, buf);
        }
        let mut tmp = vec![0u8; len];
        self.read_plain(start, &mut tmp)?;
        let skip = (off - start) as usize;
        buf.copy_from_slice(&tmp[skip..skip + buf.len()]);
        Ok(())
    }

    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        self.check(off, data.len())?;
        let _one = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let (start, len) = self.span(off, data.len());
        let mut tmp = vec![0u8; len];
        if (start, len) != (off, data.len()) {
            self.read_plain(start, &mut tmp)?;
        }
        let skip = (off - start) as usize;
        tmp[skip..skip + data.len()].copy_from_slice(data);
        self.crypt(start, &mut tmp, true);
        self.inner.write_at(self.offset + start, &tmp)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn writable(&self) -> bool {
        self.inner.writable()
    }
}
