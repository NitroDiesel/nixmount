//! The primitives LUKS is built from: AES-XTS as dm-crypt uses it, the hashes and key
//! derivations keyslots name, and the anti-forensic splitter that spreads each key out.
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use fscore::{FsError, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

type Block = GenericArray<u8, aes::cipher::consts::U16>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha512,
}

impl Hash {
    pub fn parse(name: &str) -> Result<Hash> {
        match name.to_ascii_lowercase().as_str() {
            "sha1" => Ok(Hash::Sha1),
            "sha256" => Ok(Hash::Sha256),
            "sha512" => Ok(Hash::Sha512),
            _ => Err(FsError::Unsupported(format!("the {name} hash isn't supported"))),
        }
    }

    pub fn size(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha512 => 64,
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            parts.iter().for_each(|p| d.update(p));
            d.finalize().to_vec()
        }
        match self {
            Hash::Sha1 => run::<Sha1>(parts),
            Hash::Sha256 => run::<Sha256>(parts),
            Hash::Sha512 => run::<Sha512>(parts),
        }
    }

    pub fn pbkdf2(self, secret: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
        match self {
            Hash::Sha1 => pbkdf2::pbkdf2_hmac::<Sha1>(secret, salt, rounds, out),
            Hash::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(secret, salt, rounds, out),
            Hash::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(secret, salt, rounds, out),
        }
    }
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Hash::Sha256.digest(&[data])
}

/// Argon2 working memory beyond this is refused rather than attempted: it is cryptsetup's
/// own ceiling, and a hostile header must not be able to exhaust the machine.
const ARGON2_MAX_KIB: u32 = 4 << 20;

pub fn argon2(id: bool, passphrase: &[u8], salt: &[u8], time: u32, memory_kib: u32, lanes: u32, out: &mut [u8]) -> Result<()> {
    use argon2::{Algorithm, Argon2, Params, Version};
    if memory_kib > ARGON2_MAX_KIB {
        return Err(FsError::Unsupported(format!("the keyslot asks for {} MiB of memory", memory_kib / 1024)));
    }
    let params = Params::new(memory_kib, time, lanes, Some(out.len()))
        .map_err(|e| FsError::Corrupt(format!("keyslot has invalid Argon2 parameters: {e}")))?;
    // Allocated here so that a computer without that much memory gets an error, not a crash.
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(params.block_count())
        .map_err(|_| FsError::Unsupported(format!("unlocking needs {} MiB of free memory", memory_kib / 1024)))?;
    memory.resize(params.block_count(), argon2::Block::default());
    let alg = if id { Algorithm::Argon2id } else { Algorithm::Argon2i };
    // Lanes run side by side, as cryptsetup tuned them to. The pool is this call's own, so no
    // threads outlive the unlock.
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(lanes as usize);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| FsError::Unsupported(format!("could not start key derivation: {e}")))?;
    let argon = Argon2::new(alg, Version::V0x13, params);
    let r = pool.install(|| argon.hash_password_into_with_memory(passphrase, salt, out, &mut memory[..]));
    // The memory holds values derived from the passphrase.
    use zeroize::Zeroize;
    memory.iter_mut().for_each(|b| b.zeroize());
    r.map_err(|e| FsError::Corrupt(format!("Argon2 failed: {e}")))
}

/// Recovers a key from its anti-forensic split: every stripe is needed, so wiping any part
/// of a keyslot destroys the key. `material` is `stripes` copies of the key's length.
pub fn af_merge(material: &[u8], key_size: usize, hash: Hash) -> Zeroizing<Vec<u8>> {
    let mut d = Zeroizing::new(vec![0u8; key_size]);
    let stripes: Vec<&[u8]> = material.chunks_exact(key_size).collect();
    let Some((last, rest)) = stripes.split_last() else { return d };
    for s in rest {
        d.iter_mut().zip(*s).for_each(|(a, b)| *a ^= b);
        diffuse(&mut d, hash);
    }
    d.iter_mut().zip(*last).for_each(|(a, b)| *a ^= b);
    d
}

fn diffuse(d: &mut [u8], hash: Hash) {
    for (i, chunk) in d.chunks_mut(hash.size()).enumerate() {
        let h = hash.digest(&[&(i as u32).to_be_bytes(), chunk]);
        chunk.copy_from_slice(&h[..chunk.len()]);
    }
}

enum Aes {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Result<Aes> {
        let bad = || FsError::Unsupported("invalid AES key".into());
        Ok(match key.len() {
            16 => Aes::A128(Aes128::new_from_slice(key).map_err(|_| bad())?),
            24 => Aes::A192(Aes192::new_from_slice(key).map_err(|_| bad())?),
            32 => Aes::A256(Aes256::new_from_slice(key).map_err(|_| bad())?),
            _ => return Err(bad()),
        })
    }

    fn encrypt(&self, b: &mut [Block]) {
        match self {
            Aes::A128(c) => c.encrypt_blocks(b),
            Aes::A192(c) => c.encrypt_blocks(b),
            Aes::A256(c) => c.encrypt_blocks(b),
        }
    }

    fn decrypt(&self, b: &mut [Block]) {
        match self {
            Aes::A128(c) => c.decrypt_blocks(b),
            Aes::A192(c) => c.decrypt_blocks(b),
            Aes::A256(c) => c.decrypt_blocks(b),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Xts,
    /// CBC with ESSIV(sha256) IVs: the LUKS default until 2013.
    CbcEssiv,
    CbcPlain,
}

/// A dm-crypt cipher specification such as `aes-xts-plain64`.
#[derive(Clone, Debug)]
pub struct Spec {
    pub name: String,
    pub mode: Mode,
    /// `plain` rather than `plain64`: sector numbers are truncated to 32 bits.
    pub iv32: bool,
}

impl Spec {
    pub fn parse(spec: &str) -> Result<Spec> {
        let name = spec.to_ascii_lowercase();
        let (mode, iv32) = match name.as_str() {
            "aes-xts-plain64" => (Mode::Xts, false),
            "aes-xts-plain" => (Mode::Xts, true),
            "aes-cbc-essiv:sha256" => (Mode::CbcEssiv, false),
            "aes-cbc-plain64" => (Mode::CbcPlain, false),
            "aes-cbc-plain" => (Mode::CbcPlain, true),
            _ => return Err(FsError::Unsupported(format!("the {name} cipher isn't supported, only AES in XTS or CBC mode"))),
        };
        Ok(Spec { name, mode, iv32 })
    }

    /// XTS keys hold two AES keys.
    pub fn key_ok(&self, n: usize) -> bool {
        match self.mode {
            Mode::Xts => matches!(n, 32 | 48 | 64),
            _ => matches!(n, 16 | 24 | 32),
        }
    }

    pub fn cipher(&self, key: &[u8]) -> Result<Sector> {
        if !self.key_ok(key.len()) {
            return Err(FsError::Unsupported(format!("{}-bit keys don't fit {}", key.len() * 8, self.name)));
        }
        let kind = match self.mode {
            Mode::Xts => Kind::Xts(Xts::new(key)?),
            Mode::CbcEssiv => Kind::Cbc { aes: Aes::new(key)?, essiv: Some(Aes::new(&sha256(key))?) },
            Mode::CbcPlain => Kind::Cbc { aes: Aes::new(key)?, essiv: None },
        };
        Ok(Sector { kind, iv32: self.iv32 })
    }
}

enum Kind {
    Xts(Xts),
    Cbc { aes: Aes, essiv: Option<Aes> },
}

/// Encrypts and decrypts whole sectors, given each one's number in 512-byte units.
pub struct Sector {
    kind: Kind,
    iv32: bool,
}

impl Sector {
    pub fn encrypt(&self, n: u64, sector: &mut [u8]) {
        self.run(n, sector, true);
    }

    pub fn decrypt(&self, n: u64, sector: &mut [u8]) {
        self.run(n, sector, false);
    }

    fn run(&self, n: u64, sector: &mut [u8], encrypt: bool) {
        let n = if self.iv32 { n & 0xFFFF_FFFF } else { n };
        match &self.kind {
            Kind::Xts(x) => x.run(n, sector, encrypt),
            Kind::Cbc { aes, essiv } => {
                let mut iv = Block::default();
                iv[..8].copy_from_slice(&n.to_le_bytes());
                if let Some(e) = essiv {
                    e.encrypt(std::slice::from_mut(&mut iv));
                }
                let iv = u128::from_le_bytes(iv.into());
                if encrypt {
                    cbc_encrypt(aes, iv, sector);
                } else {
                    cbc_decrypt(aes, iv, sector);
                }
            }
        }
    }
}

fn load(b: &[u8]) -> u128 {
    u128::from_le_bytes(b.try_into().unwrap_or_default())
}

fn cbc_encrypt(aes: &Aes, iv: u128, sector: &mut [u8]) {
    let mut prev = iv;
    for chunk in sector.chunks_exact_mut(16) {
        let mut b = Block::from((load(chunk) ^ prev).to_le_bytes());
        aes.encrypt(std::slice::from_mut(&mut b));
        chunk.copy_from_slice(&b);
        prev = load(chunk);
    }
}

/// Decryption doesn't chain, so it runs in batches like XTS. Each block is XORed with the
/// ciphertext before it, so a batch is written back from its end.
fn cbc_decrypt(aes: &Aes, iv: u128, sector: &mut [u8]) {
    let mut prev = iv;
    let mut batch = [Block::default(); BATCH];
    for chunk in sector.chunks_mut(16 * BATCH) {
        let n = chunk.len() / 16;
        for (b, src) in batch.iter_mut().zip(chunk.chunks_exact(16)) {
            b.copy_from_slice(src);
        }
        let last = load(&chunk[(n - 1) * 16..n * 16]);
        aes.decrypt(&mut batch[..n]);
        for i in (0..n).rev() {
            let before = if i == 0 { prev } else { load(&chunk[(i - 1) * 16..i * 16]) };
            let x = u128::from_le_bytes(batch[i].into()) ^ before;
            chunk[i * 16..(i + 1) * 16].copy_from_slice(&x.to_le_bytes());
        }
        prev = last;
    }
    batch.iter_mut().for_each(|b| b.fill(0));
}

/// AES-XTS over whole sectors, as IEEE 1619 and dm-crypt define it. Sectors are multiples
/// of 16 bytes, so ciphertext stealing never applies.
struct Xts {
    data: Aes,
    tweak: Aes,
}

/// Blocks handled per batch, which lets AES-NI work on several at once.
const BATCH: usize = 32;

impl Xts {
    /// `key` holds the data key followed by the tweak key, as LUKS stores them.
    fn new(key: &[u8]) -> Result<Xts> {
        let (a, b) = key.split_at(key.len() / 2);
        Ok(Xts { data: Aes::new(a)?, tweak: Aes::new(b)? })
    }

    fn run(&self, iv: u64, sector: &mut [u8], encrypt: bool) {
        let mut t = Block::default();
        t[..8].copy_from_slice(&iv.to_le_bytes());
        self.tweak.encrypt(std::slice::from_mut(&mut t));
        let mut tweak = u128::from_le_bytes(t.into());
        let mut tweaks = [0u128; BATCH];
        let mut batch = [Block::default(); BATCH];
        for chunk in sector.chunks_mut(16 * BATCH) {
            let n = chunk.len() / 16;
            for (i, (b, src)) in batch.iter_mut().zip(chunk.chunks_exact(16)).enumerate() {
                tweaks[i] = tweak;
                let x = u128::from_le_bytes(src.try_into().unwrap_or_default()) ^ tweak;
                b.copy_from_slice(&x.to_le_bytes());
                // Multiplying by x in GF(2^128), reduced by its polynomial.
                tweak = (tweak << 1) ^ if tweak >> 127 == 1 { 0x87 } else { 0 };
            }
            if encrypt {
                self.data.encrypt(&mut batch[..n]);
            } else {
                self.data.decrypt(&mut batch[..n]);
            }
            for (i, (b, dst)) in batch.iter().zip(chunk.chunks_exact_mut(16)).enumerate() {
                let x = u128::from_le_bytes((*b).into()) ^ tweaks[i];
                dst.copy_from_slice(&x.to_le_bytes());
            }
        }
        batch.iter_mut().for_each(|b| b.fill(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // IEEE 1619-2007, annex B: vectors 1 and 2 (XTS-AES-128).
    #[test]
    fn xts_matches_the_standard() {
        let cases = [
            ("00".repeat(32), 0u64, "00".repeat(32), "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"),
            (
                "11".repeat(16) + &"22".repeat(16),
                0x3333333333,
                "44".repeat(32),
                "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
            ),
        ];
        for (key, iv, plain, cipher) in cases {
            let x = Spec::parse("aes-xts-plain64").unwrap().cipher(&hex(&key)).unwrap();
            let mut buf = hex(&plain);
            x.encrypt(iv, &mut buf);
            assert_eq!(buf, hex(cipher));
            x.decrypt(iv, &mut buf);
            assert_eq!(buf, hex(&plain));
        }
    }

    #[test]
    fn every_mode_round_trips_whole_sectors() {
        for (spec, n) in [("aes-xts-plain64", 64), ("aes-cbc-essiv:sha256", 32), ("aes-cbc-plain", 16)] {
            let key: Vec<u8> = (0..n).collect();
            let c = Spec::parse(spec).unwrap().cipher(&key).unwrap();
            let plain: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 251) as u8).collect();
            let mut buf = plain.clone();
            c.encrypt(12345, &mut buf);
            assert_ne!(buf, plain, "{spec}");
            c.decrypt(12345, &mut buf);
            assert_eq!(buf, plain, "{spec}");
        }
    }

    // NIST SP 800-38A F.2.1, CBC-AES128.
    #[test]
    fn cbc_matches_the_standard() {
        let aes = Aes::new(&hex("2b7e151628aed2a6abf7158809cf4f3c")).unwrap();
        let iv = u128::from_le_bytes(hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap());
        let plain = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let mut buf = plain.clone();
        cbc_encrypt(&aes, iv, &mut buf);
        assert_eq!(buf, hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"));
        cbc_decrypt(&aes, iv, &mut buf);
        assert_eq!(buf, plain);
    }

    // The example in the reference implementation's README: Argon2i, t=2, 64 MiB, 4 lanes.
    #[test]
    fn argon2_matches_the_reference() {
        let mut out = [0u8; 24];
        argon2(false, b"password", b"somesalt", 2, 65536, 4, &mut out).unwrap();
        assert_eq!(out.to_vec(), hex("45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6"));
    }

    /// The splitter run forwards, as cryptsetup does when it writes a keyslot.
    fn af_split(key: &[u8], random: &[u8], hash: Hash) -> Vec<u8> {
        let n = key.len();
        let mut out = random.to_vec();
        let mut d = vec![0u8; n];
        for s in random.chunks_exact(n) {
            d.iter_mut().zip(s).for_each(|(a, b)| *a ^= b);
            diffuse(&mut d, hash);
        }
        out.extend(d.iter().zip(key).map(|(a, b)| a ^ b));
        out
    }

    #[test]
    fn af_merge_undoes_the_split() {
        for hash in [Hash::Sha1, Hash::Sha256, Hash::Sha512] {
            let key: Vec<u8> = (0..64).map(|i| i * 3).collect();
            let random: Vec<u8> = (0..64 * 39).map(|i| (i * 31 % 256) as u8).collect();
            let split = af_split(&key, &random, hash);
            assert_eq!(*af_merge(&split, 64, hash), key);
        }
    }
}
