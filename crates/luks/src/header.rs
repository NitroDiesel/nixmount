//! Reading LUKS1 and LUKS2 headers. Everything here comes from a disk that may be hostile,
//! so every size and offset is checked against the device before it is used.
use crate::crypto::{sha256, Hash, Spec};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fscore::{BlockDev, FsError, Result};
use serde_json::Value;

/// How a keyslot turns a passphrase into the key that decrypts its area.
#[derive(Clone, Debug)]
pub enum Kdf {
    Pbkdf2 { hash: Hash, iterations: u32, salt: Vec<u8> },
    Argon2 { id: bool, time: u32, memory_kib: u32, lanes: u32, salt: Vec<u8> },
}

impl Kdf {
    pub fn name(&self) -> &'static str {
        match self {
            Kdf::Pbkdf2 { .. } => "PBKDF2",
            Kdf::Argon2 { id: true, .. } => "Argon2id",
            Kdf::Argon2 { id: false, .. } => "Argon2i",
        }
    }
}

/// A check value for the volume key, which is how a correct passphrase is recognised.
#[derive(Clone, Debug)]
pub struct Digest {
    pub hash: Hash,
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub id: u32,
    pub priority: u8,
    pub kdf: Kdf,
    pub af_hash: Hash,
    pub stripes: usize,
    pub area_offset: u64,
    /// Length of the key that encrypts the keyslot area, and how it encrypts.
    pub area_key: usize,
    pub area_spec: Spec,
    pub digest: usize,
}

/// Where the encrypted data lives and how it is encrypted.
#[derive(Clone, Debug)]
pub struct Segment {
    pub offset: u64,
    pub len: u64,
    pub sector: u64,
    pub iv_tweak: u64,
    pub spec: Spec,
}

#[derive(Clone, Debug)]
pub struct Header {
    pub version: u8,
    pub uuid: String,
    pub label: String,
    pub key_size: usize,
    pub segment: Segment,
    pub slots: Vec<Slot>,
    pub digests: Vec<Digest>,
}

const LUKS1_ACTIVE: u32 = 0x00AC_71F3;
/// LUKS2 allows this many keyslots, and no more digests than keyslots.
const MAX_SLOTS: usize = 32;
/// The longest digest any supported hash produces.
const MAX_DIGEST: usize = 64;
/// Key-derivation work a header may ask for, summed over its keyslots and digests: PBKDF2
/// iterations, and Argon2 passes times KiB of memory. Real volumes are tuned to a second or
/// two per keyslot. This allows minutes, and stops a crafted header from asking for days.
const MAX_WORK: u64 = 1 << 28;
/// LUKS2 stores its header twice; the copy sits at one of these offsets.
const LUKS2_SIZES: [u64; 9] = [0x4000, 0x8000, 0x1_0000, 0x2_0000, 0x4_0000, 0x8_0000, 0x10_0000, 0x20_0000, 0x40_0000];

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap_or_default())
}

fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap_or_default())
}

fn text(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn bad(what: &str) -> FsError {
    FsError::Corrupt(format!("LUKS header: {what}"))
}

fn check_key(spec: &Spec, n: usize) -> Result<usize> {
    if spec.key_ok(n) {
        Ok(n)
    } else {
        Err(FsError::Unsupported(format!("{}-bit keys aren't supported for {}", n * 8, spec.name)))
    }
}

fn check_stripes(n: u64) -> Result<usize> {
    if (1..=65536).contains(&n) {
        Ok(n as usize)
    } else {
        Err(bad("keyslot stripe count out of range"))
    }
}

/// Reads the header of the LUKS volume on `dev`.
pub fn read(dev: &dyn BlockDev) -> Result<Header> {
    let mut b = vec![0u8; 4096];
    dev.read_at(0, &mut b)?;
    if b[0..6] != *b"LUKS\xba\xbe" {
        return Err(FsError::Unsupported("not a LUKS volume".into()));
    }
    let mut h = match be16(&b, 6) {
        1 => luks1(&b)?,
        2 => luks2(dev)?,
        v => return Err(FsError::Unsupported(format!("LUKS version {v} isn't supported"))),
    };
    let s = &mut h.segment;
    if s.len == u64::MAX {
        // A data area that runs to the end of the device, in whole sectors.
        s.len = dev.len().saturating_sub(s.offset) / s.sector * s.sector;
    }
    let end = s.offset.checked_add(s.len).ok_or_else(|| bad("data area overflows"))?;
    if s.len == 0 || s.len % s.sector != 0 || end > dev.len() {
        return Err(bad("the data area lies outside the device"));
    }
    for slot in &h.slots {
        let need = (h.key_size * slot.stripes).div_ceil(512) as u64 * 512;
        if slot.area_offset.checked_add(need).is_none_or(|e| e > dev.len()) {
            return Err(bad("a keyslot lies outside the device"));
        }
    }
    check_work(&h)?;
    Ok(h)
}

/// Refuses a header whose key derivation would cost more than any real volume's.
fn check_work(h: &Header) -> Result<()> {
    let mut pbkdf2 = h.digests.iter().fold(0u64, |n, d| n.saturating_add(d.iterations as u64));
    let mut argon2 = 0u64;
    for s in &h.slots {
        match &s.kdf {
            Kdf::Pbkdf2 { iterations, .. } => pbkdf2 = pbkdf2.saturating_add(*iterations as u64),
            Kdf::Argon2 { time, memory_kib, .. } => argon2 = argon2.saturating_add(*time as u64 * *memory_kib as u64),
        }
    }
    let long = h.digests.iter().any(|d| d.value.len() > MAX_DIGEST);
    if h.slots.len() > MAX_SLOTS || h.digests.len() > MAX_SLOTS || long || pbkdf2 > MAX_WORK || argon2 > MAX_WORK {
        return Err(FsError::Unsupported("this volume asks for more key-derivation work than any real one does".into()));
    }
    Ok(())
}

fn luks1(b: &[u8]) -> Result<Header> {
    let (name, mode, hash) = (text(&b[8..40]), text(&b[40..72]), text(&b[72..104]));
    let spec = Spec::parse(&format!("{name}-{mode}"))?;
    let hash = Hash::parse(&hash)?;
    let key_size = check_key(&spec, be32(b, 108) as usize)?;
    let digest = Digest { hash, iterations: be32(b, 164).max(1), salt: b[132..164].to_vec(), value: b[112..132].to_vec() };
    let mut slots = vec![];
    for i in 0..8 {
        let s = &b[208 + i * 48..208 + (i + 1) * 48];
        if be32(s, 0) != LUKS1_ACTIVE {
            continue;
        }
        slots.push(Slot {
            id: i as u32,
            priority: 1,
            kdf: Kdf::Pbkdf2 { hash, iterations: be32(s, 4).max(1), salt: s[8..40].to_vec() },
            af_hash: hash,
            stripes: check_stripes(be32(s, 44) as u64)?,
            area_offset: be32(s, 40) as u64 * 512,
            // LUKS1 keyslots are encrypted the way the data is.
            area_key: key_size,
            area_spec: spec.clone(),
            digest: 0,
        });
    }
    Ok(Header {
        version: 1,
        uuid: text(&b[168..208]),
        label: String::new(),
        key_size,
        // The data runs to the end of the device; `read` sizes it.
        segment: Segment { offset: be32(b, 104) as u64 * 512, len: u64::MAX, sector: 512, iv_tweak: 0, spec },
        slots,
        digests: vec![digest],
    })
}

struct Bin {
    seqid: u64,
    label: String,
    uuid: String,
    json: Value,
}

/// One copy of the LUKS2 header, if it is intact.
fn luks2_copy(dev: &dyn BlockDev, at: u64, magic: &[u8; 6]) -> Option<Bin> {
    let mut b = vec![0u8; 4096];
    dev.read_at(at, &mut b).ok()?;
    if b[0..6] != *magic || be16(&b, 6) != 2 || be64(&b, 256) != at || text(&b[72..104]) != "sha256" {
        return None;
    }
    let size = be64(&b, 8);
    if !LUKS2_SIZES.contains(&size) {
        return None;
    }
    let mut all = vec![0u8; size as usize];
    dev.read_at(at, &mut all).ok()?;
    let stored = all[448..480].to_vec();
    all[448..512].fill(0);
    if sha256(&all) != stored {
        return None;
    }
    let area = &all[4096..];
    let end = area.iter().position(|c| *c == 0).unwrap_or(area.len());
    let json = serde_json::from_slice(&area[..end]).ok()?;
    Some(Bin { seqid: be64(&b, 16), label: text(&b[24..72]), uuid: text(&b[168..208]), json })
}

/// A number LUKS2 writes as a string (offsets and sizes) or as a JSON number.
fn num(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    v.get(name).ok_or_else(|| bad(&format!("missing {name}")))
}

fn number(v: &Value, name: &str) -> Result<u64> {
    num(field(v, name)?).ok_or_else(|| bad(&format!("{name} is not a number")))
}

fn string<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    field(v, name)?.as_str().ok_or_else(|| bad(&format!("{name} is not text")))
}

fn base64(v: &Value, name: &str) -> Result<Vec<u8>> {
    B64.decode(string(v, name)?).map_err(|_| bad(&format!("{name} is not base64")))
}

fn small(n: u64, name: &str) -> Result<u32> {
    u32::try_from(n).map_err(|_| bad(&format!("{name} is out of range")))
}

fn luks2(dev: &dyn BlockDev) -> Result<Header> {
    let primary = luks2_copy(dev, 0, b"LUKS\xba\xbe");
    let secondary = LUKS2_SIZES.iter().find_map(|at| luks2_copy(dev, *at, b"SKUL\xba\xbe"));
    // Both copies are written on every change; if one was interrupted, the newer one wins.
    let h = match (primary, secondary) {
        (Some(p), Some(s)) if s.seqid > p.seqid => s,
        (Some(p), _) => p,
        (None, Some(s)) => s,
        (None, None) => return Err(bad("both copies are damaged")),
    };
    let j = &h.json;
    let config = field(j, "config")?;
    if let Some(m) = config.get("requirements").and_then(|r| r.get("mandatory")).and_then(Value::as_array) {
        if !m.is_empty() {
            let names: Vec<&str> = m.iter().filter_map(Value::as_str).collect();
            return Err(FsError::Unsupported(format!(
                "this volume needs LUKS features that aren't supported ({}), such as an unfinished re-encryption",
                names.join(", ")
            )));
        }
    }

    let segments = field(j, "segments")?.as_object().ok_or_else(|| bad("segments"))?;
    if segments.len() != 1 {
        return Err(FsError::Unsupported("volumes in the middle of re-encryption aren't supported".into()));
    }
    let seg = segments.get("0").ok_or_else(|| bad("no segment 0"))?;
    if string(seg, "type")? != "crypt" {
        return Err(FsError::Unsupported("only encrypted data segments are supported".into()));
    }
    if seg.get("integrity").is_some_and(|i| !i.is_null()) {
        return Err(FsError::Unsupported("volumes with integrity protection (dm-integrity) aren't supported".into()));
    }
    let spec = Spec::parse(string(seg, "encryption")?)?;
    let sector = number(seg, "sector_size")?;
    if !matches!(sector, 512 | 1024 | 2048 | 4096) {
        return Err(bad("unusual sector size"));
    }
    let offset = number(seg, "offset")?;
    let len = match string(seg, "size") {
        Ok("dynamic") => u64::MAX,
        _ => number(seg, "size")?,
    };
    let iv_tweak = seg.get("iv_tweak").and_then(num).unwrap_or(0);
    if offset % sector != 0 {
        return Err(bad("data area is not sector-aligned"));
    }

    let mut digests = vec![];
    let mut digest_slots: Vec<Vec<String>> = vec![];
    for d in field(j, "digests")?.as_object().ok_or_else(|| bad("digests"))?.values() {
        if string(d, "type")? != "pbkdf2" {
            continue;
        }
        let segs: Vec<&str> = field(d, "segments")?.as_array().map_or(vec![], |a| a.iter().filter_map(Value::as_str).collect());
        if !segs.contains(&"0") {
            continue;
        }
        digests.push(Digest {
            hash: Hash::parse(string(d, "hash")?)?,
            iterations: small(number(d, "iterations")?, "iterations")?.max(1),
            salt: base64(d, "salt")?,
            value: base64(d, "digest")?,
        });
        digest_slots.push(field(d, "keyslots")?.as_array().map_or(vec![], |a| {
            a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()
        }));
    }

    let mut key_size = 0;
    let mut slots = vec![];
    for (id, s) in field(j, "keyslots")?.as_object().ok_or_else(|| bad("keyslots"))? {
        // A slot that can't be used, or isn't understood, is passed over: another may work.
        let Some(digest) = digest_slots.iter().position(|d| d.contains(id)) else { continue };
        let Ok(Some((slot, size))) = keyslot(id, s, &spec, digest) else { continue };
        if key_size != 0 && key_size != size {
            return Err(bad("keyslots disagree about the key size"));
        }
        key_size = size;
        slots.push(slot);
    }
    if slots.is_empty() {
        return Err(FsError::Unsupported("this volume has no passphrase keyslot that can be used".into()));
    }
    // Preferred slots first, as cryptsetup tries them.
    slots.sort_by_key(|s| (std::cmp::Reverse(s.priority), s.id));
    Ok(Header {
        version: 2,
        uuid: h.uuid,
        label: h.label,
        key_size,
        segment: Segment { offset, len, sector, iv_tweak, spec },
        slots,
        digests,
    })
}

/// One LUKS2 keyslot and the size of the volume key it holds. None is a kind of slot that is
/// not for passphrases, such as one a TPM or security key unlocks.
fn keyslot(id: &str, s: &Value, spec: &Spec, digest: usize) -> Result<Option<(Slot, usize)>> {
    let priority = s.get("priority").and_then(num).unwrap_or(1).min(2) as u8;
    if s.get("type").and_then(Value::as_str) != Some("luks2") || priority == 0 {
        return Ok(None);
    }
    let (af, area, kdf) = (field(s, "af")?, field(s, "area")?, field(s, "kdf")?);
    if string(af, "type")? != "luks1" || string(area, "type")? != "raw" {
        return Ok(None);
    }
    let kdf = match string(kdf, "type")? {
        "pbkdf2" => Kdf::Pbkdf2 {
            hash: Hash::parse(string(kdf, "hash")?)?,
            iterations: small(number(kdf, "iterations")?, "iterations")?.max(1),
            salt: base64(kdf, "salt")?,
        },
        t @ ("argon2i" | "argon2id") => Kdf::Argon2 {
            id: t == "argon2id",
            time: small(number(kdf, "time")?, "time")?,
            memory_kib: small(number(kdf, "memory")?, "memory")?,
            lanes: small(number(kdf, "cpus")?, "cpus")?,
            salt: base64(kdf, "salt")?,
        },
        _ => return Ok(None),
    };
    let size = check_key(spec, number(s, "key_size")? as usize)?;
    let area_spec = Spec::parse(string(area, "encryption")?)?;
    let slot = Slot {
        id: id.parse().unwrap_or(u32::MAX),
        priority,
        kdf,
        af_hash: Hash::parse(string(af, "hash")?)?,
        stripes: check_stripes(number(af, "stripes")?)?,
        area_offset: number(area, "offset")?,
        area_key: check_key(&area_spec, number(area, "key_size")? as usize)?,
        area_spec,
        digest,
    };
    Ok(Some((slot, size)))
}
