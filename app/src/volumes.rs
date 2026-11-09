//! What can be mounted, and how to open it.
use crate::disk::{self, RawDev};
use btrfs::Btrfs;
use ext4::Ext4;
use fscore::part::{self, FsKind};
use fscore::{BlockDev, FileDev, Filesystem, FsError, MountOpts, Result, SliceDev, VolumeInfo};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Identifies a volume across the service boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// Image file, optionally a partition within it.
    Image { path: PathBuf, partition: Option<u32> },
    Partition { disk: u32, part: u32 },
    /// All the devices of a multi-device Btrfs filesystem.
    Group { members: Vec<(u32, u32)> },
}

/// One row of the volume list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Volume {
    pub target: Target,
    pub title: String,
    pub location: String,
    pub size: u64,
    pub kind: String,
    pub mountable: bool,
    pub label: String,
    pub uuid: String,
    pub removable: bool,
    /// Detail gathered by reading the superblock.
    pub used: Option<u64>,
    pub features: Vec<String>,
    pub ro_reasons: Vec<String>,
    pub notes: Vec<String>,
    /// Why it can't be opened at all, if so.
    pub error: Option<String>,
    /// LUKS-encrypted.
    #[serde(default)]
    pub encrypted: bool,
    /// Encrypted and not unlocked yet, so all that is known comes from the LUKS header.
    #[serde(default)]
    pub locked: bool,
}

pub const LOCKED: &str = "this volume is encrypted, so it needs its passphrase";

/// Opens every device of `target`.
fn devices(target: &Target, write: bool) -> Result<Vec<Arc<dyn BlockDev>>> {
    match target {
        Target::Image { path, partition } => {
            let file: Arc<dyn BlockDev> = Arc::new(FileDev::open(path, write)?);
            Ok(vec![image_slice(file, *partition)?])
        }
        Target::Partition { disk, part } => Ok(vec![Arc::new(RawDev::open(*disk, *part, write)?)]),
        Target::Group { members } => members
            .iter()
            .map(|(d, p)| Ok(Arc::new(RawDev::open(*d, *p, write)?) as Arc<dyn BlockDev>))
            .collect(),
    }
}

/// A whole image, or the slice of it holding one partition. With no partition given, the
/// first one holding a mountable filesystem is chosen.
fn image_slice(file: Arc<dyn BlockDev>, partition: Option<u32>) -> Result<Arc<dyn BlockDev>> {
    let usable = |d: &dyn BlockDev| {
        let k = part::probe(d);
        k.mountable() || k == FsKind::Luks
    };
    if partition.is_none() && usable(file.as_ref()) {
        return Ok(file);
    }
    for p in part::partitions(file.as_ref(), 512)? {
        let s: Arc<dyn BlockDev> = Arc::new(SliceDev::new(file.clone(), p.start, p.len));
        let wanted = partition.is_none_or(|n| n == p.index);
        if wanted && usable(s.as_ref()) {
            return Ok(s);
        }
    }
    Err(FsError::Unsupported("no ext or btrfs filesystem found".into()))
}

/// The encryption header, if `target` is a LUKS volume. Reading it needs no passphrase.
pub fn luks_header(target: &Target) -> Option<luks::Header> {
    let devs = devices(target, false).ok()?;
    let first = devs.first()?;
    (part::probe(first.as_ref()) == FsKind::Luks).then(|| luks::read_header(first.as_ref()).ok())?
}

/// Recovers the key of an encrypted volume from its passphrase.
pub fn unlock(target: &Target, passphrase: &[u8]) -> Result<luks::Key> {
    let devs = devices(target, false)?;
    let first = devs.first().ok_or(FsError::Invalid("no devices"))?;
    luks::read_header(first.as_ref())?.unlock(first.as_ref(), passphrase)
}

/// Opens a volume with the engine its signature calls for. Devices are opened read-only
/// unless writing was requested, so a read-only mount cannot write even by accident.
pub fn open(target: &Target, opts: MountOpts) -> Result<Arc<dyn Filesystem>> {
    open_with_devices(target, opts, None).map(|(fs, _)| fs)
}

pub fn open_unlocked(target: &Target, opts: MountOpts, key: Option<&luks::Key>) -> Result<Arc<dyn Filesystem>> {
    open_with_devices(target, opts, key).map(|(fs, _)| fs)
}

/// Also hands back the devices, so a mount can tell when they stop answering. LUKS devices
/// are decrypted with `key` on the way.
pub fn open_with_devices(
    target: &Target,
    opts: MountOpts,
    key: Option<&luks::Key>,
) -> Result<(Arc<dyn Filesystem>, Vec<Arc<dyn BlockDev>>)> {
    let mut devs = devices(target, opts.write)?;
    for d in &mut devs {
        if part::probe(d.as_ref()) == FsKind::Luks {
            let key = key.ok_or_else(|| FsError::Unsupported(LOCKED.into()))?;
            let header = luks::read_header(d.as_ref())?;
            *d = Arc::new(header.open(d.clone(), key)?);
        }
    }
    let Some(first) = devs.first() else { return Err(FsError::Invalid("no devices")) };
    let fs: Arc<dyn Filesystem> = match part::probe(first.as_ref()) {
        FsKind::Ext(_) => Arc::new(Ext4::open(first.clone(), opts)?),
        FsKind::Btrfs => Arc::new(Btrfs::open(devs.clone(), opts)?),
        k => return Err(FsError::Unsupported(format!("{} volumes can't be mounted", k.name()))),
    };
    Ok((fs, devs))
}

fn enrich(v: &mut Volume) {
    if let Some(h) = luks_header(&v.target) {
        v.encrypted = true;
        v.locked = true;
        v.kind = format!("LUKS{}", h.version);
        v.label = h.label.clone();
        v.uuid = h.uuid.clone();
        v.features = h.summary();
        return;
    }
    match open(&v.target, MountOpts { write: false, cache_bytes: 1 << 20 }) {
        Ok(fs) => fill_from(v, &fs.info()),
        Err(e) => v.error = Some(e.to_string()),
    }
}

/// What an unlocked volume holds, for the list.
pub fn describe_unlocked(v: &Volume, key: &luks::Key) -> Result<Volume> {
    let fs = open_unlocked(&v.target, MountOpts { write: false, cache_bytes: 1 << 20 }, Some(key))?;
    let mut out = v.clone();
    fill_from(&mut out, &fs.info());
    out.error = None;
    out.locked = false;
    Ok(out)
}

/// What write access would meet: the same checks as a real mount, without mounting.
pub fn fill_from(v: &mut Volume, info: &VolumeInfo) {
    v.label = info.label.clone();
    v.uuid = info.uuid.clone();
    v.used = Some(info.total_bytes.saturating_sub(info.free_bytes));
    v.features = info.features.clone();
    v.notes = info.notes.clone();
    v.ro_reasons = info.ro_reasons.clone();
    if !info.fs_type.is_empty() {
        v.kind = info.fs_type.clone();
    }
    if info.total_bytes > 0 {
        v.size = info.total_bytes;
    }
}

/// Lists Linux volumes on the physical disks, merging multi-device Btrfs filesystems.
pub fn scan_disks() -> Vec<Volume> {
    let found = disk::scan();
    let mut out: Vec<Volume> = vec![];
    let mut groups: Vec<([u8; 16], Vec<(u32, u32)>)> = vec![];
    for p in &found {
        if p.letter.is_some() || matches!(p.kind, FsKind::Ntfs | FsKind::Fat | FsKind::ExFat | FsKind::Unknown) {
            continue;
        }
        let mut target = Target::Partition { disk: p.disk, part: p.part };
        if p.kind == FsKind::Btrfs {
            let Ok(d) = RawDev::open(p.disk, p.part, false) else { continue };
            let Ok((fsid, _, count)) = btrfs::group_devices(&d) else { continue };
            if count > 1 {
                match groups.iter_mut().find(|g| g.0 == fsid) {
                    Some(g) => {
                        g.1.push((p.disk, p.part));
                        continue;
                    }
                    None => groups.push((fsid, vec![(p.disk, p.part)])),
                }
                target = Target::Group { members: vec![(p.disk, p.part)] };
            }
        }
        let mut v = Volume {
            target,
            title: format!("Disk {} · Partition {}", p.disk, p.part),
            location: p.disk_name.clone(),
            size: p.size,
            kind: p.kind.name(),
            mountable: p.kind.mountable() || p.kind == FsKind::Luks,
            label: String::new(),
            uuid: String::new(),
            removable: p.removable,
            used: None,
            features: vec![],
            ro_reasons: vec![],
            notes: vec![],
            error: None,
            encrypted: false,
        locked: false,
        };
        if !v.mountable {
            v.error = Some(format!("{} volumes aren't supported", v.kind));
        }
        out.push(v);
    }
    for v in &mut out {
        if let Target::Group { members } = &mut v.target {
            if let Some(g) = groups.iter().find(|g| g.1.first() == members.first()) {
                *members = g.1.clone();
            }
        }
        if v.mountable {
            enrich(v);
        }
    }
    out
}

/// Describes an image file for the volume list.
pub fn describe_image(path: &Path) -> Volume {
    let name = path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
    let mut v = Volume {
        target: Target::Image { path: path.to_path_buf(), partition: None },
        title: name,
        location: path.parent().map_or_else(String::new, |p| p.display().to_string()),
        size: std::fs::metadata(path).map_or(0, |m| m.len()),
        kind: "image".into(),
        mountable: true,
        label: String::new(),
        uuid: String::new(),
        removable: false,
        used: None,
        features: vec![],
        ro_reasons: vec![],
        notes: vec![],
        error: None,
        encrypted: false,
        locked: false,
    };
    enrich(&mut v);
    if v.error.is_some() {
        v.mountable = false;
    }
    v
}

/// A list entry for a volume that is open, built from the engine's own view of it.
pub fn describe_mounted(target: &Target, info: &VolumeInfo, encrypted: bool) -> Volume {
    let (title, location) = match target {
        Target::Partition { disk, part } => (format!("Disk {disk} · Partition {part}"), "Mounted partition".to_string()),
        Target::Group { members } => (format!("{} devices", members.len()), "Multi-device".to_string()),
        Target::Image { path, .. } => (
            path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
            path.parent().map_or_else(String::new, |p| p.display().to_string()),
        ),
    };
    let mut v = Volume {
        target: target.clone(),
        title,
        location,
        size: info.total_bytes,
        kind: info.fs_type.clone(),
        mountable: true,
        label: String::new(),
        uuid: String::new(),
        removable: false,
        used: None,
        features: vec![],
        ro_reasons: vec![],
        notes: vec![],
        error: None,
        encrypted,
        locked: false,
    };
    fill_from(&mut v, info);
    v
}
