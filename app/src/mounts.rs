//! Running mounts: the registry the service owns, plus the periodic commit.
use crate::volumes::{self, Target, Volume};
use crate::winfsp::{HostOptions, Mount, Stats};
use fscore::{BlockDev, CheckReport, Filesystem, MountOpts};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How often pending changes are committed, matching ext4's and Btrfs's own default.
const COMMIT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MountRequest {
    pub target: Target,
    /// `X:`, or empty to take the next free letter.
    pub mount_point: String,
    pub write: bool,
    pub hide_dotfiles: bool,
    pub codepage: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl MountRequest {
    pub fn host_options(&self) -> HostOptions {
        HostOptions {
            read_only: !self.write,
            hide_dotfiles: self.hide_dotfiles,
            codepage: self.codepage,
            uid: self.uid,
            gid: self.gid,
            ..HostOptions::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MountStatus {
    pub target: Target,
    pub mount_point: String,
    pub read_only: bool,
    pub ro_reasons: Vec<String>,
    pub notes: Vec<String>,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub reads: u64,
    pub writes: u64,
    pub read_bytes: u64,
    pub written_bytes: u64,
    /// Name and read-only flag of each subvolume at the top of the volume.
    pub subvolumes: Vec<(String, bool)>,
}

struct Entry {
    target: Target,
    fs: Arc<dyn Filesystem>,
    devs: Vec<Arc<dyn BlockDev>>,
    mount: Mount,
    stats: Arc<Stats>,
    encrypted: bool,
}

#[derive(Default)]
pub struct Mounts {
    list: Mutex<Vec<Entry>>,
    /// Held while a volume is being mounted, so two requests can't both find it unmounted.
    mounting: Mutex<()>,
}

/// Drive letters nothing is using, from Z down to D.
pub fn free_letters() -> impl Iterator<Item = char> {
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;
    // SAFETY: no arguments.
    let used = unsafe { GetLogicalDrives() };
    (3..26u8).rev().filter(move |i| used & (1 << i) == 0).map(|i| (b'A' + i) as char)
}

impl Mounts {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        self.list.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Mounts `r`. An encrypted volume needs `key`, which lives in the mount until unmount.
    pub fn mount(&self, r: MountRequest, key: Option<luks::Key>) -> Result<MountStatus, String> {
        let _one = self.mounting.lock().unwrap_or_else(|e| e.into_inner());
        if self.lock().iter().any(|e| e.target == r.target) {
            return Err("this volume is already mounted".into());
        }
        let point = if r.mount_point.is_empty() {
            format!("{}:", free_letters().next().ok_or("no free drive letters")?)
        } else {
            r.mount_point.clone()
        };
        let opts = MountOpts { write: r.write, cache_bytes: 0 };
        let (fs, devs) = volumes::open_with_devices(&r.target, opts, key.as_ref()).map_err(|e| e.to_string())?;
        let mount = Mount::start(fs.clone(), &point, r.host_options())?;
        let stats = mount.stats.clone();
        let e = Entry { target: r.target, fs, devs, mount, stats, encrypted: key.is_some() };
        let status = status_of(&e);
        self.lock().push(e);
        Ok(status)
    }

    /// Takes the first mount `which` picks out of the registry.
    fn take(&self, which: impl Fn(&Entry) -> bool) -> Option<Entry> {
        let mut l = self.lock();
        let i = l.iter().position(which)?;
        Some(l.remove(i))
    }

    pub fn unmount(&self, point: &str) -> Result<(), String> {
        close(self.take(|e| e.mount.mount_point.eq_ignore_ascii_case(point)).ok_or("nothing is mounted there")?)
    }

    pub fn unmount_all(&self) {
        let all: Vec<Entry> = std::mem::take(&mut *self.lock());
        for e in all {
            let _ = close(e);
        }
    }

    /// Drops mounts whose device has gone, freeing their drive letters. It asks the open
    /// handle, because a disk pulled and put straight back has its path again while this
    /// handle stays dead, and only mounting afresh gets a working one.
    pub fn prune_missing(&self) {
        let open: Vec<_> = self.lock().iter().map(|e| (e.fs.clone(), e.devs.clone())).collect();
        for (fs, devs) in open {
            if devs.iter().any(|d| d.read_at(0, &mut [0; 512]).is_err()) {
                // The mount that was tested, not whatever holds its drive letter by now.
                if let Some(e) = self.take(|e| Arc::ptr_eq(&e.fs, &fs)) {
                    let _ = close(e);
                }
            }
        }
    }

    /// Describes mounted volumes for the volume list.
    pub fn volumes(&self) -> Vec<Volume> {
        self.lock().iter().map(|e| volumes::describe_mounted(&e.target, &e.fs.info(), e.encrypted)).collect()
    }

    pub fn status(&self) -> Vec<MountStatus> {
        self.lock().iter().map(status_of).collect()
    }

    pub fn uuid_at(&self, point: &str) -> Option<String> {
        self.find(point).ok().map(|fs| fs.info().uuid)
    }

    pub fn sync_all(&self) -> Result<(), String> {
        for fs in self.handles() {
            fs.sync().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn handles(&self) -> Vec<Arc<dyn Filesystem>> {
        self.lock().iter().map(|e| e.fs.clone()).collect()
    }

    fn find(&self, point: &str) -> Result<Arc<dyn Filesystem>, String> {
        let l = self.lock();
        let e = l.iter().find(|e| e.mount.mount_point.eq_ignore_ascii_case(point));
        e.map(|e| e.fs.clone()).ok_or_else(|| "nothing is mounted there".into())
    }

    pub fn scrub(&self, point: &str, progress: &mut dyn FnMut(u64, u64)) -> Result<CheckReport, String> {
        self.find(point)?.scrub(progress).map_err(|e| e.to_string())
    }

    /// Snapshots the root subvolume to `name` at the top of the volume.
    pub fn snapshot(&self, point: &str, name: &str, read_only: bool) -> Result<(), String> {
        let fs = self.find(point)?;
        let root = fs.root();
        fs.snapshot(root, root, name.as_bytes(), read_only).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn create_subvolume(&self, point: &str, name: &str) -> Result<(), String> {
        let fs = self.find(point)?;
        fs.create_subvolume(fs.root(), name.as_bytes()).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn delete_subvolume(&self, point: &str, name: &str) -> Result<(), String> {
        let fs = self.find(point)?;
        fs.delete_subvolume(fs.root(), name.as_bytes()).map_err(|e| e.to_string())
    }

    /// Commits on a timer. Errors are ignored here: a failing engine has already
    /// switched itself to read-only and says so in its status.
    pub fn spawn_committer(self: &Arc<Self>) {
        let me = Arc::downgrade(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(COMMIT_INTERVAL);
            let Some(m) = me.upgrade() else { return };
            for fs in m.handles() {
                let _ = fs.sync();
            }
        });
    }
}

/// Detaches the drive letter first, so nothing can write while the volume closes.
fn close(e: Entry) -> Result<(), String> {
    let fs = e.fs.clone();
    drop(e);
    fs.unmount().map_err(|e| e.to_string())
}

fn status_of(e: &Entry) -> MountStatus {
    let info = e.fs.info();
    MountStatus {
        target: e.target.clone(),
        mount_point: e.mount.mount_point.clone(),
        read_only: info.read_only,
        ro_reasons: info.ro_reasons,
        notes: info.notes,
        total_bytes: info.total_bytes,
        free_bytes: info.free_bytes,
        reads: e.stats.reads.load(Ordering::Relaxed),
        writes: e.stats.writes.load(Ordering::Relaxed),
        read_bytes: e.stats.read_bytes.load(Ordering::Relaxed),
        written_bytes: e.stats.written_bytes.load(Ordering::Relaxed),
        subvolumes: e
            .fs
            .subvolumes(e.fs.root())
            .unwrap_or_default()
            .into_iter()
            .map(|s| (String::from_utf8_lossy(&s.name).into_owned(), s.read_only))
            .collect(),
    }
}
