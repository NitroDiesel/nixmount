//! The contract between filesystem engines and their hosts (WinFsp, CLI, browser, tests).
use std::fmt;

pub type Result<T> = std::result::Result<T, FsError>;

#[derive(Debug)]
pub enum FsError {
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    NoSpace,
    ReadOnly,
    NameTooLong,
    TooManyLinks,
    /// Rename or link across subvolumes; callers fall back to copying.
    CrossDevice,
    Invalid(&'static str),
    /// On-disk data failed validation; the operation stops instead of guessing.
    Corrupt(String),
    Unsupported(String),
    Io(std::io::Error),
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FsError::NotFound => f.write_str("not found"),
            FsError::Exists => f.write_str("already exists"),
            FsError::NotDir => f.write_str("not a directory"),
            FsError::IsDir => f.write_str("is a directory"),
            FsError::NotEmpty => f.write_str("directory not empty"),
            FsError::NoSpace => f.write_str("no space left on volume"),
            FsError::ReadOnly => f.write_str("volume is read-only"),
            FsError::NameTooLong => f.write_str("name too long"),
            FsError::TooManyLinks => f.write_str("too many links"),
            FsError::CrossDevice => f.write_str("not on the same subvolume"),
            FsError::Invalid(s) => write!(f, "invalid request: {s}"),
            FsError::Corrupt(s) => write!(f, "corrupt filesystem: {s}"),
            FsError::Unsupported(s) => write!(f, "unsupported: {s}"),
            FsError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for FsError {}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        FsError::Io(e)
    }
}

/// Files are named by `(tree, id)`: Btrfs inode numbers are per-subvolume, ext4 uses tree 0.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Ino {
    pub tree: u64,
    pub id: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    CharDev,
    BlockDev,
    Fifo,
    Socket,
    Unknown,
}

impl FileKind {
    /// From the type bits of a Linux `st_mode`.
    pub fn from_mode(mode: u32) -> FileKind {
        match mode & 0xF000 {
            0x8000 => FileKind::File,
            0x4000 => FileKind::Dir,
            0xA000 => FileKind::Symlink,
            0x2000 => FileKind::CharDev,
            0x6000 => FileKind::BlockDev,
            0x1000 => FileKind::Fifo,
            0xC000 => FileKind::Socket,
            _ => FileKind::Unknown,
        }
    }

    /// From the file type stored in a directory entry, which ext and Btrfs number alike.
    pub fn from_dirent(t: u8) -> FileKind {
        match t {
            1 => FileKind::File,
            2 => FileKind::Dir,
            3 => FileKind::CharDev,
            4 => FileKind::BlockDev,
            5 => FileKind::Fifo,
            6 => FileKind::Socket,
            7 => FileKind::Symlink,
            _ => FileKind::Unknown,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Time {
    pub sec: i64,
    pub nsec: u32,
}

impl Time {
    pub fn now() -> Time {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Time { sec: d.as_secs() as i64, nsec: d.subsec_nanos() }
    }
}

#[derive(Clone, Debug)]
pub struct Stat {
    pub ino: Ino,
    pub kind: FileKind,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    /// Bytes actually allocated on disk.
    pub alloc: u64,
    pub atime: Time,
    pub mtime: Time,
    pub ctime: Time,
    pub crtime: Time,
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: Ino,
    pub kind: FileKind,
}

/// What to create in [`Filesystem::create`].
#[derive(Clone, Debug)]
pub enum NewNode<'a> {
    File,
    Dir,
    Symlink(&'a [u8]),
}

#[derive(Clone, Copy, Debug)]
pub struct Owner {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Default, Debug)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<Time>,
    pub mtime: Option<Time>,
    pub crtime: Option<Time>,
}

/// Why a volume is mounted the way it is, shown to the user before anything is written.
#[derive(Clone, Debug, Default)]
pub struct VolumeInfo {
    pub fs_type: String,
    pub label: String,
    pub uuid: String,
    pub block_size: u32,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub read_only: bool,
    /// Human-readable reasons writes are disabled; empty when the volume is writable.
    pub ro_reasons: Vec<String>,
    /// Non-fatal observations (unclean state, journal recovered in memory, ...).
    pub notes: Vec<String>,
    pub features: Vec<String>,
}

/// Mount-time policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct MountOpts {
    /// Ask for write access; the engine still refuses if the volume can't be written safely.
    pub write: bool,
    /// Bytes of metadata cache; 0 picks the default.
    pub cache_bytes: usize,
}

/// A Btrfs subvolume or snapshot linked into a directory.
#[derive(Clone, Debug)]
pub struct Subvolume {
    pub id: u64,
    pub name: Vec<u8>,
    pub read_only: bool,
}

/// The result of a checksum verification pass.
#[derive(Clone, Debug, Default)]
pub struct CheckReport {
    pub scanned_bytes: u64,
    pub errors: Vec<String>,
    pub repaired: u64,
}

pub trait Filesystem: Send + Sync {
    fn info(&self) -> VolumeInfo;
    fn root(&self) -> Ino;
    fn lookup(&self, dir: Ino, name: &[u8]) -> Result<Ino>;
    fn stat(&self, ino: Ino) -> Result<Stat>;
    /// Lists entries from `start` (0 or a cookie previously passed to `out`), excluding
    /// `.` and `..`. `out` receives each entry with the cookie that follows it and
    /// returns false to stop.
    fn read_dir(&self, dir: Ino, start: u64, out: &mut dyn FnMut(u64, DirEntry) -> bool) -> Result<()>;
    /// Reads at `off`, returning the byte count; 0 means end of file.
    fn read(&self, ino: Ino, off: u64, buf: &mut [u8]) -> Result<usize>;
    fn read_link(&self, ino: Ino) -> Result<Vec<u8>>;
    fn list_xattrs(&self, ino: Ino) -> Result<Vec<Vec<u8>>>;
    fn get_xattr(&self, ino: Ino, name: &[u8]) -> Result<Vec<u8>>;

    fn create(&self, dir: Ino, name: &[u8], node: NewNode, owner: Owner) -> Result<Ino>;
    fn link(&self, ino: Ino, dir: Ino, name: &[u8]) -> Result<()>;
    fn unlink(&self, dir: Ino, name: &[u8]) -> Result<()>;
    fn rmdir(&self, dir: Ino, name: &[u8]) -> Result<()>;
    /// Moves an entry; an existing target is replaced only if `replace` is set.
    fn rename(&self, from: Ino, name: &[u8], to: Ino, new_name: &[u8], replace: bool) -> Result<()>;
    fn write(&self, ino: Ino, off: u64, data: &[u8]) -> Result<usize>;
    fn set_attr(&self, ino: Ino, attr: &SetAttr) -> Result<Stat>;
    /// Makes everything so far durable.
    fn sync(&self) -> Result<()>;
    /// Final sync that also marks the volume cleanly unmounted.
    fn unmount(&self) -> Result<()>;
    /// Verifies on-disk checksums, repairing from redundancy where the engine can.
    fn scrub(&self, _progress: &mut dyn FnMut(u64, u64)) -> Result<CheckReport> {
        Err(FsError::Unsupported("scrub is not available for this filesystem".into()))
    }
    /// Btrfs subvolume and snapshot management.
    fn create_subvolume(&self, _dir: Ino, _name: &[u8]) -> Result<Ino> {
        Err(FsError::Unsupported("this filesystem has no subvolumes".into()))
    }
    fn snapshot(&self, _src: Ino, _dir: Ino, _name: &[u8], _read_only: bool) -> Result<Ino> {
        Err(FsError::Unsupported("this filesystem has no snapshots".into()))
    }
    fn subvolumes(&self, _dir: Ino) -> Result<Vec<Subvolume>> {
        Ok(vec![])
    }
    /// Removes a subvolume and everything in it.
    fn delete_subvolume(&self, _dir: Ino, _name: &[u8]) -> Result<()> {
        Err(FsError::Unsupported("this filesystem has no subvolumes".into()))
    }
}

/// Resolves a `/`-separated path from the root without following symlinks.
pub fn resolve(fs: &dyn Filesystem, path: &str) -> Result<Ino> {
    let mut cur = fs.root();
    for part in path.split(['/', '\\']).filter(|p| !p.is_empty() && *p != ".") {
        cur = fs.lookup(cur, part.as_bytes())?;
    }
    Ok(cur)
}
