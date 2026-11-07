//! Serves a [`Filesystem`] to Windows through WinFsp, a Microsoft-signed driver that
//! forwards file requests to this process. That is what lets the engines stay ordinary
//! safe user-mode code: a bug here can crash one mount, not the machine.
//!
//! The DLL is loaded at run time from WinFsp's registered install directory.
use crate::names;
use fscore::{FileKind, Filesystem, FsError, Ino, NewNode, Owner, SetAttr, Stat, Time};
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::GetSecurityDescriptorLength;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY};

type Ntstatus = i32;
type Pwstr = *const u16;
type Fsp = *mut c_void;
type BOOLEAN = u8;

const STATUS_SUCCESS: Ntstatus = 0;
const STATUS_REPARSE: Ntstatus = 0x104;
const STATUS_BUFFER_OVERFLOW: Ntstatus = 0x8000_0005u32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: Ntstatus = 0xC000_0010u32 as i32;
const STATUS_ACCESS_DENIED: Ntstatus = 0xC000_0022u32 as i32;
const STATUS_BUFFER_TOO_SMALL: Ntstatus = 0xC000_0023u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: Ntstatus = 0xC000_0034u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: Ntstatus = 0xC000_0035u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: Ntstatus = 0xC000_003Au32 as i32;
const STATUS_DISK_FULL: Ntstatus = 0xC000_007Fu32 as i32;
const STATUS_MEDIA_WRITE_PROTECTED: Ntstatus = 0xC000_00A2u32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: Ntstatus = 0xC000_00BAu32 as i32;
const STATUS_NOT_SUPPORTED: Ntstatus = 0xC000_00BBu32 as i32;
const STATUS_NOT_SAME_DEVICE: Ntstatus = 0xC000_00D4u32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: Ntstatus = 0xC000_0101u32 as i32;
const STATUS_FILE_CORRUPT_ERROR: Ntstatus = 0xC000_0102u32 as i32;
const STATUS_NOT_A_DIRECTORY: Ntstatus = 0xC000_0103u32 as i32;
const STATUS_NAME_TOO_LONG: Ntstatus = 0xC000_0106u32 as i32;
const STATUS_IO_DEVICE_ERROR: Ntstatus = 0xC000_0185u32 as i32;
const STATUS_TOO_MANY_LINKS: Ntstatus = 0xC000_0265u32 as i32;
const STATUS_NOT_A_REPARSE_POINT: Ntstatus = 0xC000_0275u32 as i32;
const STATUS_INVALID_PARAMETER: Ntstatus = 0xC000_000Du32 as i32;
const STATUS_INTERNAL_ERROR: Ntstatus = 0xC000_00E5u32 as i32;

const FILE_ATTRIBUTE_READONLY: u32 = 1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 2;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_DIRECTORY_FILE: u32 = 1;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const SYMLINK_FLAG_RELATIVE: u32 = 1;
const CLEANUP_DELETE: u32 = 1;

/// Seconds between the Windows and Unix epochs.
const EPOCH_DELTA: i64 = 11_644_473_600;

fn filetime(t: Time) -> u64 {
    ((t.sec + EPOCH_DELTA).max(0) as u64).saturating_mul(10_000_000) + t.nsec as u64 / 100
}

fn from_filetime(v: u64) -> Time {
    Time { sec: (v / 10_000_000) as i64 - EPOCH_DELTA, nsec: (v % 10_000_000) as u32 * 100 }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FileInfo {
    attributes: u32,
    reparse_tag: u32,
    allocation_size: u64,
    file_size: u64,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    index_number: u64,
    hard_links: u32,
    ea_size: u32,
}

#[repr(C)]
struct VolumeInfo {
    total_size: u64,
    free_size: u64,
    label_length: u16,
    label: [u16; 32],
}

#[repr(C)]
struct DirInfoHeader {
    size: u16,
    file_info: FileInfo,
    padding: [u8; 24],
}

type GetReparseByName =
    unsafe extern "system" fn(Fsp, *mut c_void, Pwstr, BOOLEAN, *mut c_void, *mut usize) -> Ntstatus;

/// The entry points used from `winfsp-x64.dll`.
struct Api {
    create: unsafe extern "system" fn(Pwstr, *const u8, *const usize, *mut Fsp) -> Ntstatus,
    delete: unsafe extern "system" fn(Fsp),
    set_mount_point: unsafe extern "system" fn(Fsp, Pwstr) -> Ntstatus,
    start: unsafe extern "system" fn(Fsp, u32) -> Ntstatus,
    stop: unsafe extern "system" fn(Fsp),
    add_dir_info: unsafe extern "system" fn(*mut DirInfoHeader, *mut c_void, u32, *mut u32) -> BOOLEAN,
    find_reparse: unsafe extern "system" fn(Fsp, GetReparseByName, *mut c_void, Pwstr, *mut u32) -> BOOLEAN,
    resolve_reparse: unsafe extern "system" fn(
        Fsp,
        GetReparseByName,
        *mut c_void,
        Pwstr,
        u32,
        BOOLEAN,
        *mut c_void,
        *mut c_void,
        *mut usize,
    ) -> Ntstatus,
}

/// Where WinFsp is installed, from the registry.
pub fn install_dir() -> Option<std::path::PathBuf> {
    let key: Vec<u16> = "SOFTWARE\\WinFsp\0".encode_utf16().collect();
    let val: Vec<u16> = "InstallDir\0".encode_utf16().collect();
    let mut buf = [0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: strings are NUL-terminated and `buf` is sized by `len`.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let n = buf.iter().position(|c| *c == 0).unwrap_or(0);
    Some(String::from_utf16_lossy(&buf[..n]).into())
}

/// Whether the driver is on this machine, without loading it.
pub fn driver_present() -> bool {
    install_dir().is_some_and(|d| d.join("bin").join("winfsp-x64.dll").exists())
}

pub fn available() -> bool {
    api().is_ok()
}

fn api() -> Result<&'static Api, String> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Api, String> {
    let dir = install_dir().ok_or("WinFsp is not installed")?;
    let dll = dir.join("bin").join("winfsp-x64.dll");
    let wide: Vec<u16> = dll.to_string_lossy().encode_utf16().chain([0]).collect();
    // SAFETY: an absolute path from HKLM, so the search path can't substitute a DLL.
    let h = unsafe { LoadLibraryExW(wide.as_ptr(), null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
    if h.is_null() {
        return Err(format!("could not load {}", dll.display()));
    }
    macro_rules! sym {
        ($n:literal) => {{
            // SAFETY: the exported symbol has the signature declared in `Api`.
            match unsafe { GetProcAddress(h, concat!($n, "\0").as_ptr()) } {
                Some(f) => unsafe { std::mem::transmute(f) },
                None => return Err(format!("WinFsp is missing {}", $n)),
            }
        }};
    }
    Ok(Api {
        create: sym!("FspFileSystemCreate"),
        delete: sym!("FspFileSystemDelete"),
        set_mount_point: sym!("FspFileSystemSetMountPoint"),
        start: sym!("FspFileSystemStartDispatcher"),
        stop: sym!("FspFileSystemStopDispatcher"),
        add_dir_info: sym!("FspFileSystemAddDirInfo"),
        find_reparse: sym!("FspFileSystemFindReparsePoint"),
        resolve_reparse: sym!("FspFileSystemResolveReparsePoints"),
    })
}

fn status_of(e: &FsError) -> Ntstatus {
    match e {
        FsError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::Exists => STATUS_OBJECT_NAME_COLLISION,
        FsError::NotDir => STATUS_NOT_A_DIRECTORY,
        FsError::IsDir => STATUS_FILE_IS_A_DIRECTORY,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::NoSpace => STATUS_DISK_FULL,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::NameTooLong => STATUS_NAME_TOO_LONG,
        FsError::TooManyLinks => STATUS_TOO_MANY_LINKS,
        FsError::CrossDevice => STATUS_NOT_SAME_DEVICE,
        FsError::Invalid(_) => STATUS_INVALID_PARAMETER,
        FsError::Corrupt(_) => STATUS_FILE_CORRUPT_ERROR,
        FsError::Unsupported(_) => STATUS_NOT_SUPPORTED,
        FsError::Io(_) => STATUS_IO_DEVICE_ERROR,
    }
}

#[derive(Clone, Debug)]
pub struct HostOptions {
    pub read_only: bool,
    /// Mark dotfiles hidden, the Windows equivalent of how Linux treats them.
    pub hide_dotfiles: bool,
    /// Windows code page for legacy-encoded names; 0 means UTF-8.
    pub codepage: u32,
    /// Owner of newly created files, or inherited from the parent directory.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Default permissions of new files and directories.
    pub file_mode: u32,
    pub dir_mode: u32,
}

impl Default for HostOptions {
    fn default() -> Self {
        HostOptions {
            read_only: true,
            hide_dotfiles: true,
            codepage: 0,
            uid: None,
            gid: None,
            file_mode: 0o644,
            dir_mode: 0o755,
        }
    }
}

/// Live I/O counters, shown as statistics in the interface.
#[derive(Default)]
pub struct Stats {
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub read_bytes: AtomicU64,
    pub written_bytes: AtomicU64,
}

/// One row of a directory listing, sorted for marker-based resumption.
struct Row {
    name: Vec<u16>,
    info: FileInfo,
}

/// Per-open state, referenced by WinFsp as the file context.
struct Handle {
    ino: Ino,
    listing: Mutex<Option<Arc<Vec<Row>>>>,
}

struct Host {
    fs: Arc<dyn Filesystem>,
    opts: HostOptions,
    sd: Vec<u8>,
    label: Vec<u16>,
    block: u64,
    stats: Arc<Stats>,
}

/// Builds the volume's security descriptor. Permissions are per volume rather than per
/// file: Linux uids have no meaning on this machine.
fn security_descriptor(read_only: bool) -> Result<Vec<u8>, String> {
    let users = if read_only { "0x1200A9" } else { "0x1301BF" };
    let sddl = format!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{users};;;AU)\0");
    let wide: Vec<u16> = sddl.encode_utf16().collect();
    let mut p: *mut c_void = null_mut();
    let mut len = 0u32;
    // SAFETY: on success `p` holds a LocalAlloc'd descriptor of `len` bytes.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), 1, &mut p, &mut len) == 0 {
            return Err("could not build the security descriptor".into());
        }
        let v = std::slice::from_raw_parts(p as *const u8, GetSecurityDescriptorLength(p) as usize).to_vec();
        LocalFree(p);
        Ok(v)
    }
}

fn wstr(p: Pwstr) -> &'static [u16] {
    if p.is_null() {
        return &[];
    }
    // SAFETY: WinFsp passes NUL-terminated strings valid for the call.
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        std::slice::from_raw_parts(p, n)
    }
}

fn host(fs: Fsp) -> &'static Host {
    // SAFETY: UserContext sits right after the 8-byte-aligned version field, and holds the
    // `Host` that outlives the dispatcher.
    unsafe { &*(*(fs as *const *const Host).add(1)) }
}

fn handle(ctx: *mut c_void) -> &'static Handle {
    // SAFETY: contexts are Box<Handle> pointers handed out by Open/Create until Close.
    unsafe { &*(ctx as *const Handle) }
}

/// Keeps a Rust panic from unwinding into C. An engine bug fails the one request.
fn guard(f: impl FnOnce() -> Ntstatus) -> Ntstatus {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(STATUS_INTERNAL_ERROR)
}

impl Host {
    fn components<'a>(&self, path: &'a [u16]) -> impl Iterator<Item = &'a [u16]> {
        path.split(|c| *c == u16::from(b'\\')).filter(|p| !p.is_empty())
    }

    fn to_linux(&self, name: &[u16]) -> Result<Vec<u8>, Ntstatus> {
        names::from_wide(name, self.opts.codepage).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    /// Resolves a path, returning the inode and its parent.
    fn walk(&self, path: &[u16]) -> Result<(Ino, Ino), Ntstatus> {
        let root = self.fs.root();
        let (mut cur, mut parent) = (root, root);
        let parts: Vec<&[u16]> = self.components(path).collect();
        for (i, part) in parts.iter().enumerate() {
            let name = self.to_linux(part)?;
            parent = cur;
            cur = self.fs.lookup(cur, &name).map_err(|e| match e {
                FsError::NotFound if i + 1 < parts.len() => STATUS_OBJECT_PATH_NOT_FOUND,
                e => status_of(&e),
            })?;
        }
        Ok((cur, parent))
    }

    /// Splits a path into its parent directory and final name.
    fn parent_and_name(&self, path: &[u16]) -> Result<(Ino, Vec<u8>), Ntstatus> {
        let cut = path.iter().rposition(|c| *c == u16::from(b'\\')).unwrap_or(0);
        let (dir, _) = self.walk(&path[..cut])?;
        Ok((dir, self.to_linux(&path[(cut + 1).min(path.len())..])?))
    }

    fn file_info(&self, st: &Stat, name: Option<&[u8]>) -> FileInfo {
        let mut attributes = match st.kind {
            FileKind::Dir => FILE_ATTRIBUTE_DIRECTORY,
            _ => 0,
        };
        let mut reparse_tag = 0;
        if st.kind == FileKind::Symlink {
            attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
            reparse_tag = IO_REPARSE_TAG_SYMLINK;
        }
        if st.mode & 0o222 == 0 && st.kind != FileKind::Dir {
            attributes |= FILE_ATTRIBUTE_READONLY;
        }
        if self.opts.hide_dotfiles && name.is_some_and(|n| n.first() == Some(&b'.') && n != b"." && n != b"..") {
            attributes |= FILE_ATTRIBUTE_HIDDEN;
        }
        if attributes == 0 {
            attributes = FILE_ATTRIBUTE_NORMAL;
        }
        let special = !matches!(st.kind, FileKind::File | FileKind::Dir | FileKind::Symlink);
        let size = if special { 0 } else { st.size };
        FileInfo {
            attributes,
            reparse_tag,
            allocation_size: size.div_ceil(self.block) * self.block,
            file_size: size,
            creation_time: filetime(st.crtime),
            last_access_time: filetime(st.atime),
            last_write_time: filetime(st.mtime),
            change_time: filetime(st.ctime),
            index_number: st.ino.id ^ st.ino.tree.rotate_left(48),
            hard_links: 0,
            ea_size: 0,
        }
    }

    fn fill(&self, out: *mut FileInfo, ino: Ino) -> Ntstatus {
        match self.fs.stat(ino) {
            Ok(st) => {
                // SAFETY: WinFsp provides a valid FileInfo for the call.
                unsafe { *out = self.file_info(&st, None) };
                STATUS_SUCCESS
            }
            Err(e) => status_of(&e),
        }
    }

    fn owner_for(&self, dir: Ino, mode: u32) -> Owner {
        let st = self.fs.stat(dir).ok();
        Owner {
            mode,
            uid: self.opts.uid.or(st.as_ref().map(|s| s.uid)).unwrap_or(0),
            gid: self.opts.gid.or(st.as_ref().map(|s| s.gid)).unwrap_or(0),
        }
    }

    /// Builds the listing `.`, `..`, then entries in code-unit order.
    fn list(&self, h: &Handle, root: bool) -> Result<Arc<Vec<Row>>, Ntstatus> {
        let mut ents = vec![];
        self.fs
            .read_dir(h.ino, 0, &mut |_, e| {
                ents.push(e);
                true
            })
            .map_err(|e| status_of(&e))?;
        let mut rows = Vec::with_capacity(ents.len() + 2);
        for e in ents {
            let Ok(st) = self.fs.stat(e.ino) else { continue };
            let info = self.file_info(&st, Some(&e.name));
            rows.push(Row { name: names::to_wide(&e.name, self.opts.codepage), info });
        }
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        if !root {
            let dot = self.fs.stat(h.ino).map(|s| self.file_info(&s, None)).unwrap_or_default();
            rows.insert(0, Row { name: vec![b'.' as u16, b'.' as u16], info: dot });
            rows.insert(0, Row { name: vec![b'.' as u16], info: dot });
        }
        Ok(Arc::new(rows))
    }

    /// Reparse data for the symlink at `path`, confined to the volume.
    fn link_data(&self, path: &[u16], ino: Ino) -> Result<Vec<u8>, Ntstatus> {
        let target = self.fs.read_link(ino).map_err(|e| status_of(&e))?;
        let mut dir: Vec<Vec<u8>> = vec![];
        let parts: Vec<&[u16]> = self.components(path).collect();
        for p in &parts[..parts.len().saturating_sub(1)] {
            dir.push(self.to_linux(p)?);
        }
        let name = names::safe_link_target(&dir, &target, self.opts.codepage);
        let bytes = name.len() * 2;
        let mut b = Vec::with_capacity(20 + bytes);
        b.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
        b.extend_from_slice(&((12 + bytes) as u16).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(bytes as u16).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(bytes as u16).to_le_bytes());
        b.extend_from_slice(&SYMLINK_FLAG_RELATIVE.to_le_bytes());
        for c in &name {
            b.extend_from_slice(&c.to_le_bytes());
        }
        Ok(b)
    }
}

unsafe extern "system" fn get_volume_info(fs: Fsp, out: *mut VolumeInfo) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        let info = h.fs.info();
        // SAFETY: WinFsp provides a valid VolumeInfo.
        let v = unsafe { &mut *out };
        v.total_size = info.total_bytes;
        v.free_size = info.free_bytes;
        let n = h.label.len().min(32);
        v.label[..n].copy_from_slice(&h.label[..n]);
        v.label_length = (n * 2) as u16;
        STATUS_SUCCESS
    })
}

unsafe extern "system" fn get_reparse_by_name(
    fs: Fsp,
    _ctx: *mut c_void,
    name: Pwstr,
    _is_dir: BOOLEAN,
    buffer: *mut c_void,
    size: *mut usize,
) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        let path = wstr(name);
        let ino = match h.walk(path) {
            Ok((i, _)) => i,
            Err(s) => return s,
        };
        match h.fs.stat(ino) {
            Ok(st) if st.kind == FileKind::Symlink => {}
            Ok(_) => return STATUS_NOT_A_REPARSE_POINT,
            Err(e) => return status_of(&e),
        }
        if buffer.is_null() {
            return STATUS_SUCCESS;
        }
        match h.link_data(path, ino) {
            Ok(d) => copy_reparse(&d, buffer, size),
            Err(s) => s,
        }
    })
}

fn copy_reparse(d: &[u8], buffer: *mut c_void, size: *mut usize) -> Ntstatus {
    // SAFETY: `size` holds the capacity of `buffer`, both supplied by WinFsp.
    unsafe {
        if d.len() > *size {
            return STATUS_BUFFER_TOO_SMALL;
        }
        *size = d.len();
        std::ptr::copy_nonoverlapping(d.as_ptr(), buffer as *mut u8, d.len());
    }
    STATUS_SUCCESS
}

unsafe extern "system" fn get_security_by_name(
    fs: Fsp,
    name: Pwstr,
    attrs: *mut u32,
    sd: *mut c_void,
    sd_size: *mut usize,
) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        let a = api().expect("api is loaded before mounting");
        // SAFETY: arguments are forwarded unchanged from WinFsp.
        if unsafe { (a.find_reparse)(fs, get_reparse_by_name, null_mut(), name, attrs) } != 0 {
            return STATUS_REPARSE;
        }
        let path = wstr(name);
        let (ino, _) = match h.walk(path) {
            Ok(v) => v,
            Err(s) => return s,
        };
        let st = match h.fs.stat(ino) {
            Ok(s) => s,
            Err(e) => return status_of(&e),
        };
        let leaf = h.components(path).last().and_then(|n| h.to_linux(n).ok());
        // SAFETY: the out-pointers are optional and valid when non-null.
        unsafe {
            if !attrs.is_null() {
                *attrs = h.file_info(&st, leaf.as_deref()).attributes;
            }
            if !sd_size.is_null() {
                if h.sd.len() > *sd_size {
                    *sd_size = h.sd.len();
                    return STATUS_BUFFER_OVERFLOW;
                }
                *sd_size = h.sd.len();
                if !sd.is_null() {
                    std::ptr::copy_nonoverlapping(h.sd.as_ptr(), sd as *mut u8, h.sd.len());
                }
            }
        }
        STATUS_SUCCESS
    })
}

fn new_handle(ino: Ino, out: *mut *mut c_void) {
    let b = Box::new(Handle { ino, listing: Mutex::new(None) });
    // SAFETY: `out` is the file-context slot provided by WinFsp.
    unsafe { *out = Box::into_raw(b).cast() };
}

unsafe extern "system" fn create(
    fs: Fsp,
    name: Pwstr,
    options: u32,
    _access: u32,
    _attrs: u32,
    _sd: *mut c_void,
    _alloc: u64,
    ctx: *mut *mut c_void,
    info: *mut FileInfo,
) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        if h.opts.read_only {
            return STATUS_MEDIA_WRITE_PROTECTED;
        }
        let (dir, leaf) = match h.parent_and_name(wstr(name)) {
            Ok(v) => v,
            Err(s) => return s,
        };
        let is_dir = options & FILE_DIRECTORY_FILE != 0;
        let mode = if is_dir { h.opts.dir_mode } else { h.opts.file_mode };
        let node = if is_dir { NewNode::Dir } else { NewNode::File };
        match h.fs.create(dir, &leaf, node, h.owner_for(dir, mode)) {
            Ok(ino) => {
                new_handle(ino, ctx);
                h.fill(info, ino)
            }
            Err(e) => status_of(&e),
        }
    })
}

unsafe extern "system" fn open(
    fs: Fsp,
    name: Pwstr,
    _options: u32,
    _access: u32,
    ctx: *mut *mut c_void,
    info: *mut FileInfo,
) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        let ino = match h.walk(wstr(name)) {
            Ok(v) => v.0,
            Err(s) => return s,
        };
        let s = h.fill(info, ino);
        if s == STATUS_SUCCESS {
            new_handle(ino, ctx);
        }
        s
    })
}

unsafe extern "system" fn overwrite(
    fs: Fsp,
    ctx: *mut c_void,
    _attrs: u32,
    _replace: BOOLEAN,
    _alloc: u64,
    info: *mut FileInfo,
) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        let attr = SetAttr { size: Some(0), ..SetAttr::default() };
        match h.fs.set_attr(f.ino, &attr) {
            Ok(_) => h.fill(info, f.ino),
            Err(e) => status_of(&e),
        }
    })
}

unsafe extern "system" fn cleanup(fs: Fsp, ctx: *mut c_void, name: Pwstr, flags: u32) {
    guard(|| {
        if flags & CLEANUP_DELETE == 0 || name.is_null() {
            return STATUS_SUCCESS;
        }
        let (h, f) = (host(fs), handle(ctx));
        let Ok((dir, leaf)) = h.parent_and_name(wstr(name)) else { return STATUS_SUCCESS };
        let is_dir = h.fs.stat(f.ino).is_ok_and(|s| s.kind == FileKind::Dir);
        let r = if is_dir { h.fs.rmdir(dir, &leaf) } else { h.fs.unlink(dir, &leaf) };
        r.map_or_else(|e| status_of(&e), |()| STATUS_SUCCESS)
    });
}

unsafe extern "system" fn close(_fs: Fsp, ctx: *mut c_void) {
    if !ctx.is_null() {
        // SAFETY: reclaims the Box from `new_handle`; WinFsp closes each context once.
        drop(unsafe { Box::from_raw(ctx as *mut Handle) });
    }
}

unsafe extern "system" fn read(
    fs: Fsp,
    ctx: *mut c_void,
    buffer: *mut u8,
    offset: u64,
    length: u32,
    done: *mut u32,
) -> Ntstatus {
    const STATUS_END_OF_FILE: Ntstatus = 0xC000_0011u32 as i32;
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        // SAFETY: WinFsp provides `length` writable bytes at `buffer`.
        let dst = unsafe { std::slice::from_raw_parts_mut(buffer, length as usize) };
        match h.fs.read(f.ino, offset, dst) {
            Ok(0) if length > 0 => STATUS_END_OF_FILE,
            Ok(n) => {
                h.stats.reads.fetch_add(1, Ordering::Relaxed);
                h.stats.read_bytes.fetch_add(n as u64, Ordering::Relaxed);
                // SAFETY: `done` is a valid out-pointer.
                unsafe { *done = n as u32 };
                STATUS_SUCCESS
            }
            Err(e) => status_of(&e),
        }
    })
}

unsafe extern "system" fn write(
    fs: Fsp,
    ctx: *mut c_void,
    buffer: *const u8,
    offset: u64,
    length: u32,
    to_end: BOOLEAN,
    constrained: BOOLEAN,
    done: *mut u32,
    info: *mut FileInfo,
) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        let size = match h.fs.stat(f.ino) {
            Ok(s) => s.size,
            Err(e) => return status_of(&e),
        };
        let mut off = if to_end != 0 { size } else { offset };
        let mut len = length as u64;
        // Paging writes must not extend the file.
        if constrained != 0 {
            if off >= size {
                // SAFETY: valid out-pointer.
                unsafe { *done = 0 };
                return h.fill(info, f.ino);
            }
            len = len.min(size - off);
        }
        // SAFETY: WinFsp provides `length` readable bytes at `buffer`.
        let src = unsafe { std::slice::from_raw_parts(buffer, len as usize) };
        let mut written = 0;
        while written < src.len() {
            match h.fs.write(f.ino, off, &src[written..]) {
                Ok(0) => break,
                Ok(n) => {
                    written += n;
                    off += n as u64;
                }
                Err(FsError::NoSpace) if written > 0 => break,
                Err(e) => return status_of(&e),
            }
        }
        h.stats.writes.fetch_add(1, Ordering::Relaxed);
        h.stats.written_bytes.fetch_add(written as u64, Ordering::Relaxed);
        // SAFETY: valid out-pointer.
        unsafe { *done = written as u32 };
        h.fill(info, f.ino)
    })
}

unsafe extern "system" fn flush(fs: Fsp, ctx: *mut c_void, info: *mut FileInfo) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        if let Err(e) = h.fs.sync() {
            return status_of(&e);
        }
        if ctx.is_null() {
            return STATUS_SUCCESS;
        }
        h.fill(info, handle(ctx).ino)
    })
}

unsafe extern "system" fn get_file_info(fs: Fsp, ctx: *mut c_void, info: *mut FileInfo) -> Ntstatus {
    guard(|| host(fs).fill(info, handle(ctx).ino))
}

unsafe extern "system" fn set_basic_info(
    fs: Fsp,
    ctx: *mut c_void,
    attrs: u32,
    created: u64,
    accessed: u64,
    written: u64,
    _changed: u64,
    info: *mut FileInfo,
) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        let time = |v: u64| (v != 0).then(|| from_filetime(v));
        let mut a = SetAttr { crtime: time(created), atime: time(accessed), mtime: time(written), ..SetAttr::default() };
        if attrs != u32::MAX {
            if let Ok(st) = h.fs.stat(f.ino) {
                let ro = attrs & FILE_ATTRIBUTE_READONLY != 0;
                if ro && st.mode & 0o222 != 0 {
                    a.mode = Some(st.mode & !0o222);
                } else if !ro && st.mode & 0o222 == 0 {
                    a.mode = Some(st.mode | 0o200);
                }
            }
        }
        match h.fs.set_attr(f.ino, &a) {
            Ok(_) => h.fill(info, f.ino),
            Err(e) => status_of(&e),
        }
    })
}

unsafe extern "system" fn set_file_size(
    fs: Fsp,
    ctx: *mut c_void,
    new_size: u64,
    allocation: BOOLEAN,
    info: *mut FileInfo,
) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        // Allocation requests come ahead of cached writes. The engines allocate lazily, so
        // this is the last chance to report a full disk to the application: once the data
        // is in the cache, a failure would only surface as a lost delayed write.
        if allocation != 0 {
            let Ok(st) = h.fs.stat(f.ino) else { return STATUS_IO_DEVICE_ERROR };
            if new_size >= st.size {
                let need = new_size.saturating_sub(st.alloc);
                if need > 0 && need > h.fs.info().free_bytes {
                    return STATUS_DISK_FULL;
                }
                return h.fill(info, f.ino);
            }
        }
        let a = SetAttr { size: Some(new_size), ..SetAttr::default() };
        match h.fs.set_attr(f.ino, &a) {
            Ok(_) => h.fill(info, f.ino),
            Err(e) => status_of(&e),
        }
    })
}

unsafe extern "system" fn can_delete(fs: Fsp, ctx: *mut c_void, _name: Pwstr) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        if h.opts.read_only {
            return STATUS_MEDIA_WRITE_PROTECTED;
        }
        match h.fs.stat(f.ino) {
            Ok(s) if s.kind == FileKind::Dir => {
                let mut empty = true;
                let r = h.fs.read_dir(f.ino, 0, &mut |_, _| {
                    empty = false;
                    false
                });
                match r {
                    Err(e) => status_of(&e),
                    Ok(()) if !empty => STATUS_DIRECTORY_NOT_EMPTY,
                    Ok(()) => STATUS_SUCCESS,
                }
            }
            Ok(_) => STATUS_SUCCESS,
            Err(e) => status_of(&e),
        }
    })
}

unsafe extern "system" fn rename(fs: Fsp, _ctx: *mut c_void, name: Pwstr, new_name: Pwstr, replace: BOOLEAN) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        let from = h.parent_and_name(wstr(name));
        let to = h.parent_and_name(wstr(new_name));
        let (Ok((fd, fnm)), Ok((td, tn))) = (from, to) else { return STATUS_OBJECT_PATH_NOT_FOUND };
        h.fs.rename(fd, &fnm, td, &tn, replace != 0).map_or_else(|e| status_of(&e), |()| STATUS_SUCCESS)
    })
}

unsafe extern "system" fn get_security(fs: Fsp, _ctx: *mut c_void, sd: *mut c_void, size: *mut usize) -> Ntstatus {
    guard(|| {
        let h = host(fs);
        // SAFETY: `size` is valid, `sd` has that capacity when non-null.
        unsafe {
            if h.sd.len() > *size {
                *size = h.sd.len();
                return STATUS_BUFFER_OVERFLOW;
            }
            *size = h.sd.len();
            if !sd.is_null() {
                std::ptr::copy_nonoverlapping(h.sd.as_ptr(), sd as *mut u8, h.sd.len());
            }
        }
        STATUS_SUCCESS
    })
}

/// ACLs have nowhere to live on these volumes. Accepting the call keeps applications
/// that re-apply a file's ACL after saving working; documented in the user guide.
unsafe extern "system" fn set_security(_fs: Fsp, _ctx: *mut c_void, _info: u32, _sd: *mut c_void) -> Ntstatus {
    STATUS_SUCCESS
}

unsafe extern "system" fn read_directory(
    fs: Fsp,
    ctx: *mut c_void,
    _pattern: Pwstr,
    marker: Pwstr,
    buffer: *mut c_void,
    length: u32,
    done: *mut u32,
) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        let a = api().expect("api is loaded before mounting");
        let is_root = h.fs.root() == f.ino;
        let mut slot = f.listing.lock().unwrap_or_else(|e| e.into_inner());
        // A fresh enumeration re-reads the directory; a continuation reuses the snapshot.
        if marker.is_null() || slot.is_none() {
            *slot = match h.list(f, is_root) {
                Ok(r) => Some(r),
                Err(s) => return s,
            };
        }
        let rows = slot.clone().unwrap_or_default();
        drop(slot);
        let start = if marker.is_null() {
            0
        } else {
            let m = wstr(marker);
            let dots = rows.iter().take_while(|r| r.name == [46] || r.name == [46, 46]).count();
            match m {
                [46] => 1,
                [46, 46] => 2,
                _ => dots + rows[dots..].partition_point(|r| r.name.as_slice() <= m),
            }
        };
        let mut scratch = vec![0u8; size_of::<DirInfoHeader>() + 512 * 2];
        for r in &rows[start.min(rows.len())..] {
            let size = size_of::<DirInfoHeader>() + r.name.len() * 2;
            if size > scratch.len() {
                continue;
            }
            scratch[..size_of::<DirInfoHeader>()].fill(0);
            let d = scratch.as_mut_ptr() as *mut DirInfoHeader;
            // SAFETY: `scratch` holds the header and name; unaligned-safe writes via ptr.
            unsafe {
                std::ptr::addr_of_mut!((*d).size).write_unaligned(size as u16);
                std::ptr::addr_of_mut!((*d).file_info).write_unaligned(r.info);
                std::ptr::copy_nonoverlapping(
                    r.name.as_ptr() as *const u8,
                    scratch.as_mut_ptr().add(size_of::<DirInfoHeader>()),
                    r.name.len() * 2,
                );
                if (a.add_dir_info)(d, buffer, length, done) == 0 {
                    return STATUS_SUCCESS;
                }
            }
        }
        // SAFETY: a null entry marks the end of the listing.
        unsafe { (a.add_dir_info)(null_mut(), buffer, length, done) };
        STATUS_SUCCESS
    })
}

unsafe extern "system" fn resolve_reparse_points(
    fs: Fsp,
    name: Pwstr,
    index: u32,
    last: BOOLEAN,
    io_status: *mut c_void,
    buffer: *mut c_void,
    size: *mut usize,
) -> Ntstatus {
    guard(|| {
        let a = api().expect("api is loaded before mounting");
        // SAFETY: arguments are forwarded unchanged from WinFsp.
        unsafe { (a.resolve_reparse)(fs, get_reparse_by_name, null_mut(), name, index, last, io_status, buffer, size) }
    })
}

unsafe extern "system" fn get_reparse_point(
    fs: Fsp,
    ctx: *mut c_void,
    name: Pwstr,
    buffer: *mut c_void,
    size: *mut usize,
) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        match h.link_data(wstr(name), f.ino) {
            Ok(d) => copy_reparse(&d, buffer, size),
            Err(s) => s,
        }
    })
}

unsafe extern "system" fn set_reparse_point(
    fs: Fsp,
    ctx: *mut c_void,
    name: Pwstr,
    buffer: *const u8,
    size: usize,
) -> Ntstatus {
    guard(|| {
        let (h, f) = (host(fs), handle(ctx));
        if h.opts.read_only {
            return STATUS_MEDIA_WRITE_PROTECTED;
        }
        // SAFETY: WinFsp provides `size` readable bytes.
        let d = unsafe { std::slice::from_raw_parts(buffer, size) };
        let rd = |o: usize| d.get(o..o + 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]])) as usize;
        if size < 20 || d[..4] != IO_REPARSE_TAG_SYMLINK.to_le_bytes() {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        let (off, len) = (20 + rd(8), rd(10));
        let Some(raw) = d.get(off..off + len) else { return STATUS_INVALID_PARAMETER };
        let wide: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let Some(target) = names::link_from_windows(&wide, h.opts.codepage) else { return STATUS_ACCESS_DENIED };
        let (dir, leaf) = match h.parent_and_name(wstr(name)) {
            Ok(v) => v,
            Err(s) => return s,
        };
        // Windows creates an empty file first; it becomes the symlink here.
        if h.fs.stat(f.ino).map_or(true, |s| s.size != 0) {
            return STATUS_ACCESS_DENIED;
        }
        let own = h.owner_for(dir, 0o777);
        let r = h.fs.unlink(dir, &leaf).and_then(|()| h.fs.create(dir, &leaf, NewNode::Symlink(&target), own));
        r.map_or_else(|e| status_of(&e), |_| STATUS_SUCCESS)
    })
}

unsafe extern "system" fn delete_reparse_point(_fs: Fsp, _ctx: *mut c_void, _name: Pwstr, _b: *const u8, _s: usize) -> Ntstatus {
    STATUS_INVALID_DEVICE_REQUEST
}

fn interface() -> [usize; 64] {
    let mut t = [0usize; 64];
    t[0] = get_volume_info as *const () as usize;
    t[2] = get_security_by_name as *const () as usize;
    t[3] = create as *const () as usize;
    t[4] = open as *const () as usize;
    t[5] = overwrite as *const () as usize;
    t[6] = cleanup as *const () as usize;
    t[7] = close as *const () as usize;
    t[8] = read as *const () as usize;
    t[9] = write as *const () as usize;
    t[10] = flush as *const () as usize;
    t[11] = get_file_info as *const () as usize;
    t[12] = set_basic_info as *const () as usize;
    t[13] = set_file_size as *const () as usize;
    t[14] = can_delete as *const () as usize;
    t[15] = rename as *const () as usize;
    t[16] = get_security as *const () as usize;
    t[17] = set_security as *const () as usize;
    t[18] = read_directory as *const () as usize;
    t[19] = resolve_reparse_points as *const () as usize;
    t[20] = get_reparse_point as *const () as usize;
    t[21] = set_reparse_point as *const () as usize;
    t[22] = delete_reparse_point as *const () as usize;
    t
}

/// FSP_FSCTL_VOLUME_PARAMS as bytes; a byte image avoids mirroring its bitfields.
fn volume_params(fs_name: &str, block: u32, serial: u32, read_only: bool) -> Vec<u8> {
    let mut p = vec![0u8; 504];
    let put16 = |p: &mut [u8], o: usize, v: u16| p[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |p: &mut [u8], o: usize, v: u32| p[o..o + 4].copy_from_slice(&v.to_le_bytes());
    put16(&mut p, 0, 504);
    put16(&mut p, 2, 512);
    put16(&mut p, 4, (block / 512).max(1) as u16);
    put16(&mut p, 6, 255);
    put32(&mut p, 16, serial);
    put32(&mut p, 32, 1000); // FileInfoTimeout: let the kernel cache metadata for a second.
    let mut flags = 0u32;
    for bit in [0, 1, 2, 3, 4, 16] {
        // Case sensitive and preserving, Unicode, ACLs, reparse points, UserContext2.
        flags |= 1 << bit;
    }
    if read_only {
        flags |= 1 << 9;
    }
    put32(&mut p, 36, flags);
    for (i, c) in fs_name.encode_utf16().take(15).enumerate() {
        put16(&mut p, 424 + i * 2, c);
    }
    p
}

/// A running mount. Dropping it stops serving and detaches the drive letter.
pub struct Mount {
    fsp: Fsp,
    host: *mut Host,
    /// Kept alive for as long as WinFsp may read it.
    _iface: Box<[usize; 64]>,
    pub stats: Arc<Stats>,
    pub mount_point: String,
}

// SAFETY: the raw pointers are only used by `drop`; WinFsp's handle is thread-safe.
unsafe impl Send for Mount {}
unsafe impl Sync for Mount {}

impl Mount {
    /// Starts serving `fs` at `mount_point`, such as `X:` or a directory.
    pub fn start(fs: Arc<dyn Filesystem>, mount_point: &str, opts: HostOptions) -> Result<Mount, String> {
        let a = api()?;
        let info = fs.info();
        let read_only = opts.read_only || info.read_only;
        let opts = HostOptions { read_only, ..opts };
        let sd = security_descriptor(read_only)?;
        let stats = Arc::new(Stats::default());
        let block = info.block_size.max(512);
        let serial = info.uuid.bytes().fold(0x811C_9DC5u32, |h, b| (h ^ b as u32).wrapping_mul(16_777_619));
        let label = if info.label.is_empty() { info.fs_type.clone() } else { info.label.clone() };
        let name = info.fs_type.to_uppercase();
        let host = Box::into_raw(Box::new(Host {
            fs,
            opts,
            sd,
            label: label.encode_utf16().collect(),
            block: block as u64,
            stats: stats.clone(),
        }));
        let params = volume_params(&name, block, serial, read_only);
        let iface = Box::new(interface());
        let device: Vec<u16> = "WinFsp.Disk\0".encode_utf16().collect();
        let mut fsp: Fsp = null_mut();
        // SAFETY: `params` and `iface` have the layouts WinFsp documents; `fsp` is an out-pointer.
        let rc = unsafe { (a.create)(device.as_ptr(), params.as_ptr(), iface.as_ptr(), &mut fsp) };
        if rc < 0 {
            // SAFETY: nothing else references `host` yet.
            drop(unsafe { Box::from_raw(host) });
            return Err(format!("WinFsp refused the volume ({rc:#010x})"));
        }
        // SAFETY: UserContext is the pointer-sized field after the version.
        unsafe { *(fsp as *mut *mut Host).add(1) = host };
        let mp: Vec<u16> = mount_point.encode_utf16().chain([0]).collect();
        // SAFETY: `fsp` is live and `mp` is NUL-terminated.
        unsafe {
            let rc = (a.set_mount_point)(fsp, if mount_point.is_empty() { null() } else { mp.as_ptr() });
            if rc < 0 {
                (a.delete)(fsp);
                drop(Box::from_raw(host));
                return Err(format!("could not mount at {mount_point} ({rc:#010x})"));
            }
            let rc = (a.start)(fsp, 0);
            if rc < 0 {
                (a.delete)(fsp);
                drop(Box::from_raw(host));
                return Err(format!("could not start serving ({rc:#010x})"));
            }
        }
        Ok(Mount { fsp, host, _iface: iface, stats, mount_point: mount_point.to_string() })
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let Ok(a) = api() else { return };
        // SAFETY: stopping joins the dispatcher, so no callback can see `host` afterwards.
        unsafe {
            (a.stop)(self.fsp);
            (a.delete)(self.fsp);
            drop(Box::from_raw(self.host));
        }
    }
}
