//! Physical disks: enumeration, and raw access with the alignment Windows requires.
use fscore::part::{probe, FsKind};
use fscore::{BlockDev, FsError, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, GetLogicalDrives, ReadFile, WriteFile, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::*;
use windows_sys::Win32::System::IO::{DeviceIoControl, OVERLAPPED};

/// An owned handle to a disk or partition.
struct Raw(HANDLE);

// SAFETY: Windows handles may be used from any thread; I/O here is positional.
unsafe impl Send for Raw {}
unsafe impl Sync for Raw {}

impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

fn open_raw(path: &str, write: bool) -> Result<Raw> {
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let access = GENERIC_READ | if write { GENERIC_WRITE } else { 0 };
    // SAFETY: `wide` is NUL-terminated.
    let h = unsafe {
        CreateFileW(wide.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, null(), OPEN_EXISTING, 0, null_mut())
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Raw(h))
}

fn ioctl<T>(h: &Raw, code: u32, input: &[u8]) -> Option<T> {
    // SAFETY: T is a plain C struct for which all-zero is valid.
    let mut out: T = unsafe { zeroed() };
    let mut n = 0;
    // SAFETY: buffers are sized by the lengths passed.
    let ok = unsafe {
        DeviceIoControl(
            h.0,
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            (&raw mut out).cast(),
            size_of::<T>() as u32,
            &mut n,
            null_mut(),
        )
    };
    (ok != 0).then_some(out)
}

/// A partition or disk as a [`BlockDev`]. Windows only accepts sector-aligned raw I/O, so
/// unaligned requests go through a bounce buffer.
pub struct RawDev {
    h: Raw,
    len: u64,
    sector: u64,
    writable: bool,
    /// Serialises read-modify-write of shared sectors.
    rmw: Mutex<()>,
}

impl RawDev {
    /// Opens a partition. With `write`, the volume is locked so nothing else can touch it
    /// while it is mounted, the guard against simultaneous writers.
    pub fn open(disk: u32, part: u32, write: bool) -> Result<RawDev> {
        let h = open_raw(&format!(r"\\?\GLOBALROOT\Device\Harddisk{disk}\Partition{part}"), write)?;
        let len: GET_LENGTH_INFORMATION = ioctl(&h, IOCTL_DISK_GET_LENGTH_INFO, &[])
            .ok_or_else(|| FsError::Unsupported("could not read the partition size".into()))?;
        let geo: Option<DISK_GEOMETRY_EX> = ioctl(&h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[]);
        let sector = geo.map_or(512, |g| g.Geometry.BytesPerSector as u64).max(512);
        if write {
            let mut n = 0;
            // SAFETY: FSCTL_LOCK_VOLUME takes no buffers.
            let ok = unsafe { DeviceIoControl(h.0, FSCTL_LOCK_VOLUME, null(), 0, null_mut(), 0, &mut n, null_mut()) };
            if ok == 0 {
                return Err(FsError::Unsupported(
                    "the partition is in use by another program, close it and try again".into(),
                ));
            }
        }
        Ok(RawDev { h, len: len.Length as u64, sector, writable: write, rmw: Mutex::new(()) })
    }

    fn pread(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        // SAFETY: an all-zero OVERLAPPED is valid; offset is then set.
        let mut o: OVERLAPPED = unsafe { zeroed() };
        o.Anonymous.Anonymous.Offset = off as u32;
        o.Anonymous.Anonymous.OffsetHigh = (off >> 32) as u32;
        let mut n = 0;
        // SAFETY: `buf` is writable for the length passed.
        let ok = unsafe { ReadFile(self.h.0, buf.as_mut_ptr(), buf.len() as u32, &mut n, &mut o) };
        if ok == 0 || n as usize != buf.len() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn pwrite(&self, off: u64, data: &[u8]) -> Result<()> {
        // SAFETY: as in `pread`.
        let mut o: OVERLAPPED = unsafe { zeroed() };
        o.Anonymous.Anonymous.Offset = off as u32;
        o.Anonymous.Anonymous.OffsetHigh = (off >> 32) as u32;
        let mut n = 0;
        // SAFETY: `data` is readable for the length passed.
        let ok = unsafe { WriteFile(self.h.0, data.as_ptr(), data.len() as u32, &mut n, &mut o) };
        if ok == 0 || n as usize != data.len() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn check(&self, off: u64, n: usize) -> Result<()> {
        if off.checked_add(n as u64).is_none_or(|e| e > self.len) {
            return Err(FsError::Corrupt(format!("access at {off:#x} is past the end of the device")));
        }
        Ok(())
    }

    fn aligned(&self, off: u64, n: usize) -> bool {
        off % self.sector == 0 && n as u64 % self.sector == 0
    }

    fn span(&self, off: u64, n: usize) -> (u64, usize) {
        let lo = off / self.sector * self.sector;
        let hi = (off + n as u64).div_ceil(self.sector) * self.sector;
        (lo, (hi - lo) as usize)
    }
}

impl BlockDev for RawDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.check(off, buf.len())?;
        if self.aligned(off, buf.len()) {
            return self.pread(off, buf);
        }
        let (lo, n) = self.span(off, buf.len());
        let mut tmp = vec![0u8; n];
        self.pread(lo, &mut tmp)?;
        let s = (off - lo) as usize;
        buf.copy_from_slice(&tmp[s..s + buf.len()]);
        Ok(())
    }

    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        if !self.writable {
            return Err(FsError::ReadOnly);
        }
        self.check(off, data.len())?;
        if self.aligned(off, data.len()) {
            return self.pwrite(off, data);
        }
        let _guard = self.rmw.lock().unwrap_or_else(|e| e.into_inner());
        let (lo, n) = self.span(off, data.len());
        let mut tmp = vec![0u8; n];
        self.pread(lo, &mut tmp)?;
        let s = (off - lo) as usize;
        tmp[s..s + data.len()].copy_from_slice(data);
        self.pwrite(lo, &tmp)
    }

    fn flush(&self) -> Result<()> {
        if self.writable {
            // SAFETY: the handle is valid.
            if unsafe { FlushFileBuffers(self.h.0) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn writable(&self) -> bool {
        self.writable
    }
}

/// A partition found on a physical disk.
#[derive(Clone, Debug)]
pub struct FoundPartition {
    pub disk: u32,
    pub part: u32,
    pub disk_name: String,
    pub size: u64,
    pub kind: FsKind,
    pub letter: Option<char>,
    pub removable: bool,
}

fn disk_name(h: &Raw) -> (String, bool) {
    let query = [0u8; 12]; // StorageDeviceProperty, PropertyStandardQuery.
    let mut buf = vec![0u8; 1024];
    let mut n = 0;
    // SAFETY: buffers are sized by the lengths passed.
    let ok = unsafe {
        DeviceIoControl(
            h.0,
            IOCTL_STORAGE_QUERY_PROPERTY,
            query.as_ptr().cast::<c_void>(),
            12,
            buf.as_mut_ptr().cast(),
            1024,
            &mut n,
            null_mut(),
        )
    };
    if ok == 0 {
        return ("Disk".into(), false);
    }
    let field = |o: usize| {
        let at = u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]) as usize;
        let s = buf.get(at..).unwrap_or(&[]);
        let end = s.iter().position(|b| *b == 0).unwrap_or(0);
        if at == 0 { String::new() } else { String::from_utf8_lossy(&s[..end]).trim().to_string() }
    };
    let removable = buf[10] != 0;
    let (vendor, product) = (field(12), field(16));
    let name = format!("{vendor} {product}").trim().to_string();
    (if name.is_empty() { "Disk".into() } else { name }, removable)
}

/// Which drive letter, if any, sits on each (disk, partition).
fn drive_letters() -> Vec<(u32, u32, char)> {
    let mut out = vec![];
    // SAFETY: no arguments.
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let Ok(h) = open_attrs(&format!(r"\\.\{letter}:")) else { continue };
        if let Some(n) = ioctl::<STORAGE_DEVICE_NUMBER>(&h, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[]) {
            out.push((n.DeviceNumber, n.PartitionNumber, letter));
        }
    }
    out
}

fn open_attrs(path: &str) -> Result<Raw> {
    let wide: Vec<u16> = path.encode_utf16().chain([0]).collect();
    // SAFETY: `wide` is NUL-terminated; zero access only queries the device.
    let h = unsafe { CreateFileW(wide.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, null(), OPEN_EXISTING, 0, null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Raw(h))
}

/// Walks every physical disk. Reads signatures only, and needs administrator rights;
/// without them the list is simply empty.
pub fn scan() -> Vec<FoundPartition> {
    let letters = drive_letters();
    let mut out = vec![];
    for disk in 0..32u32 {
        let Ok(h) = open_raw(&format!(r"\\.\PhysicalDrive{disk}"), false) else { continue };
        let (name, removable) = disk_name(&h);
        let mut buf = vec![0u8; 64 * 1024];
        let mut n = 0;
        // SAFETY: the buffer is sized by the length passed.
        let ok = unsafe {
            DeviceIoControl(
                h.0,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                null(),
                0,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut n,
                null_mut(),
            )
        };
        if ok == 0 {
            continue;
        }
        let header = std::mem::offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
        let count = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        let stride = size_of::<PARTITION_INFORMATION_EX>();
        for i in 0..count.min((buf.len() - header) / stride) {
            // SAFETY: the entry lies within the buffer; read_unaligned has no alignment needs.
            let p: PARTITION_INFORMATION_EX =
                unsafe { std::ptr::read_unaligned(buf.as_ptr().add(header + i * stride).cast()) };
            if p.PartitionNumber == 0 || p.PartitionLength == 0 {
                continue;
            }
            let kind = RawDev::open(disk, p.PartitionNumber, false).map_or(FsKind::Unknown, |d| probe(&d));
            let letter = letters.iter().find(|l| l.0 == disk && l.1 == p.PartitionNumber).map(|l| l.2);
            out.push(FoundPartition {
                disk,
                part: p.PartitionNumber,
                disk_name: name.clone(),
                size: p.PartitionLength as u64,
                kind,
                letter,
                removable,
            });
        }
    }
    out
}

pub fn last_error() -> u32 {
    // SAFETY: no arguments.
    unsafe { GetLastError() }
}
