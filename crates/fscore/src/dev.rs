//! Byte-addressed storage. Engines never see files or handles, only this trait, which
//! is what lets every code path run against images, memory and crash simulators.
use crate::vfs::{FsError, Result};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub trait BlockDev: Send + Sync {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()>;
    fn write_at(&self, off: u64, data: &[u8]) -> Result<()>;
    /// Durability barrier: everything written before this call survives power loss.
    fn flush(&self) -> Result<()>;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn writable(&self) -> bool {
        true
    }
}

/// A regular file (disk image) as a device.
pub struct FileDev {
    file: File,
    len: u64,
    writable: bool,
}

impl FileDev {
    /// Opening for writing shuts out every other writer, as locking a partition does: two
    /// programs writing one image would destroy it. Readers are still let in.
    pub fn open(path: &Path, writable: bool) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(writable);
        #[cfg(windows)]
        if writable {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 1;
            const ERROR_SHARING_VIOLATION: i32 = 32;
            options.share_mode(FILE_SHARE_READ);
            return match options.open(path) {
                Ok(file) => Ok(FileDev { len: file.metadata()?.len(), file, writable }),
                Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
                    Err(FsError::Unsupported("the image is in use by another program, close it and try again".into()))
                }
                Err(e) => Err(e.into()),
            };
        }
        let file = options.open(path)?;
        let len = file.metadata()?.len();
        Ok(FileDev { file, len, writable })
    }
}

#[cfg(windows)]
fn pread(f: &File, mut off: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        off += n as u64;
        buf = &mut buf[n..];
    }
    Ok(())
}

#[cfg(windows)]
fn pwrite(f: &File, mut off: u64, mut buf: &[u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_write(buf, off)?;
        off += n as u64;
        buf = &buf[n..];
    }
    Ok(())
}

#[cfg(unix)]
fn pread(f: &File, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}

#[cfg(unix)]
fn pwrite(f: &File, off: u64, buf: &[u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(f, buf, off)
}

impl BlockDev for FileDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        Ok(pread(&self.file, off, buf)?)
    }
    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        if !self.writable {
            return Err(FsError::ReadOnly);
        }
        Ok(pwrite(&self.file, off, data)?)
    }
    fn flush(&self) -> Result<()> {
        if self.writable {
            self.file.sync_data()?;
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

/// In-memory device for tests.
pub struct MemDev(pub Mutex<Vec<u8>>);

impl MemDev {
    pub fn new(data: Vec<u8>) -> Self {
        MemDev(Mutex::new(data))
    }
    pub fn snapshot(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl BlockDev for MemDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        let d = self.0.lock().unwrap();
        let s = usize::try_from(off).ok().filter(|s| s.saturating_add(buf.len()) <= d.len());
        let s = s.ok_or_else(|| FsError::Corrupt("read past end of device".into()))?;
        buf.copy_from_slice(&d[s..s + buf.len()]);
        Ok(())
    }
    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        let mut d = self.0.lock().unwrap();
        let s = usize::try_from(off).ok().filter(|s| s.saturating_add(data.len()) <= d.len());
        let s = s.ok_or_else(|| FsError::Corrupt("write past end of device".into()))?;
        d[s..s + data.len()].copy_from_slice(data);
        Ok(())
    }
    fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn len(&self) -> u64 {
        self.0.lock().unwrap().len() as u64
    }
}

/// A window onto a device: how a partition is presented to an engine. All accesses are
/// bounds-checked, so a filesystem can never reach outside its partition.
pub struct SliceDev {
    inner: Arc<dyn BlockDev>,
    start: u64,
    len: u64,
}

impl SliceDev {
    pub fn new(inner: Arc<dyn BlockDev>, start: u64, len: u64) -> Self {
        SliceDev { inner, start, len }
    }
    fn check(&self, off: u64, n: usize) -> Result<u64> {
        let end = off.checked_add(n as u64);
        if end.is_none_or(|e| e > self.len) {
            return Err(FsError::Corrupt(format!("access at {off:#x} is outside the partition")));
        }
        Ok(self.start + off)
    }
}

impl BlockDev for SliceDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.inner.read_at(self.check(off, buf.len())?, buf)
    }
    fn write_at(&self, off: u64, data: &[u8]) -> Result<()> {
        self.inner.write_at(self.check(off, data.len())?, data)
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn an_image_has_one_writer() {
        let path = std::env::temp_dir().join(format!("nixmount-one-writer-{}.img", std::process::id()));
        std::fs::write(&path, [0u8; 4096]).unwrap();
        let writer = FileDev::open(&path, true).unwrap();
        // Another spelling of the same file is still the same file.
        let shouted = std::path::PathBuf::from(path.to_string_lossy().to_uppercase());
        assert!(matches!(FileDev::open(&shouted, true), Err(FsError::Unsupported(_))));
        let reader = FileDev::open(&path, false).unwrap();
        writer.write_at(0, b"x").unwrap();
        let mut b = [0u8; 1];
        reader.read_at(0, &mut b).unwrap();
        assert_eq!(&b, b"x");
        drop((writer, reader));
        FileDev::open(&path, true).unwrap();
        std::fs::remove_file(&path).unwrap();
    }
}
