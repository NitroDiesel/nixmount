//! The local protocol between the interface and the service: length-prefixed JSON over
//! a named pipe that only administrators and SYSTEM can open.
use crate::mounts::{MountRequest, MountStatus};
use crate::volumes::Volume;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use zeroize::Zeroize;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers,
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

const PIPE: &str = r"\\.\pipe\nixmount";
/// Requests are small; refusing anything large caps what a client can make us allocate.
const MAX_MESSAGE: usize = 4 << 20;

/// Key material in a message. It is wiped when dropped and never printed.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(key: &luks::Key) -> Secret {
        Secret(key.as_bytes().to_vec())
    }

    pub fn into_key(mut self) -> luks::Key {
        luks::Key::from_bytes(std::mem::take(&mut self.0))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Status,
    Scan,
    Inspect { path: PathBuf },
    /// `key` unlocks an encrypted volume. The passphrase itself never reaches the service.
    Mount { mount: MountRequest, key: Option<Secret> },
    Unmount { point: String },
    Sync,
    Scrub { point: String },
    ScrubProgress,
    Snapshot { point: String, name: String, read_only: bool },
    CreateSubvolume { point: String, name: String },
    DeleteSubvolume { point: String, name: String },
    SetAutomount { uuid: String, mount: Option<MountRequest> },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScrubState {
    pub running: bool,
    pub point: String,
    pub done: u64,
    pub total: u64,
    pub scanned_bytes: u64,
    pub repaired: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Error(String),
    Status { mounts: Vec<MountStatus>, winfsp: bool, automount_uuids: Vec<String> },
    Volumes(Vec<Volume>),
    Volume(Box<Volume>),
    Mounted(MountStatus),
    Scrub(ScrubState),
}

/// An open pipe end.
pub struct Pipe(HANDLE);

// SAFETY: a pipe handle is usable from any thread and each `Pipe` is used by one.
unsafe impl Send for Pipe {}

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: owned handle, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

impl Pipe {
    fn read_exact(&self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let mut n = 0;
            // SAFETY: the slice is writable for the length passed.
            let ok = unsafe { ReadFile(self.0, buf[done..].as_mut_ptr(), (buf.len() - done) as u32, &mut n, null_mut()) };
            if ok == 0 || n == 0 {
                return Err(std::io::Error::last_os_error());
            }
            done += n as usize;
        }
        Ok(())
    }

    fn write_all(&self, buf: &[u8]) -> std::io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let mut n = 0;
            // SAFETY: the slice is readable for the length passed.
            let ok = unsafe { WriteFile(self.0, buf[done..].as_ptr(), (buf.len() - done) as u32, &mut n, null_mut()) };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            done += n as usize;
        }
        Ok(())
    }

    /// Messages can carry a volume key, so their encoded form is wiped once used.
    pub fn send<T: Serialize>(&self, msg: &T) -> std::io::Result<()> {
        let mut body = serde_json::to_vec(msg)?;
        let r = self.write_all(&(body.len() as u32).to_le_bytes()).and_then(|()| self.write_all(&body));
        body.zeroize();
        r
    }

    pub fn receive<T: for<'a> Deserialize<'a>>(&self) -> std::io::Result<T> {
        let mut len = [0u8; 4];
        self.read_exact(&mut len)?;
        let n = u32::from_le_bytes(len) as usize;
        if n > MAX_MESSAGE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut body = vec![0u8; n];
        let r = self.read_exact(&mut body).and_then(|()| Ok(serde_json::from_slice(&body)?));
        body.zeroize();
        r
    }
}

/// Sends one request to the service. Between connections the server briefly has no free
/// pipe instance, which shows up as busy or not-found, so those are retried.
pub fn call(req: &Request) -> std::io::Result<Response> {
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;
    let wide = crate::wide(PIPE);
    for attempt in 0.. {
        // SAFETY: `wide` is NUL-terminated.
        let h = unsafe { CreateFileW(wide.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, 0, null_mut()) };
        if h != INVALID_HANDLE_VALUE {
            let p = Pipe(h);
            p.send(req)?;
            return p.receive();
        }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(ERROR_PIPE_BUSY) if attempt < 20 => {
                // SAFETY: `wide` is NUL-terminated.
                unsafe { WaitNamedPipeW(wide.as_ptr(), 500) };
            }
            Some(ERROR_FILE_NOT_FOUND) if attempt < 3 => std::thread::sleep(std::time::Duration::from_millis(30)),
            _ => return Err(e),
        }
    }
    unreachable!()
}

/// Creates one server end. The original design let Guests and Anonymous onto its pipe;
/// here the DACL admits only SYSTEM and Administrators, and remote clients are rejected.
fn server_instance(first: bool) -> std::io::Result<Pipe> {
    let sddl = crate::wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    let mut sd: *mut c_void = null_mut();
    // SAFETY: on success `sd` is a LocalAlloc'd descriptor, freed below.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, null_mut()) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let wide = crate::wide(PIPE);
    // First-instance ownership stops another process squatting on the pipe name.
    let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    // SAFETY: all pointers are valid for the call.
    let h = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            &sa,
        )
    };
    // SAFETY: `sd` came from LocalAlloc and isn't used after this.
    unsafe { LocalFree(sd) };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Pipe(h))
}

/// Serves requests until the process exits, one thread per connection.
pub fn serve(handler: impl Fn(Request) -> Response + Send + Sync + 'static) -> std::io::Result<()> {
    let handler = std::sync::Arc::new(handler);
    let mut first = true;
    loop {
        let p = server_instance(first)?;
        first = false;
        // SAFETY: a valid pipe handle, synchronous mode.
        let connected = unsafe { ConnectNamedPipe(p.0, null_mut()) } != 0 || crate::disk::last_error() == 535;
        if !connected {
            continue;
        }
        let h = handler.clone();
        std::thread::spawn(move || {
            if let Ok(req) = p.receive::<Request>() {
                let _ = p.send(&h(req));
            }
            // Flushing first: disconnecting discards anything the client hasn't read yet.
            // SAFETY: a valid pipe handle.
            unsafe {
                FlushFileBuffers(p.0);
                DisconnectNamedPipe(p.0);
            }
        });
    }
}
