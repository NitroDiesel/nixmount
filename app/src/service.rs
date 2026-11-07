//! The Windows service: owns all mounts, so they outlive the interface, reach every
//! logon session, and shut down cleanly with the machine.
use crate::config::{Automount, Config};
use crate::ipc::{self, Request, Response, ScrubState};
use crate::mounts::Mounts;
use crate::volumes;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, OnceLock};
use windows_sys::Win32::Foundation::{NO_ERROR, ERROR_CALL_NOT_IMPLEMENTED};
use windows_sys::Win32::System::Services::*;

pub const NAME: &str = "Causeway";
const SERVICE_WIN32_OWN: u32 = SERVICE_WIN32_OWN_PROCESS;

struct State {
    mounts: Arc<Mounts>,
    scrub: Arc<Mutex<ScrubState>>,
}

static STATE: OnceLock<State> = OnceLock::new();
static STATUS_HANDLE: Mutex<usize> = Mutex::new(0);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn set_state(state: u32, accept: u32) {
    let h = *STATUS_HANDLE.lock().unwrap_or_else(|e| e.into_inner());
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN,
        dwCurrentState: state,
        dwControlsAccepted: accept,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 15_000,
    };
    // SAFETY: `h` was returned by RegisterServiceCtrlHandlerExW.
    unsafe { SetServiceStatus(h as SERVICE_STATUS_HANDLE, &st) };
}

unsafe extern "system" fn control(code: u32, _ty: u32, _data: *mut std::ffi::c_void, _ctx: *mut std::ffi::c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_PRESHUTDOWN | SERVICE_CONTROL_SHUTDOWN => {
            set_state(SERVICE_STOP_PENDING, 0);
            if let Some(s) = STATE.get() {
                s.mounts.unmount_all();
            }
            set_state(SERVICE_STOPPED, 0);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(NAME);
    // SAFETY: `name` is NUL-terminated, `control` has the documented signature.
    let h = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null_mut()) };
    *STATUS_HANDLE.lock().unwrap_or_else(|e| e.into_inner()) = h as usize;
    set_state(SERVICE_START_PENDING, 0);
    let mounts = Arc::new(Mounts::default());
    mounts.spawn_committer();
    let _ = STATE.set(State { mounts: mounts.clone(), scrub: Arc::default() });
    automount(&mounts);
    set_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN);
    let _ = ipc::serve(handle);
    set_state(SERVICE_STOPPED, 0);
}

/// Mounts remembered volumes that are present.
fn automount(mounts: &Mounts) {
    let cfg = Config::load();
    if cfg.automounts.is_empty() {
        return;
    }
    let present = volumes::scan_disks();
    for a in &cfg.automounts {
        let mut req = a.mount.clone();
        // Disk numbers can change between boots; the UUID is what identifies the volume.
        if let Some(v) = present.iter().find(|v| v.uuid == a.uuid) {
            req.target = v.target.clone();
        } else if !matches!(req.target, volumes::Target::Image { .. }) {
            continue;
        }
        let _ = mounts.mount(req);
    }
}

fn handle(r: Request) -> Response {
    let Some(s) = STATE.get() else { return Response::Error("service is starting".into()) };
    let done = |r: Result<(), String>| r.map_or_else(Response::Error, |()| Response::Ok);
    match r {
        Request::Status => Response::Status {
            mounts: s.mounts.status(),
            winfsp: crate::winfsp::available(),
            automount_uuids: Config::load().automounts.into_iter().map(|a| a.uuid).collect(),
        },
        Request::Scan => {
            let mut all = volumes::scan_disks();
            all.extend(Config::load().images.iter().map(|p| volumes::describe_image(p)));
            Response::Volumes(all)
        }
        Request::Inspect { path } => {
            let v = volumes::describe_image(&path);
            if v.error.is_none() {
                let mut c = Config::load();
                if !c.images.contains(&path) {
                    c.images.push(path);
                    let _ = c.save();
                }
            }
            Response::Volume(Box::new(v))
        }
        Request::Mount(m) => s.mounts.mount(m).map_or_else(Response::Error, Response::Mounted),
        Request::Unmount { point } => done(s.mounts.unmount(&point)),
        Request::Sync => done(s.mounts.sync_all()),
        Request::Scrub { point } => start_scrub(s, point),
        Request::ScrubProgress => Response::Scrub(s.scrub.lock().unwrap_or_else(|e| e.into_inner()).clone()),
        Request::Snapshot { point, name, read_only } => done(s.mounts.snapshot(&point, &name, read_only)),
        Request::CreateSubvolume { point, name } => done(s.mounts.create_subvolume(&point, &name)),
        Request::SetAutomount { uuid, mount } => {
            let mut c = Config::load();
            c.automounts.retain(|a| a.uuid != uuid);
            if let Some(mount) = mount {
                c.automounts.push(Automount { uuid, mount });
            }
            done(c.save())
        }
    }
}

fn start_scrub(s: &State, point: String) -> Response {
    {
        let mut st = s.scrub.lock().unwrap_or_else(|e| e.into_inner());
        if st.running {
            return Response::Error("a scrub is already running".into());
        }
        *st = ScrubState { running: true, point: point.clone(), ..ScrubState::default() };
    }
    let (mounts, state) = (s.mounts.clone(), s.scrub.clone());
    std::thread::spawn(move || {
        let progress_state = state.clone();
        let r = mounts.scrub(&point, &mut |done, total| {
            let mut st = progress_state.lock().unwrap_or_else(|e| e.into_inner());
            st.done = done;
            st.total = total;
        });
        let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
        st.running = false;
        match r {
            Ok(rep) => {
                st.scanned_bytes = rep.scanned_bytes;
                st.repaired = rep.repaired;
                st.errors = rep.errors;
            }
            Err(e) => st.errors = vec![e],
        }
    });
    Response::Ok
}

/// Entry point for `causeway service run`, which the service control manager starts.
pub fn run() -> Result<(), String> {
    let name = wide(NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_ptr() as *mut u16, lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    // SAFETY: the table outlives this call, which blocks until the service stops.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

/// Runs the service logic in the foreground, for debugging.
pub fn run_foreground() -> Result<(), String> {
    let mounts = Arc::new(Mounts::default());
    mounts.spawn_committer();
    let _ = STATE.set(State { mounts: mounts.clone(), scrub: Arc::default() });
    automount(&mounts);
    ipc::serve(handle).map_err(|e| e.to_string())
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: owned handle, closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn manager() -> Result<ScHandle, String> {
    // SAFETY: null arguments select the local manager.
    let h = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) };
    if h.is_null() {
        return Err("administrator rights are needed to manage the service".into());
    }
    Ok(ScHandle(h))
}

/// Copies the executable next to where the service will run it from. A SYSTEM service
/// must not start from a directory an ordinary user can write to.
fn install_location() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let base = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles"));
    let dir = std::path::PathBuf::from(base.ok_or("no Program Files directory")?).join("Causeway");
    let dest = dir.join("causeway.exe");
    if exe != dest {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::copy(&exe, &dest).map_err(|e| format!("could not copy to {}: {e}", dest.display()))?;
    }
    Ok(dest)
}

pub fn install() -> Result<(), String> {
    let exe = install_location()?;
    // Quoted, or a path with spaces becomes a privilege-escalation hole.
    let cmd = wide(&format!("\"{}\" service run", exe.display()));
    let sc = manager()?;
    let (name, display) = (wide(NAME), wide("Causeway Volume Service"));
    let deps = wide("WinFsp.Launcher\0");
    // SAFETY: all strings are NUL-terminated.
    let h = unsafe {
        CreateServiceW(
            sc.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            cmd.as_ptr(),
            null(),
            null_mut(),
            deps.as_ptr(),
            null(),
            null(),
        )
    };
    if h.is_null() {
        return Err(format!("could not create the service: {}", std::io::Error::last_os_error()));
    }
    let svc = ScHandle(h);
    let mut desc = wide("Mounts ext2/3/4 and Btrfs volumes.");
    let d = SERVICE_DESCRIPTIONW { lpDescription: desc.as_mut_ptr() };
    let mut pre = SERVICE_PRESHUTDOWN_INFO { dwPreshutdownTimeout: 60_000 };
    // SAFETY: info structures match the requested levels.
    unsafe {
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, (&raw const d).cast());
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_PRESHUTDOWN_INFO, (&raw mut pre).cast());
        if StartServiceW(svc.0, 0, null()) == 0 {
            return Err(format!("installed, but could not start: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let sc = manager()?;
    let name = wide(NAME);
    // SAFETY: `name` is NUL-terminated.
    let h = unsafe { OpenServiceW(sc.0, name.as_ptr(), SERVICE_ALL_ACCESS) };
    if h.is_null() {
        return Err("the service isn't installed".into());
    }
    let svc = ScHandle(h);
    // SAFETY: an all-zero SERVICE_STATUS is valid; `svc` is open.
    unsafe {
        let mut st = std::mem::zeroed();
        ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st);
        if DeleteService(svc.0) == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}
