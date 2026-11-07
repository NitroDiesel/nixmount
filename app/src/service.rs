//! The Windows service: owns all mounts, so they outlive the interface, reach every
//! logon session, and shut down cleanly with the machine.
use crate::config::{Automount, Config};
use crate::ipc::{self, Request, Response, ScrubState};
use crate::mounts::Mounts;
use crate::volumes;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    RegisterDeviceNotificationW, DBT_DEVTYP_DEVICEINTERFACE, DEV_BROADCAST_DEVICEINTERFACE_W,
};

pub const NAME: &str = "Causeway";
const SERVICE_WIN32_OWN: u32 = SERVICE_WIN32_OWN_PROCESS;
const DBT_DEVICEARRIVAL: u32 = 0x8000;
const DBT_DEVICEREMOVECOMPLETE: u32 = 0x8004;
const DEVICE_NOTIFY_SERVICE_HANDLE: u32 = 1;

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

unsafe extern "system" fn control(code: u32, ty: u32, _data: *mut std::ffi::c_void, _ctx: *mut std::ffi::c_void) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_PRESHUTDOWN | SERVICE_CONTROL_SHUTDOWN => {
            set_state(SERVICE_STOP_PENDING, 0);
            if let Some(s) = STATE.get() {
                s.mounts.unmount_all();
            }
            set_state(SERVICE_STOPPED, 0);
            NO_ERROR
        }
        SERVICE_CONTROL_DEVICEEVENT => {
            if ty == DBT_DEVICEARRIVAL || ty == DBT_DEVICEREMOVECOMPLETE {
                device_changed();
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// Reacts to disks coming and going. One unplug raises a burst of events, and control
/// handlers must return quickly, so a single worker settles and then handles them all.
fn device_changed() {
    static PENDING: AtomicBool = AtomicBool::new(false);
    if PENDING.swap(true, Ordering::AcqRel) {
        return;
    }
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        PENDING.store(false, Ordering::Release);
        if let Some(s) = STATE.get() {
            s.mounts.prune_missing();
            automount(&s.mounts);
        }
    });
}

/// Asks for disk arrival and removal events, the job of the original driver's PnP code.
fn watch_devices(h: SERVICE_STATUS_HANDLE) {
    // SAFETY: an all-zero filter is valid before its fields are set.
    let mut filter: DEV_BROADCAST_DEVICEINTERFACE_W = unsafe { std::mem::zeroed() };
    filter.dbcc_size = size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>() as u32;
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = GUID::from_u128(0x53F56307_B6BF_11D0_94F2_00A0C91EFB8B);
    // SAFETY: the filter is valid for the call. Failure only costs hotplug automounting.
    unsafe { RegisterDeviceNotificationW(h, (&raw const filter).cast(), DEVICE_NOTIFY_SERVICE_HANDLE) };
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
    watch_devices(h);
    set_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN);
    // Scanning disks can take a while, and the service manager shouldn't wait for it.
    std::thread::spawn(move || automount(&mounts));
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
            // A partition mounted read-write is locked, so a rescan can't see it.
            for v in s.mounts.volumes() {
                if !all.iter().any(|x| x.target == v.target) {
                    all.push(v);
                }
            }
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
        Request::DeleteSubvolume { point, name } => done(s.mounts.delete_subvolume(&point, &name)),
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

fn open_service(sc: &ScHandle) -> Option<ScHandle> {
    let name = wide(NAME);
    // SAFETY: `name` is NUL-terminated.
    let h = unsafe { OpenServiceW(sc.0, name.as_ptr(), SERVICE_ALL_ACCESS) };
    (!h.is_null()).then_some(ScHandle(h))
}

fn start(svc: &ScHandle) -> Result<(), String> {
    const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
    // SAFETY: `svc` is open.
    if unsafe { StartServiceW(svc.0, 0, null()) } == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING) {
            return Err(format!("the service could not start: {e}"));
        }
    }
    Ok(())
}

/// Stops the service and waits for it to exit, which commits and detaches every mount.
fn stop_and_wait(svc: &ScHandle) {
    // SAFETY: an all-zero SERVICE_STATUS is valid; `svc` is open.
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: as above. Failure means it wasn't running, which the loop below sees.
    unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st) };
    for _ in 0..300 {
        // SAFETY: `st` is valid for the call.
        if unsafe { QueryServiceStatus(svc.0, &mut st) } == 0 || st.dwCurrentState == SERVICE_STOPPED {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Stops the service if it exists, so its executable can be replaced.
pub fn stop() -> Result<(), String> {
    let sc = manager()?;
    if let Some(svc) = open_service(&sc) {
        stop_and_wait(&svc);
    }
    Ok(())
}

/// Creates the service for `exe` if needed, and starts it.
pub fn register(exe: &std::path::Path) -> Result<(), String> {
    let sc = manager()?;
    if let Some(svc) = open_service(&sc) {
        return start(&svc);
    }
    // Quoted, or a path with spaces becomes a privilege-escalation hole.
    let cmd = wide(&format!("\"{}\" service run", exe.display()));
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
    }
    start(&svc)
}

/// Stops and deletes the service, if there is one.
pub fn unregister() -> Result<(), String> {
    let sc = manager()?;
    let Some(svc) = open_service(&sc) else { return Ok(()) };
    stop_and_wait(&svc);
    // SAFETY: `svc` is open.
    if unsafe { DeleteService(svc.0) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}
