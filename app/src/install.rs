//! One-step setup. Everything needed ships inside this executable, including the signed
//! WinFsp installer, so a user runs one file and approves one elevation prompt.
use crate::{config, service, wide, winfsp};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// The unmodified, Authenticode-signed installer from the WinFsp project. It stays in the
/// executable's image and is only paged in during setup, so it costs no memory at run time.
const WINFSP_MSI: &[u8] = include_bytes!("../res/winfsp-2.1.25156.msi");
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NixMount";

/// True when this process holds a full administrator token.
pub fn elevated() -> bool {
    let mut tok = null_mut();
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut n = 0;
    // SAFETY: out-pointers are valid; the token is closed below.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let ok = GetTokenInformation(tok, TokenElevation, (&raw mut e).cast(), 4, &mut n);
        CloseHandle(tok);
        ok != 0 && e.TokenIsElevated != 0
    }
}

/// Starts this program again through UAC. Returns false if the user declined.
pub fn relaunch_elevated(args: &str) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let (verb, path, params) = (wide("runas"), wide(&exe.to_string_lossy()), wide(args));
    // SAFETY: strings are NUL-terminated.
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), path.as_ptr(), params.as_ptr(), null(), SW_SHOWNORMAL) };
    r as isize > 32
}

fn program_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles"));
    Ok(PathBuf::from(base.ok_or("no Program Files directory")?).join("NixMount"))
}

/// Windows' own system folder, asked of Windows: tools run elevated must not come from a
/// path that an environment variable could redirect.
pub fn system_dir() -> PathBuf {
    let mut buf = [0u16; 260];
    // SAFETY: `buf` is sized by the length passed.
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    String::from_utf16_lossy(&buf[..n.min(buf.len())]).into()
}

fn start_menu_link() -> PathBuf {
    let base = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join(r"Microsoft\Windows\Start Menu\Programs\NixMount.lnk")
}

/// Runs WinFsp's installer if the driver isn't already there.
///
/// The MSI is written into the program folder, not a temporary one. It runs elevated, and in
/// a folder an ordinary user can write to, it could be swapped between writing and running.
/// A copy left behind also records that NixMount installed WinFsp, so uninstalling knows
/// whether it is ours to remove.
fn ensure_winfsp(dir: &Path) -> Result<(), String> {
    if winfsp::driver_present() {
        return Ok(());
    }
    let msi = dir.join("winfsp.msi");
    std::fs::write(&msi, WINFSP_MSI).map_err(|e| format!("could not unpack the driver: {e}"))?;
    match run_msi("/i", &msi)? {
        // Success, and success with a restart pending.
        Some(0 | 1641 | 3010) => Ok(()),
        Some(1618) => Err("another installation is running, wait for it to finish and try again".into()),
        code => {
            let _ = std::fs::remove_file(&msi);
            Err(format!("the WinFsp driver failed to install (code {code:?})"))
        }
    }
}

/// Runs Windows Installer quietly. Its Restart Manager would otherwise close whatever holds a
/// file it is replacing, and for a console program that means a Ctrl-C to the whole console,
/// including whoever ran this. Disabled, a locked file just finishes at the next restart.
fn run_msi(action: &str, msi: &Path) -> Result<Option<i32>, String> {
    let mut cmd = Command::new(system_dir().join("msiexec.exe"));
    cmd.arg(action).arg(msi).args(["/qn", "/norestart", "MSIRESTARTMANAGERCONTROL=Disable"]);
    if let Some(log) = std::env::var_os("NIXMOUNT_MSI_LOG") {
        cmd.arg("/l*v").arg(log);
    }
    cmd.status().map(|s| s.code()).map_err(|e| format!("could not run Windows Installer: {e}"))
}

/// Waits for the service's process to end. It reports itself stopped slightly before that,
/// and until then it holds the program file and the driver's DLL.
fn wait_for_release(exe: &Path) {
    for _ in 0..50 {
        let free = std::fs::OpenOptions::new().write(true).open(exe);
        if free.is_ok() || !exe.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn set_string(key: HKEY, name: &str, value: &str) {
    let (n, v) = (wide(name), wide(value));
    // SAFETY: both strings are NUL-terminated and sized in bytes.
    unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_SZ, v.as_ptr().cast(), (v.len() * 2) as u32) };
}

fn set_number(key: HKEY, name: &str, value: u32) {
    let n = wide(name);
    // SAFETY: the value is one DWORD.
    unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_DWORD, (&raw const value).cast(), 4) };
}

/// Lists NixMount in Settings, under installed apps.
fn register_uninstaller(exe: &Path, dir: &Path) -> Result<(), String> {
    let path = wide(UNINSTALL_KEY);
    let mut key = null_mut();
    // SAFETY: `path` is NUL-terminated and `key` receives the handle closed below.
    let rc = unsafe {
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, null(), 0, KEY_SET_VALUE, null(), &mut key, null_mut())
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("could not register the uninstaller ({rc})"));
    }
    let size = std::fs::metadata(exe).map_or(0, |m| m.len() / 1024) as u32;
    set_string(key, "DisplayName", "NixMount");
    set_string(key, "DisplayVersion", env!("CARGO_PKG_VERSION"));
    set_string(key, "Publisher", "NixMount contributors");
    set_string(key, "DisplayIcon", &exe.display().to_string());
    set_string(key, "InstallLocation", &dir.display().to_string());
    set_string(key, "UninstallString", &format!("\"{}\" uninstall", exe.display()));
    set_number(key, "NoModify", 1);
    set_number(key, "NoRepair", 1);
    set_number(key, "EstimatedSize", size);
    // SAFETY: `key` was opened above.
    unsafe { RegCloseKey(key) };
    Ok(())
}

/// Adds the Start menu entry. A missing shortcut isn't worth failing setup over.
fn create_shortcut(exe: &Path) {
    let script = "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:CW_LINK);\
                  $s.TargetPath=$env:CW_EXE;$s.Description='Mount Linux volumes';$s.Save()";
    let _ = Command::new(system_dir().join(r"WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("CW_LINK", start_menu_link())
        .env("CW_EXE", exe)
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

/// Installs or upgrades everything. Safe to run again: each step keeps what is already right.
pub fn install() -> Result<(), String> {
    let dir = program_dir()?;
    let dest = dir.join("nixmount.exe");
    let this = std::env::current_exe().map_err(|e| e.to_string())?;
    // Only an administrator can have put the program there, so settings beside it are ours.
    config::secure_directory(dest.exists())?;
    // An upgrade has to stop the running copy. Its mounts close cleanly on the way.
    service::stop()?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    if this != dest {
        if let Err(e) = replace_program(&this, &dest) {
            // Whatever is installed is better running than not.
            let _ = service::register(&dest);
            return Err(e);
        }
    }
    ensure_winfsp(&dir)?;
    service::register(&dest)?;
    create_shortcut(&dest);
    register_uninstaller(&dest, &dir)
}

/// Copies the program into place. A service reports itself stopped just before its process
/// exits, so the old file can stay locked for a moment after the stop returns.
fn replace_program(from: &Path, to: &Path) -> Result<(), String> {
    let mut last = None;
    for _ in 0..50 {
        match std::fs::copy(from, to) {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(format!("could not copy to {}: {}", to.display(), last.map_or_else(String::new, |e| e.to_string())))
}

/// Removes everything `install` added, including WinFsp if NixMount was what installed it.
/// If another program brought WinFsp, it stays.
pub fn uninstall() -> Result<(), String> {
    let dir = program_dir()?;
    service::unregister()?;
    let _ = std::fs::remove_file(start_menu_link());
    let key = wide(UNINSTALL_KEY);
    // SAFETY: `key` is NUL-terminated.
    unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, key.as_ptr()) };
    let this = std::env::current_exe().map_err(|e| e.to_string())?;
    let dest = dir.join("nixmount.exe");
    if this != dest {
        wait_for_release(&dest);
    }
    let msi = dir.join("winfsp.msi");
    if msi.exists() {
        let code = run_msi("/x", &msi)?;
        if !matches!(code, Some(0 | 1605 | 1641 | 3010)) {
            return Err(format!("the WinFsp driver could not be removed (code {code:?})"));
        }
        let _ = std::fs::remove_file(&msi);
    }
    config::remove();
    remove_program(&dir)
}

/// Deletes the program folder. A running program can't delete itself, so when uninstalling
/// from the installed copy a short-lived shell finishes the job after this process exits.
fn remove_program(dir: &Path) -> Result<(), String> {
    let exe = dir.join("nixmount.exe");
    if std::env::current_exe().map_err(|e| e.to_string())? == exe {
        let cmd = format!("/C ping -n 3 127.0.0.1 >NUL & del /F /Q \"{}\" & rmdir \"{}\"", exe.display(), dir.display());
        return Command::new(system_dir().join("cmd.exe"))
            .raw_arg(cmd)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map(|_| ())
            .map_err(|e| e.to_string());
    }
    // The service process needs a moment to exit and release the file.
    for _ in 0..50 {
        if std::fs::remove_file(&exe).is_ok() || !exe.exists() {
            let _ = std::fs::remove_dir(dir);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(format!("could not delete {}", exe.display()))
}
