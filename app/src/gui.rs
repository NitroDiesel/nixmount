//! The interface: a sidebar of volumes and a detail pane. Everything is painted from
//! state on demand; nothing animates, so an idle window uses no CPU at all.
use crate::canvas::{rgb, Canvas, Color, Font, Rect};
use crate::cli;
use crate::ipc::{self, Request, Response, ScrubState};
use crate::mounts::{MountRequest, MountStatus};
use crate::volumes::{self, Target, Volume};
use fscore::{resolve, DirEntry, FileKind, Filesystem, MountOpts};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Dwm::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
use windows_sys::Win32::UI::Controls::Dialogs::*;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_WORKER: u32 = WM_APP + 1;
const TIMER_STATUS: usize = 1;
const TIMER_POLL: usize = 2;
const WM_MOUSELEAVE: u32 = 0x02A3;

const I_DISK: &str = "\u{EDA2}";
const I_USB: &str = "\u{E88E}";
const I_IMAGE: &str = "\u{E7C3}";
const I_ADD: &str = "\u{E710}";
const I_REFRESH: &str = "\u{E72C}";
const I_FOLDER: &str = "\u{E8B7}";
const I_FILE: &str = "\u{E7C3}";
const I_LINK: &str = "\u{E71B}";
const I_BACK: &str = "\u{E72B}";
const I_WARN: &str = "\u{E7BA}";
const I_CLOSE: &str = "\u{E711}";
const I_INFO: &str = "\u{E946}";
const I_CHEVRON: &str = "\u{E70D}";

struct Theme {
    bg: Color,
    side: Color,
    card: Color,
    line: Color,
    text: Color,
    muted: Color,
    accent: Color,
    on_accent: Color,
    hover: Color,
    selected: Color,
    ok: Color,
    warn: Color,
    bad: Color,
    track: Color,
}

const DARK: Theme = Theme {
    bg: rgb(0x16181D),
    side: rgb(0x1B1E24),
    card: rgb(0x21252C),
    line: rgb(0x31363F),
    text: rgb(0xE8EAED),
    muted: rgb(0xA0A8B3),
    accent: rgb(0x5B9BFF),
    on_accent: rgb(0x0B1220),
    hover: rgb(0x2A2F38),
    selected: rgb(0x2C3A52),
    ok: rgb(0x4CC38A),
    warn: rgb(0xE0A93B),
    bad: rgb(0xF0716B),
    track: rgb(0x31363F),
};

const LIGHT: Theme = Theme {
    bg: rgb(0xF5F6F8),
    side: rgb(0xEBEDF1),
    card: rgb(0xFFFFFF),
    line: rgb(0xD9DDE3),
    text: rgb(0x1C1F26),
    muted: rgb(0x5B6573),
    accent: rgb(0x2257C9),
    on_accent: rgb(0xFFFFFF),
    hover: rgb(0xDFE2E8),
    selected: rgb(0xD5E2F8),
    ok: rgb(0x14804A),
    warn: rgb(0x96660C),
    bad: rgb(0xC62B2B),
    track: rgb(0xE3E6EB),
};

#[derive(Clone, Debug, PartialEq)]
enum Act {
    Select(usize),
    AddImage,
    Refresh,
    Mount,
    Unmount,
    OpenFolder,
    PickLetter,
    ToggleWrite,
    ToggleAuto,
    Scrub,
    Snapshot,
    DeleteSubvolume(String),
    Browse,
    CloseBrowser,
    BrowseUp,
    BrowseRow(usize),
    Export,
    Install,
    WinFspHome,
    Dismiss,
}

struct Region {
    rect: Rect,
    act: Act,
}

#[derive(Clone, PartialEq, Debug)]
enum Service {
    Unknown,
    Missing,
    Ready,
}

/// A read-only file browser that needs neither WinFsp nor the service.
struct Browser {
    fs: Option<Arc<dyn Filesystem>>,
    target: Target,
    path: Vec<String>,
    rows: Vec<Row>,
    scroll: i32,
    selected: Option<usize>,
}

struct Row {
    name: String,
    kind: FileKind,
    size: u64,
}

enum Msg {
    Status { mounts: Vec<MountStatus>, autos: Vec<String>, winfsp: bool },
    NoService,
    Volumes(Vec<Volume>),
    Added(Box<Volume>),
    Done { note: Option<String> },
    Failed(String),
    Scrub(ScrubState),
    Browser(Box<Browser>),
}

/// Options the user has chosen for each volume, by list position.
#[derive(Clone, Default)]
struct Choice {
    letter: Option<char>,
    write: bool,
}

struct App {
    hwnd: HWND,
    canvas: Canvas,
    dark: bool,
    volumes: Vec<Volume>,
    mounts: Vec<MountStatus>,
    autos: Vec<String>,
    choices: Vec<Choice>,
    winfsp: bool,
    service: Service,
    selected: usize,
    regions: Vec<Region>,
    hover: Option<Act>,
    focus: Option<usize>,
    busy: Option<String>,
    banner: Option<(bool, String)>,
    browser: Option<Browser>,
    scrub: Option<ScrubState>,
    scanned: bool,
    side_scroll: usize,
    side_max: usize,
    detail_scroll: i32,
    detail_max: i32,
}

/// `Send` wrapper so workers can post back to the window.
#[derive(Clone, Copy)]
struct Wnd(usize);
// SAFETY: PostMessageW is callable from any thread.
unsafe impl Send for Wnd {}

impl Wnd {
    fn post(self, m: Msg) {
        let p = Box::into_raw(Box::new(m));
        // SAFETY: on success the window procedure takes ownership of `p`.
        let ok = unsafe { PostMessageW(self.0 as HWND, WM_WORKER, 0, p as LPARAM) };
        if ok == 0 {
            // SAFETY: the message was not delivered, so `p` is still owned here.
            drop(unsafe { Box::from_raw(p) });
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn human(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut u = 0;
    // 1024-based with these labels, to match what Explorer shows for the same volume.
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[u])
    }
}

fn system_dark() -> bool {
    let (key, val) = (wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"), wide("AppsUseLightTheme"));
    let (mut v, mut n) = (1u32, 4u32);
    // SAFETY: strings are NUL-terminated and the output is one DWORD.
    let rc = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), val.as_ptr(), RRF_RT_REG_DWORD, null_mut(), (&raw mut v).cast(), &mut n)
    };
    rc == 0 && v == 0
}

impl App {
    fn theme(&self) -> &'static Theme {
        if self.dark {
            &DARK
        } else {
            &LIGHT
        }
    }

    fn wnd(&self) -> Wnd {
        Wnd(self.hwnd as usize)
    }

    fn invalidate(&self) {
        // SAFETY: the window is alive while `App` is.
        unsafe { InvalidateRect(self.hwnd, null(), 0) };
    }

    /// Native menus ignore the window's theme unless asked. These two entry points have no
    /// names, only ordinals, but they are what Windows' own dark apps use; on a system without
    /// them the menu simply stays light.
    fn theme_menus(&self) {
        let name: Vec<u16> = "uxtheme.dll\0".encode_utf16().collect();
        // SAFETY: the module comes from System32, and these ordinals take the arguments below.
        unsafe {
            let m = LoadLibraryExW(name.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
            if m.is_null() {
                return;
            }
            if let Some(f) = GetProcAddress(m, 135 as *const u8) {
                let set: unsafe extern "system" fn(i32) -> i32 = std::mem::transmute(f);
                set(if self.dark { 2 } else { 3 });
            }
            if let Some(f) = GetProcAddress(m, 136 as *const u8) {
                let flush: unsafe extern "system" fn() = std::mem::transmute(f);
                flush();
            }
        }
    }

    fn apply_title_bar(&self) {
        self.theme_menus();
        let dark = self.dark as i32;
        let caption = self.theme().side;
        let bgr = ((caption & 0xFF) << 16) | (caption & 0xFF00) | ((caption >> 16) & 0xFF);
        // SAFETY: attribute sizes match the values passed; failure leaves the default frame.
        unsafe {
            DwmSetWindowAttribute(self.hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE as u32, (&raw const dark).cast(), 4);
            DwmSetWindowAttribute(self.hwnd, DWMWA_CAPTION_COLOR as u32, (&raw const bgr).cast(), 4);
        }
    }

    fn current(&self) -> Option<&Volume> {
        self.volumes.get(self.selected)
    }

    fn mount_of(&self, v: &Volume) -> Option<&MountStatus> {
        self.mounts.iter().find(|m| m.target == v.target)
    }

    fn set_busy(&mut self, s: &str) {
        self.busy = Some(s.to_string());
        self.banner = None;
        self.invalidate();
    }

    fn refresh_status(&self) {
        let w = self.wnd();
        std::thread::spawn(move || match ipc::call(&Request::Status) {
            Ok(Response::Status { mounts, automount_uuids, winfsp }) => {
                w.post(Msg::Status { mounts, autos: automount_uuids, winfsp })
            }
            _ => w.post(Msg::NoService),
        });
    }

    fn scan(&mut self) {
        self.set_busy("Scanning disks…");
        let w = self.wnd();
        std::thread::spawn(move || match ipc::call(&Request::Scan) {
            Ok(Response::Volumes(v)) => w.post(Msg::Volumes(v)),
            Ok(Response::Error(e)) => w.post(Msg::Failed(e)),
            // Without the service the list still works, for browsing and exporting.
            _ => w.post(Msg::Volumes(volumes::scan_disks())),
        });
    }

    /// Runs a service request off the UI thread, then refreshes.
    fn request(&mut self, label: &str, req: Request, note: Option<String>) {
        self.set_busy(label);
        let w = self.wnd();
        std::thread::spawn(move || match ipc::call(&req) {
            Ok(Response::Error(e)) => w.post(Msg::Failed(e)),
            Ok(Response::Mounted(m)) => {
                let mut text = format!("Mounted at {}", m.mount_point);
                if let Some(r) = m.ro_reasons.first() {
                    text = format!("Mounted read-only at {}. {r}", m.mount_point);
                }
                w.post(Msg::Done { note: Some(text) });
            }
            Ok(_) => w.post(Msg::Done { note }),
            Err(e) => w.post(Msg::Failed(format!("The service didn't answer: {e}"))),
        });
    }

    fn mount_request(&self, v: &Volume, c: &Choice) -> MountRequest {
        MountRequest {
            target: v.target.clone(),
            mount_point: c.letter.map_or_else(String::new, |l| format!("{l}:")),
            write: c.write,
            hide_dotfiles: true,
            codepage: 0,
            uid: None,
            gid: None,
        }
    }

    fn confirm(&self, title: &str, text: &str) -> bool {
        let (t, b) = (wide(title), wide(text));
        // SAFETY: strings are NUL-terminated.
        let r = unsafe { MessageBoxW(self.hwnd, b.as_ptr(), t.as_ptr(), MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2) };
        r == IDOK
    }

    fn act(&mut self, a: Act) {
        // One action at a time, while still letting people look around.
        if self.busy.is_some() && !matches!(a, Act::Select(_) | Act::Dismiss | Act::WinFspHome) {
            return;
        }
        match a {
            Act::Select(i) => {
                self.selected = i;
                self.browser = None;
                self.banner = None;
                self.scrub = None;
                self.detail_scroll = 0;
            }
            Act::AddImage => self.add_image(),
            Act::Refresh => {
                self.refresh_status();
                self.scan();
            }
            Act::Mount => self.do_mount(),
            Act::Unmount => {
                let Some(m) = self.current().and_then(|v| self.mount_of(v)) else { return };
                let req = Request::Unmount { point: m.mount_point.clone() };
                self.request("Committing and detaching…", req, Some("Safe to disconnect".into()));
            }
            Act::OpenFolder => {
                if let Some(m) = self.current().and_then(|v| self.mount_of(v)) {
                    let p = wide(&format!("{}\\", m.mount_point));
                    let verb = wide("open");
                    // SAFETY: strings are NUL-terminated.
                    unsafe { ShellExecuteW(self.hwnd, verb.as_ptr(), p.as_ptr(), null(), null(), SW_SHOW) };
                }
            }
            Act::PickLetter => self.pick_letter(),
            Act::ToggleWrite => {
                if let Some(c) = self.choices.get_mut(self.selected) {
                    c.write = !c.write;
                }
            }
            Act::ToggleAuto => self.toggle_auto(),
            Act::Scrub => {
                let Some(m) = self.current().and_then(|v| self.mount_of(v)) else { return };
                let req = Request::Scrub { point: m.mount_point.clone() };
                self.request("Starting verification…", req, None);
                self.scrub = Some(ScrubState { running: true, ..ScrubState::default() });
                // SAFETY: the window is alive.
                unsafe { SetTimer(self.hwnd, TIMER_STATUS, 500, None) };
            }
            Act::Snapshot => {
                let Some(m) = self.current().and_then(|v| self.mount_of(v)) else { return };
                let t = fscore::Time::now().sec;
                let name = format!("snapshot-{t}");
                let note = format!("Created read-only snapshot {name}");
                let req = Request::Snapshot { point: m.mount_point.clone(), name, read_only: true };
                self.request("Creating snapshot…", req, Some(note));
            }
            Act::DeleteSubvolume(name) => {
                let Some(m) = self.current().and_then(|v| self.mount_of(v)) else { return };
                let point = m.mount_point.clone();
                let text = format!("Delete {name} and everything in it? This can't be undone.");
                if self.confirm("Delete this subvolume?", &text) {
                    let req = Request::DeleteSubvolume { point, name: name.clone() };
                    let note = format!("Deleted {name}. Linux reclaims the space on its next read-write mount.");
                    self.request("Deleting…", req, Some(note));
                }
            }
            Act::Browse => self.open_browser(),
            Act::CloseBrowser => self.browser = None,
            Act::BrowseUp => {
                if let Some(b) = &mut self.browser {
                    b.path.pop();
                    list_into(b);
                }
            }
            Act::BrowseRow(i) => self.browse_row(i),
            Act::Export => self.export(),
            Act::Install => self.install(),
            Act::WinFspHome => {
                let (verb, url) = (wide("open"), wide("https://github.com/winfsp/winfsp"));
                // SAFETY: strings are NUL-terminated.
                unsafe { ShellExecuteW(self.hwnd, verb.as_ptr(), url.as_ptr(), null(), null(), SW_SHOW) };
            }
            Act::Dismiss => self.banner = None,
        }
        self.invalidate();
    }

    fn do_mount(&mut self) {
        let Some(v) = self.current().cloned() else { return };
        let c = self.choices.get(self.selected).cloned().unwrap_or_default();
        if c.write
            && !self.confirm(
                "Allow writing to this volume?",
                "Changes go straight to the volume.\n\nIf Linux is hibernated on this disk, or the volume is in use \
                 anywhere else, writing can destroy data. Shut Linux down fully first, and keep a backup of anything \
                 you can't lose.",
            )
        {
            return;
        }
        let req = Request::Mount(self.mount_request(&v, &c));
        self.request("Mounting…", req, None);
    }

    fn toggle_auto(&mut self) {
        let Some(v) = self.current().cloned() else { return };
        let on = self.autos.contains(&v.uuid);
        let c = self.choices.get(self.selected).cloned().unwrap_or_default();
        let mount = (!on).then(|| self.mount_request(&v, &c));
        self.request("Saving…", Request::SetAutomount { uuid: v.uuid.clone(), mount }, None);
        if on {
            self.autos.retain(|u| *u != v.uuid);
        } else {
            self.autos.push(v.uuid);
        }
    }

    fn add_image(&mut self) {
        let mut buf = [0u16; 1024];
        let filter: Vec<u16> = "Disk images\0*.img;*.raw;*.bin;*.dd;*.iso\0All files\0*.*\0\0".encode_utf16().collect();
        // SAFETY: an all-zero OPENFILENAMEW is valid before its fields are set.
        let mut o: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        o.lStructSize = size_of::<OPENFILENAMEW>() as u32;
        o.hwndOwner = self.hwnd;
        o.lpstrFilter = filter.as_ptr();
        o.lpstrFile = buf.as_mut_ptr();
        o.nMaxFile = buf.len() as u32;
        o.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
        // SAFETY: `o` points at buffers that outlive the call.
        if unsafe { GetOpenFileNameW(&mut o) } == 0 {
            return;
        }
        let n = buf.iter().position(|c| *c == 0).unwrap_or(0);
        let path: PathBuf = String::from_utf16_lossy(&buf[..n]).into();
        self.set_busy("Reading the image…");
        let w = self.wnd();
        std::thread::spawn(move || match ipc::call(&Request::Inspect { path: path.clone() }) {
            Ok(Response::Volume(v)) => w.post(Msg::Added(v)),
            _ => w.post(Msg::Added(Box::new(volumes::describe_image(&path)))),
        });
    }

    fn pick_letter(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;
        // SAFETY: a fresh popup menu, destroyed below.
        let menu = unsafe { CreatePopupMenu() };
        // SAFETY: no arguments.
        let used = unsafe { GetLogicalDrives() };
        let auto = wide("Next free letter");
        // SAFETY: `menu` is live; strings are NUL-terminated.
        unsafe {
            AppendMenuW(menu, MF_STRING, 1, auto.as_ptr());
            for i in (3..26u32).rev() {
                if used & (1 << i) == 0 {
                    let label = wide(&format!("{}:", (b'A' + i as u8) as char));
                    AppendMenuW(menu, MF_STRING, 2 + i as usize, label.as_ptr());
                }
            }
            let mut p = POINT { x: 0, y: 0 };
            GetCursorPos(&mut p);
            let id = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, p.x, p.y, 0, self.hwnd, null());
            DestroyMenu(menu);
            if let Some(c) = self.choices.get_mut(self.selected) {
                match id {
                    0 => {}
                    1 => c.letter = None,
                    n => c.letter = Some((b'A' + (n - 2) as u8) as char),
                }
            }
        }
    }

    fn open_browser(&mut self) {
        let Some(v) = self.current().cloned() else { return };
        self.set_busy("Opening…");
        let w = self.wnd();
        std::thread::spawn(move || match volumes::open(&v.target, MountOpts::default()) {
            Ok(fs) => {
                let mut b = Browser { fs: Some(fs), target: v.target, path: vec![], rows: vec![], scroll: 0, selected: None };
                list_into(&mut b);
                w.post(Msg::Browser(Box::new(b)));
            }
            Err(e) => w.post(Msg::Failed(e.to_string())),
        });
    }

    fn browse_row(&mut self, i: usize) {
        let Some(b) = &mut self.browser else { return };
        if b.selected == Some(i) {
            if let Some(r) = b.rows.get(i) {
                if r.kind == FileKind::Dir {
                    b.path.push(r.name.clone());
                    list_into(b);
                    return;
                }
            }
        }
        b.selected = Some(i);
    }

    /// Copies the selection, or the current folder, to a folder the user picks.
    fn export(&mut self) {
        let Some(b) = &self.browser else { return };
        let mut path = b.path.clone();
        let mut leaf = path.last().cloned().unwrap_or_else(|| "volume".into());
        if let Some(r) = b.selected.and_then(|i| b.rows.get(i)) {
            leaf = r.name.clone();
            path.push(r.name.clone());
        }
        let Some(dest) = pick_folder(self.hwnd) else { return };
        let Some(safe) = crate::names::host_component(leaf.as_bytes()) else { return };
        let dest = dest.join(safe);
        let (target, src) = (b.target.clone(), format!("/{}", path.join("/")));
        self.set_busy("Exporting…");
        let w = self.wnd();
        std::thread::spawn(move || match cli::export_path(&target, &src, &dest) {
            Ok(n) => w.post(Msg::Done { note: Some(format!("Exported {n} files to {}", dest.display())) }),
            Err(e) => w.post(Msg::Failed(e)),
        });
    }

    fn install(&mut self) {
        self.set_busy("Installing…");
        let w = self.wnd();
        std::thread::spawn(move || match crate::install::install() {
            Ok(()) => w.post(Msg::Done { note: Some("NixMount is installed and ready".into()) }),
            Err(e) => w.post(Msg::Failed(e)),
        });
    }

    fn receive(&mut self, m: Msg) {
        match m {
            Msg::Status { mounts, autos, winfsp } => {
                let changed = mounts != self.mounts
                    || autos != self.autos
                    || winfsp != self.winfsp
                    || self.service != Service::Ready;
                // Counters only move while something is mounted, so only then is it worth
                // asking; an idle window with nothing mounted stays completely quiet.
                // SAFETY: the window is alive.
                unsafe {
                    if mounts.is_empty() {
                        KillTimer(self.hwnd, TIMER_POLL);
                    } else {
                        SetTimer(self.hwnd, TIMER_POLL, 2000, None);
                    }
                }
                self.mounts = mounts;
                self.autos = autos;
                self.winfsp = winfsp;
                self.service = Service::Ready;
                if !self.scanned {
                    self.scanned = true;
                    self.scan();
                }
                if !changed {
                    return;
                }
            }
            Msg::NoService => {
                self.service = Service::Missing;
                self.winfsp = crate::winfsp::available();
                if !self.scanned {
                    self.scanned = true;
                    self.scan();
                }
            }
            Msg::Volumes(v) => {
                self.busy = None;
                let old: Vec<(Target, Choice)> =
                    self.volumes.iter().map(|x| x.target.clone()).zip(self.choices.iter().cloned()).collect();
                self.choices = v
                    .iter()
                    .map(|x| old.iter().find(|o| o.0 == x.target).map_or_else(Choice::default, |o| o.1.clone()))
                    .collect();
                self.volumes = v;
                self.selected = self.selected.min(self.volumes.len().saturating_sub(1));
            }
            Msg::Added(v) => {
                self.busy = None;
                if let Some(e) = &v.error {
                    self.banner = Some((true, format!("Can't use this image: {e}")));
                } else if !self.volumes.iter().any(|x| x.target == v.target) {
                    self.volumes.push(*v);
                    self.choices.push(Choice::default());
                    self.selected = self.volumes.len() - 1;
                }
            }
            Msg::Done { note } => {
                self.busy = None;
                self.banner = note.map(|n| (false, n));
                self.refresh_status();
            }
            Msg::Failed(e) => {
                self.busy = None;
                self.banner = Some((true, e));
                self.refresh_status();
            }
            Msg::Scrub(s) => {
                if !s.running {
                    // SAFETY: the window is alive.
                    unsafe { KillTimer(self.hwnd, TIMER_STATUS) };
                }
                self.scrub = Some(s);
            }
            Msg::Browser(b) => {
                self.busy = None;
                self.browser = Some(*b);
            }
        }
        self.invalidate();
    }

    fn poll_scrub(&self) {
        let w = self.wnd();
        std::thread::spawn(move || {
            if let Ok(Response::Scrub(s)) = ipc::call(&Request::ScrubProgress) {
                w.post(Msg::Scrub(s));
            }
        });
    }

    fn button(&mut self, r: Rect, label: &str, act: Act, primary: bool) {
        let t = self.theme();
        let hot = self.hover.as_ref() == Some(&act);
        let radius = self.canvas.px(6.0);
        // One action at a time: a double click can't start a second mount.
        if self.busy.is_some() {
            self.canvas.card(r, radius, t.card, t.line);
            self.canvas.text(r, label, Font::Body, t.muted, true);
            return;
        }
        if primary {
            self.canvas.round(r, radius, t.accent);
            self.canvas.text(r, label, Font::Strong, t.on_accent, true);
        } else {
            let fill = if hot { t.hover } else { t.card };
            self.canvas.card(r, radius, fill, t.line);
            self.canvas.text(r, label, Font::Body, t.text, true);
        }
        self.region(r, act);
    }

    /// A square button holding one glyph.
    fn glyph_button(&mut self, r: Rect, glyph: &str, act: Act, enabled: bool) {
        let t = self.theme();
        let hot = enabled && self.hover.as_ref() == Some(&act);
        self.canvas.card(r, self.canvas.px(6.0), if hot { t.hover } else { t.card }, t.line);
        self.canvas.text(r, glyph, Font::Icon, if enabled { t.text } else { t.line }, true);
        if enabled {
            self.region(r, act);
        }
    }

    fn region(&mut self, rect: Rect, act: Act) {
        let focused = self.focus == Some(self.regions.len());
        self.regions.push(Region { rect, act });
        if focused {
            let t = self.theme();
            let (gap, w) = (self.canvas.px(2.0), self.canvas.px(2.0).max(1));
            let outer = rect.inset(-gap);
            self.canvas.ring(outer, self.canvas.px(8.0), w, t.accent);
        }
    }

    fn switch(&mut self, r: Rect, label: &str, hint: &str, on: bool, enabled: bool, act: Act) {
        let t = self.theme();
        let (sw, sh) = (self.canvas.px(36.0), self.canvas.px(20.0));
        let sy = r.y + self.canvas.px(2.0);
        let track = Rect::new(r.x, sy, sw, sh);
        let knob = sh / 2 - self.canvas.px(4.0);
        let kx = if on { track.right() - sh / 2 } else { track.x + sh / 2 };
        // Off is an outline and on is solid, so the state reads without comparing the two.
        if on && enabled {
            self.canvas.round(track, sh / 2, t.accent);
            self.canvas.circle(kx, track.y + sh / 2, knob, t.on_accent);
        } else {
            let line = if enabled { t.muted } else { t.line };
            self.canvas.card(track, sh / 2, t.card, line);
            self.canvas.circle(kx, track.y + sh / 2, knob, line);
        }
        let tx = r.x + sw + self.canvas.px(12.0);
        let tw = r.right() - tx;
        let color = if enabled { t.text } else { t.muted };
        self.canvas.text(Rect::new(tx, r.y, tw, self.canvas.px(22.0)), label, Font::Body, color, false);
        if !hint.is_empty() {
            let y = r.y + self.canvas.px(22.0);
            self.canvas.text(Rect::new(tx, y, tw, self.canvas.px(18.0)), hint, Font::Small, t.muted, false);
        }
        if enabled {
            self.region(r, act);
        }
    }

    /// A thin thumb showing that a list continues, and how far.
    fn scrollbar(&mut self, x: i32, y: i32, h: i32, offset: i32, visible: i32, total: i32) {
        if total <= visible || total <= 0 {
            return;
        }
        let t = self.theme();
        let w = self.canvas.px(3.0).max(2);
        let thumb = (h as i64 * visible as i64 / total as i64) as i32;
        let thumb = thumb.max(self.canvas.px(24.0)).min(h);
        let travel = h - thumb;
        let at = (travel as i64 * offset as i64 / (total - visible) as i64) as i32;
        self.canvas.round(Rect::new(x, y + at, w, thumb), w, t.line);
    }

    fn pill(&mut self, right: i32, y: i32, label: &str, c: Color) -> i32 {
        let t = self.theme();
        let (tw, _) = self.canvas.measure(label, Font::Small);
        let (pad, h) = (self.canvas.px(10.0), self.canvas.px(24.0));
        let r = Rect::new(right - tw - pad * 2 - self.canvas.px(14.0), y, tw + pad * 2 + self.canvas.px(14.0), h);
        self.canvas.card(r, h / 2, t.card, t.line);
        self.canvas.circle(r.x + pad + self.canvas.px(1.0), r.y + h / 2, self.canvas.px(3.5), c);
        let text = Rect::new(r.x + pad + self.canvas.px(8.0), r.y, tw + pad, h);
        self.canvas.text(text, label, Font::Small, t.text, false);
        r.x
    }

    fn paint(&mut self) {
        let t = self.theme();
        self.regions.clear();
        let (w, h) = (self.canvas.w, self.canvas.h);
        let side = self.canvas.px(280.0).min(w / 2);
        self.canvas.fill(Rect::new(0, 0, w, h), t.bg);
        self.canvas.fill(Rect::new(0, 0, side, h), t.side);
        self.canvas.fill(Rect::new(side, 0, self.canvas.px(1.0).max(1), h), t.line);
        self.paint_sidebar(Rect::new(0, 0, side, h));
        let body = Rect::new(side + 1, 0, w - side - 1, h);
        if self.browser.is_some() {
            self.paint_browser(body);
        } else {
            self.paint_details(body);
        }
    }

    fn paint_sidebar(&mut self, r: Rect) {
        let t = self.theme();
        let p = |c: &Canvas, v: f32| c.px(v);
        let pad = p(&self.canvas, 16.0);
        let row_h = p(&self.canvas, 56.0);
        let step = row_h + p(&self.canvas, 2.0);
        let x = r.x + pad;
        let cw = r.w - pad * 2;
        let mut y = p(&self.canvas, 16.0);
        self.canvas.text(Rect::new(x, y, cw, p(&self.canvas, 24.0)), "Volumes", Font::Strong, t.text, false);
        y += p(&self.canvas, 32.0);
        let list_top = y;
        let bottom = r.bottom() - p(&self.canvas, 136.0);
        let list: Vec<(String, String, String, bool, bool)> = self
            .volumes
            .iter()
            .map(|v| {
                let name = if v.label.is_empty() { v.title.clone() } else { v.label.clone() };
                let icon = if matches!(v.target, Target::Image { .. }) {
                    I_IMAGE
                } else if v.removable {
                    I_USB
                } else {
                    I_DISK
                };
                let sub = format!("{} · {}", v.kind, human(v.size));
                (name, sub, icon.to_string(), self.mount_of(v).is_some(), v.mountable)
            })
            .collect();
        if list.is_empty() {
            let msg = if self.busy.is_some() { "Looking…" } else { "None found" };
            self.canvas.text(Rect::new(x, y, cw, p(&self.canvas, 24.0)), msg, Font::Body, t.muted, false);
        }
        // Keep the selection in view when the keyboard moves it past either end.
        let fits = ((bottom - list_top) / step).max(1) as usize;
        self.side_max = list.len().saturating_sub(fits);
        if self.selected < self.side_scroll {
            self.side_scroll = self.selected;
        } else if self.selected >= self.side_scroll + fits {
            self.side_scroll = self.selected + 1 - fits;
        }
        self.side_scroll = self.side_scroll.min(self.side_max);
        for (i, (name, sub, icon, mounted, usable)) in list.iter().enumerate().skip(self.side_scroll).take(fits) {
            let row = Rect::new(r.x + p(&self.canvas, 8.0), y, r.w - p(&self.canvas, 16.0), row_h);
            let hot = self.hover == Some(Act::Select(i));
            let sel = i == self.selected;
            if sel || hot {
                let radius = p(&self.canvas, 6.0);
                self.canvas.round(row, radius, if sel { t.selected } else { t.hover });
            }
            let ix = row.x + p(&self.canvas, 12.0);
            let color = if *usable { t.text } else { t.muted };
            self.canvas.text(Rect::new(ix, row.y, p(&self.canvas, 24.0), row.h), icon, Font::IconLarge, color, false);
            let tx = ix + p(&self.canvas, 34.0);
            let tw = row.right() - tx - p(&self.canvas, 18.0);
            let y1 = row.y + p(&self.canvas, 9.0);
            self.canvas.text(Rect::new(tx, y1, tw, p(&self.canvas, 20.0)), name, Font::Body, color, false);
            let y2 = row.y + p(&self.canvas, 29.0);
            self.canvas.text(Rect::new(tx, y2, tw, p(&self.canvas, 18.0)), sub, Font::Small, t.muted, false);
            if *mounted {
                let radius = p(&self.canvas, 4.0);
                self.canvas.circle(row.right() - p(&self.canvas, 12.0), row.y + row.h / 2, radius, t.ok);
            }
            self.region(row, Act::Select(i));
            y += step;
        }
        let bar_x = r.right() - p(&self.canvas, 6.0);
        let shown = list.len().min(fits) as i32;
        self.scrollbar(bar_x, list_top, shown * step, self.side_scroll as i32, shown, list.len() as i32);
        let by = r.bottom() - p(&self.canvas, 128.0);
        let bh = p(&self.canvas, 32.0);
        let half = (cw - p(&self.canvas, 8.0)) / 2;
        self.icon_button(Rect::new(x, by, half, bh), I_ADD, "Add image", Act::AddImage);
        self.icon_button(Rect::new(x + half + p(&self.canvas, 8.0), by, half, bh), I_REFRESH, "Refresh", Act::Refresh);
        let sy = by + bh + p(&self.canvas, 12.0);
        let (dot, label) = match (&self.service, self.winfsp) {
            (Service::Ready, true) => (t.ok, "Ready"),
            (Service::Ready, false) => (t.warn, "Driver missing"),
            (Service::Missing, _) => (t.warn, "Not installed yet"),
            (Service::Unknown, _) => (t.muted, "Connecting…"),
        };
        let radius = p(&self.canvas, 4.0);
        self.canvas.circle(x + radius, sy + p(&self.canvas, 12.0), radius, dot);
        let tx = x + p(&self.canvas, 16.0);
        self.canvas.text(Rect::new(tx, sy, cw - p(&self.canvas, 16.0), p(&self.canvas, 24.0)), label, Font::Small, t.muted, false);
        // The WinFsp license asks for this notice and a link in the interface.
        let nr = Rect::new(x, sy + p(&self.canvas, 28.0), cw, p(&self.canvas, 34.0));
        let notice = "WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos";
        let hot = self.hover == Some(Act::WinFspHome);
        self.canvas.paragraph(nr, notice, Font::Small, if hot { t.text } else { t.muted });
        self.region(nr, Act::WinFspHome);
    }

    fn icon_button(&mut self, r: Rect, icon: &str, label: &str, act: Act) {
        let t = self.theme();
        let hot = self.hover.as_ref() == Some(&act);
        let radius = self.canvas.px(6.0);
        self.canvas.card(r, radius, if hot { t.hover } else { t.side }, t.line);
        let (tw, _) = self.canvas.measure(label, Font::Small);
        let gap = self.canvas.px(22.0);
        let x = r.x + (r.w - tw - gap) / 2;
        self.canvas.text(Rect::new(x, r.y, self.canvas.px(18.0), r.h), icon, Font::Icon, t.text, false);
        self.canvas.text(Rect::new(x + gap, r.y, tw + 2, r.h), label, Font::Small, t.text, false);
        self.region(r, act);
    }

    fn paint_setup(&mut self, r: Rect, y: i32) -> i32 {
        let t = self.theme();
        let radius = self.canvas.px(8.0);
        if self.service == Service::Unknown || (self.service == Service::Ready && self.winfsp) {
            return y;
        }
        let (title, text, label, act) = (
            "Install NixMount",
            "One step sets up the driver and background service that give volumes a drive letter. Everything is \
             included, with nothing else to download.",
            "Install",
            Act::Install,
        );
        let inner = r.w - self.canvas.px(32.0);
        let tw = inner - self.canvas.px(170.0);
        let h = self.canvas.px(88.0);
        let card = Rect::new(r.x, y, r.w, h);
        self.canvas.card(card, radius, t.card, t.line);
        let tx = r.x + self.canvas.px(16.0);
        let ty = y + self.canvas.px(12.0);
        self.canvas.text(Rect::new(tx, ty, tw, self.canvas.px(20.0)), title, Font::Strong, t.text, false);
        let pr = Rect::new(tx, ty + self.canvas.px(22.0), tw, self.canvas.px(44.0));
        self.canvas.paragraph(pr, text, Font::Small, t.muted);
        let bw = self.canvas.px(136.0);
        let bh = self.canvas.px(34.0);
        let br = Rect::new(card.right() - bw - self.canvas.px(16.0), y + (h - bh) / 2, bw, bh);
        self.button(br, label, act, true);
        y + h + self.canvas.px(16.0)
    }

    fn paint_banner(&mut self, r: Rect, y: i32) -> i32 {
        let t = self.theme();
        let radius = self.canvas.px(6.0);
        if let Some(b) = self.busy.clone() {
            let h = self.canvas.px(36.0);
            self.canvas.card(Rect::new(r.x, y, r.w, h), radius, t.card, t.line);
            let tr = Rect::new(r.x + self.canvas.px(14.0), y, r.w - self.canvas.px(28.0), h);
            self.canvas.text(tr, &b, Font::Body, t.muted, false);
            return y + h + self.canvas.px(12.0);
        }
        let Some((is_err, msg)) = self.banner.clone() else { return y };
        let c = if is_err { t.bad } else { t.ok };
        let tw = r.w - self.canvas.px(64.0);
        let h = self.canvas.px(16.0) + self.canvas.wrapped_height(&msg, Font::Body, tw);
        self.canvas.card(Rect::new(r.x, y, r.w, h), radius, t.card, c);
        let pr = Rect::new(r.x + self.canvas.px(14.0), y + self.canvas.px(8.0), tw, h);
        self.canvas.paragraph(pr, &msg, Font::Body, t.text);
        let close = Rect::new(r.right() - self.canvas.px(36.0), y + self.canvas.px(4.0), self.canvas.px(28.0), self.canvas.px(28.0));
        self.canvas.text(close, I_CLOSE, Font::IconSmall, t.muted, true);
        self.region(close, Act::Dismiss);
        y + h + self.canvas.px(12.0)
    }

    fn paint_details(&mut self, area: Rect) {
        let pad = self.canvas.px(28.0);
        let r = Rect::new(area.x + pad, area.y, area.w - pad * 2, area.h);
        let top = self.canvas.px(24.0) - self.detail_scroll;
        let end = self.details(r, top);
        // Scrolling only exists when the window is too short for the content.
        self.detail_max = (end + self.detail_scroll + self.canvas.px(24.0) - area.h).max(0);
        if self.detail_scroll > self.detail_max {
            self.detail_scroll = self.detail_max;
            self.invalidate();
        }
        let x = area.right() - self.canvas.px(6.0);
        self.scrollbar(x, 0, area.h, self.detail_scroll, area.h, area.h + self.detail_max);
    }

    /// The first thing a new user may see, so it says what to do and offers the way forward.
    fn empty_state(&mut self, r: Rect, y: i32) -> i32 {
        let t = self.theme();
        if self.busy.is_some() {
            return y;
        }
        let block = self.canvas.px(132.0);
        let top = y.max((r.h - block) / 2);
        let line = |me: &App, v: f32| me.canvas.px(v);
        let icon = Rect::new(r.x, top - line(self, 16.0), r.w, line(self, 48.0));
        self.canvas.text(icon, I_DISK, Font::IconHero, t.muted, true);
        let title = Rect::new(r.x, top + line(self, 36.0), r.w, line(self, 28.0));
        self.canvas.text(title, "No Linux volumes found", Font::Heading, t.text, true);
        let text = Rect::new(r.x, title.bottom(), r.w, line(self, 24.0));
        self.canvas.text(text, "Connect a disk with an ext or Btrfs volume, or open a disk image.", Font::Body, t.muted, true);
        let (bw, bh) = (line(self, 128.0), line(self, 36.0));
        let b = Rect::new(r.x + (r.w - bw) / 2, text.bottom() + line(self, 12.0), bw, bh);
        self.button(b, "Add image", Act::AddImage, true);
        b.bottom()
    }

    /// One label and value on a row of a card. Long values end in an ellipsis.
    fn fact(&mut self, x: i32, y: i32, width: i32, k: &str, val: &str) {
        let t = self.theme();
        let (lw, h) = (self.canvas.px(68.0), self.canvas.px(22.0));
        self.canvas.text(Rect::new(x, y, lw, h), k, Font::Small, t.muted, false);
        self.canvas.text(Rect::new(x + lw, y, width - lw, h), val, Font::Small, t.text, false);
    }

    /// Paints the selected volume from `y` down and returns where it ended.
    fn details(&mut self, r: Rect, mut y: i32) -> i32 {
        let t = self.theme();
        y = self.paint_banner(r, y);
        y = self.paint_setup(r, y);
        let Some(v) = self.current().cloned() else { return self.empty_state(r, y) };
        let mounted = self.mount_of(&v).cloned();
        let name = if v.label.is_empty() { v.title.clone() } else { v.label.clone() };

        let (status, dot) = match &mounted {
            Some(m) if m.read_only => (format!("Read-only at {}", m.mount_point), t.warn),
            Some(m) => (format!("Mounted at {}", m.mount_point), t.ok),
            None => ("Not mounted".to_string(), t.muted),
        };
        let px = self.pill(r.right(), y + self.canvas.px(6.0), &status, dot);
        let title = Rect::new(r.x, y, px - r.x - self.canvas.px(12.0), self.canvas.px(36.0));
        self.canvas.text(title, &name, Font::Title, t.text, false);
        y += self.canvas.px(38.0);
        let sub = format!("{} · {} · {}", v.kind, human(v.size), v.location);
        self.canvas.text(Rect::new(r.x, y, r.w, self.canvas.px(20.0)), &sub, Font::Body, t.muted, false);
        y += self.canvas.px(34.0);

        if let Some(e) = &v.error {
            let pr = Rect::new(r.x, y, r.w, self.canvas.px(60.0));
            y += self.canvas.paragraph(pr, e, Font::Body, t.warn) + self.canvas.px(12.0);
        }

        // Capacity.
        let (used, total) = match &mounted {
            Some(m) => (m.total_bytes.saturating_sub(m.free_bytes), m.total_bytes),
            None => (v.used.unwrap_or(0), v.size),
        };
        if total > 0 && v.used.is_some() {
            let bh = self.canvas.px(8.0);
            let bar = Rect::new(r.x, y, r.w, bh);
            self.canvas.round(bar, bh / 2, t.track);
            let frac = (used as f64 / total as f64).clamp(0.0, 1.0);
            let fill = ((bar.w as f64 * frac) as i32).max(bh);
            let color = if frac > 0.9 { t.warn } else { t.accent };
            self.canvas.round(Rect::new(r.x, y, fill, bh), bh / 2, color);
            y += bh + self.canvas.px(8.0);
            let cap = format!("{} used of {} · {} free", human(used), human(total), human(total - used.min(total)));
            self.canvas.text(Rect::new(r.x, y, r.w, self.canvas.px(18.0)), &cap, Font::Small, t.muted, false);
            y += self.canvas.px(32.0);
        }

        // Actions.
        let bh = self.canvas.px(36.0);
        let gap = self.canvas.px(8.0);
        let mut bx = r.x;
        let usable = v.mountable && self.winfsp && self.service == Service::Ready;
        let mut add = |me: &mut App, label: &str, act: Act, primary: bool, width: f32| {
            let bw = me.canvas.px(width);
            me.button(Rect::new(bx, y, bw, bh), label, act, primary);
            bx += bw + gap;
        };
        if mounted.is_some() {
            add(self, "Open", Act::OpenFolder, true, 96.0);
            add(self, "Unmount", Act::Unmount, false, 104.0);
            add(self, "Verify checksums", Act::Scrub, false, 148.0);
            if v.kind == "btrfs" {
                add(self, "Snapshot", Act::Snapshot, false, 104.0);
            }
        } else {
            if usable {
                add(self, "Mount", Act::Mount, true, 104.0);
            }
            if v.mountable {
                add(self, "Browse files", Act::Browse, false, 120.0);
            }
        }
        y += bh + self.canvas.px(20.0);

        // Why the volume behaves the way it does comes first: it changes what is safe.
        let reasons = mounted.as_ref().map_or_else(|| v.ro_reasons.clone(), |m| m.ro_reasons.clone());
        let notes = mounted.as_ref().map_or_else(|| v.notes.clone(), |m| m.notes.clone());
        let radius = self.canvas.px(8.0);
        for (line, warn) in reasons.iter().map(|l| (l, true)).chain(notes.iter().map(|l| (l, false))).take(3) {
            let tw = r.w - self.canvas.px(56.0);
            let h = self.canvas.wrapped_height(line, Font::Body, tw) + self.canvas.px(20.0);
            let card = Rect::new(r.x, y, r.w, h);
            self.canvas.card(card, radius, t.card, if warn { t.warn } else { t.line });
            let ic = Rect::new(r.x + self.canvas.px(14.0), y, self.canvas.px(20.0), self.canvas.px(40.0));
            self.canvas.text(ic, if warn { I_WARN } else { I_INFO }, Font::Icon, if warn { t.warn } else { t.muted }, false);
            let tr = Rect::new(r.x + self.canvas.px(42.0), y + self.canvas.px(10.0), tw, h);
            self.canvas.paragraph(tr, line, Font::Body, t.text);
            y += h + self.canvas.px(8.0);
        }
        y += self.canvas.px(4.0);

        // Live state of a verification pass.
        if let Some(s) = self.scrub.clone() {
            let text = if s.running {
                let pct = if s.total > 0 { s.done * 100 / s.total } else { 0 };
                format!("Verifying… {pct}%")
            } else if s.errors.is_empty() {
                format!("All good: {} verified, {} repaired", human(s.scanned_bytes), s.repaired)
            } else {
                format!("{} problems found. {}", s.errors.len(), s.errors[0])
            };
            let color = if s.errors.is_empty() { t.ok } else { t.bad };
            let tr = Rect::new(r.x, y, r.w, self.canvas.px(20.0));
            self.canvas.text(tr, &text, Font::Body, color, false);
            y += self.canvas.px(28.0);
        }

        // Two cards side by side: how it is mounted, and what it is. They stack when narrow.
        let gap = self.canvas.px(16.0);
        let stacked = r.w < self.canvas.px(560.0);
        let col = if stacked { r.w } else { (r.w - gap) / 2 };
        let pad = self.canvas.px(16.0);
        let inner = col - pad * 2;
        let c = self.choices.get(self.selected).cloned().unwrap_or_default();
        let on_auto = self.autos.contains(&v.uuid);
        let can_auto = self.service == Service::Ready && !v.uuid.is_empty();
        let head = self.canvas.px(44.0);
        let row = self.canvas.px(26.0);
        let option = self.canvas.px(52.0);

        // Raw feature flags matter to few people, so they are quiet text, not decoration.
        let features = v.features.join(", ");
        let value_w = inner - self.canvas.px(68.0);
        let features_h = self.canvas.wrapped_height(&features, Font::Small, value_w);
        let fact_rows = 2 + !features.is_empty() as i32;
        let about_h = head + (fact_rows - 1) * row + features_h.max(row) + pad;
        let left_h = if mounted.is_some() { head + 3 * row + option + pad / 2 } else { head + 3 * option + pad / 2 };
        let left_h = if v.mountable { left_h } else { 0 };
        let h = if stacked { left_h } else { left_h.max(about_h) };

        let left = Rect::new(r.x, y, col, h);
        if v.mountable {
            self.canvas.card(left, radius, t.card, t.line);
            let title = if mounted.is_some() { "This mount" } else { "Mount options" };
            let tr = Rect::new(left.x + pad, y + self.canvas.px(12.0), inner, self.canvas.px(22.0));
            self.canvas.text(tr, title, Font::Strong, t.text, false);
            let mut oy = y + head;
            if let Some(m) = &mounted {
                let mode = if m.read_only { "Read-only" } else { "Read and write" };
                self.fact(left.x + pad, oy, inner, "Access", mode);
                oy += row;
                self.fact(left.x + pad, oy, inner, "Read", &human(m.read_bytes));
                oy += row;
                self.fact(left.x + pad, oy, inner, "Written", &human(m.written_bytes));
                oy += row + self.canvas.px(6.0);
            } else {
                let letter = c.letter.map_or_else(|| "Next free letter".to_string(), |l| format!("{l}:"));
                let lr = Rect::new(left.x + pad, oy, inner, self.canvas.px(36.0));
                let hot = self.hover == Some(Act::PickLetter);
                self.canvas.card(lr, self.canvas.px(6.0), if hot { t.hover } else { t.bg }, t.line);
                let tr = Rect::new(lr.x + self.canvas.px(12.0), lr.y, lr.w - self.canvas.px(40.0), lr.h);
                self.canvas.text(tr, &format!("Drive letter: {letter}"), Font::Body, t.text, false);
                let cr = Rect::new(lr.right() - self.canvas.px(30.0), lr.y, self.canvas.px(20.0), lr.h);
                self.canvas.text(cr, I_CHEVRON, Font::Icon, t.muted, true);
                self.region(lr, Act::PickLetter);
                oy += option;
                let hint = if !v.ro_reasons.is_empty() {
                    "Not available for this volume"
                } else if c.write {
                    "Changes go to the volume"
                } else {
                    "Read-only protects the volume"
                };
                let sr = Rect::new(left.x + pad, oy, inner, self.canvas.px(42.0));
                self.switch(sr, "Allow writing", hint, c.write, v.ro_reasons.is_empty(), Act::ToggleWrite);
                oy += option;
            }
            let sr = Rect::new(left.x + pad, oy, inner, self.canvas.px(42.0));
            self.switch(sr, "Mount automatically", "Whenever this volume is present", on_auto, can_auto, Act::ToggleAuto);
        }

        let about = if stacked {
            Rect::new(r.x, y + h + gap, col, about_h)
        } else {
            Rect::new(r.x + col + gap, y, col, h.max(about_h))
        };
        self.canvas.card(about, radius, t.card, t.line);
        let tr = Rect::new(about.x + pad, about.y + self.canvas.px(12.0), inner, self.canvas.px(22.0));
        self.canvas.text(tr, "About this volume", Font::Strong, t.text, false);
        let mut ay = about.y + head;
        self.fact(about.x + pad, ay, inner, "Type", &v.kind);
        ay += row;
        let uuid = if v.uuid.is_empty() { "Unknown" } else { &v.uuid };
        self.fact(about.x + pad, ay, inner, "UUID", uuid);
        ay += row;
        if !features.is_empty() {
            let lw = self.canvas.px(68.0);
            let lr = Rect::new(about.x + pad, ay, lw, self.canvas.px(22.0));
            self.canvas.text(lr, "Features", Font::Small, t.muted, false);
            let fr = Rect::new(about.x + pad + lw, ay + self.canvas.px(3.0), value_w, features_h);
            self.canvas.paragraph(fr, &features, Font::Small, t.muted);
        }
        let mut end = about.bottom();

        // Snapshots get their own card: this is the way back out of creating them.
        let subvols = mounted.as_ref().map(|m| &m.subvolumes).filter(|s| !s.is_empty());
        if let Some(subvols) = subvols {
            let names: Vec<String> = subvols.iter().map(|s| s.0.clone()).collect();
            let sy = end + gap;
            let rows = self.chip_rows(&names, r.w - pad * 2);
            let card = Rect::new(r.x, sy, r.w, head + rows * self.canvas.px(30.0) + pad / 2);
            self.canvas.card(card, radius, t.card, t.line);
            let tr = Rect::new(card.x + pad, sy + self.canvas.px(12.0), r.w - pad * 2, self.canvas.px(22.0));
            self.canvas.text(tr, "Snapshots and subvolumes", Font::Strong, t.text, false);
            self.chips(card.x + pad, sy + head, r.w - pad * 2, &names);
            end = card.bottom();
        }
        end
    }

    fn chip_width(&self, s: &str) -> i32 {
        self.canvas.measure(s, Font::Small).0 + self.canvas.px(38.0)
    }

    /// How many rows `chips` needs at this width.
    fn chip_rows(&self, items: &[String], width: i32) -> i32 {
        let (mut x, mut rows) = (0, 1);
        for s in items {
            let w = self.chip_width(s);
            if x + w > width && x > 0 {
                rows += 1;
                x = 0;
            }
            x += w + self.canvas.px(6.0);
        }
        rows
    }

    /// Subvolumes as tags that wrap within `width`, each with its delete mark.
    fn chips(&mut self, x0: i32, y0: i32, width: i32, items: &[String]) {
        let t = self.theme();
        let (h, gap) = (self.canvas.px(24.0), self.canvas.px(6.0));
        let (mut x, mut y) = (x0, y0);
        for s in items {
            let w = self.chip_width(s);
            if x + w > x0 + width && x > x0 {
                x = x0;
                y += h + gap;
            }
            let c = Rect::new(x, y, w, h);
            let act = Act::DeleteSubvolume(s.clone());
            let hot = self.hover.as_ref() == Some(&act);
            self.canvas.round(c, h / 2, if hot { t.hover } else { t.track });
            let label = Rect::new(c.x + self.canvas.px(12.0), c.y, w - self.canvas.px(30.0), h);
            self.canvas.text(label, s, Font::Small, t.text, false);
            let mark = Rect::new(c.right() - self.canvas.px(24.0), c.y, self.canvas.px(18.0), h);
            self.canvas.text(mark, I_CLOSE, Font::IconSmall, t.muted, true);
            self.region(c, act);
            x += w + gap;
        }
    }

    fn paint_browser(&mut self, area: Rect) {
        let t = self.theme();
        let pad = self.canvas.px(28.0);
        let r = Rect::new(area.x + pad, area.y, area.w - pad * 2, area.h);
        let mut y = self.canvas.px(20.0);
        y = self.paint_banner(r, y);
        let bh = self.canvas.px(34.0);
        let Some(b) = &self.browser else { return };
        let at_root = b.path.is_empty();
        let crumb = format!("/{}", b.path.join("/"));
        let label = if b.selected.is_some() { "Export selection" } else { "Export folder" };

        let up = Rect::new(r.x, y, self.canvas.px(40.0), bh);
        self.glyph_button(up, I_BACK, Act::BrowseUp, !at_root);
        let (ew, cw) = (self.canvas.px(136.0), self.canvas.px(76.0));
        let er = Rect::new(r.right() - ew, y, ew, bh);
        let cr = Rect::new(er.x - cw - self.canvas.px(8.0), y, cw, bh);
        let tr = Rect::new(up.right() + self.canvas.px(14.0), y, cr.x - up.right() - self.canvas.px(24.0), bh);
        self.canvas.text(tr, &crumb, Font::Strong, t.text, false);
        self.button(cr, "Close", Act::CloseBrowser, false);
        self.button(er, label, Act::Export, true);
        y += bh + self.canvas.px(14.0);

        let row_h = self.canvas.px(32.0);
        let hdr = self.canvas.px(24.0);
        let inset = self.canvas.px(12.0);
        let size_w = self.canvas.px(100.0);
        let size_r = Rect::new(r.right() - size_w - inset, y, size_w, hdr);
        self.canvas.text(Rect::new(r.x + self.canvas.px(36.0), y, r.w / 2, hdr), "Name", Font::Small, t.muted, false);
        self.canvas.text_right(size_r, "Size", Font::Small, t.muted);
        y += hdr;
        self.canvas.fill(Rect::new(r.x, y, r.w, self.canvas.px(1.0).max(1)), t.line);
        y += self.canvas.px(4.0);
        let list_top = y;
        let Some(b) = &self.browser else { return };
        let (scroll, sel) = (b.scroll, b.selected);
        let rows: Vec<(String, FileKind, u64)> = b.rows.iter().map(|x| (x.name.clone(), x.kind, x.size)).collect();
        if rows.is_empty() {
            let tr = Rect::new(r.x, y + self.canvas.px(8.0), r.w, self.canvas.px(24.0));
            self.canvas.text(tr, "This folder is empty", Font::Body, t.muted, true);
            return;
        }
        let bottom = r.bottom() - self.canvas.px(12.0);
        let fits = ((bottom - y) / row_h).max(1) as usize;
        let first = scroll.max(0) as usize;
        for (i, (name, kind, size)) in rows.iter().enumerate().skip(first).take(fits) {
            let row = Rect::new(r.x - self.canvas.px(6.0), y, r.w + self.canvas.px(12.0), row_h);
            let radius = self.canvas.px(4.0);
            if sel == Some(i) {
                self.canvas.round(row, radius, t.selected);
            } else if self.hover == Some(Act::BrowseRow(i)) {
                self.canvas.round(row, radius, t.hover);
            }
            let icon = match kind {
                FileKind::Dir => I_FOLDER,
                FileKind::Symlink => I_LINK,
                _ => I_FILE,
            };
            self.canvas.text(Rect::new(r.x + self.canvas.px(4.0), y, self.canvas.px(24.0), row_h), icon, Font::Icon, t.muted, false);
            let nw = r.w - size_w - self.canvas.px(56.0);
            self.canvas.text(Rect::new(r.x + self.canvas.px(36.0), y, nw, row_h), name, Font::Body, t.text, false);
            if *kind != FileKind::Dir {
                let sr = Rect::new(size_r.x, y, size_w, row_h);
                self.canvas.text_right(sr, &human(*size), Font::Small, t.muted);
            }
            self.region(row, Act::BrowseRow(i));
            y += row_h;
        }
        let x = area.right() - self.canvas.px(6.0);
        self.scrollbar(x, list_top, bottom - list_top, first as i32, fits as i32, rows.len() as i32);
    }

    fn hit(&self, x: i32, y: i32) -> Option<&Region> {
        self.regions.iter().rev().find(|r| r.rect.contains(x, y))
    }

    /// Scrolls whichever pane the pointer is over.
    fn wheel(&mut self, x: i32, delta: i32) {
        let notches = delta.signum();
        if x < self.canvas.px(280.0).min(self.canvas.w / 2) {
            let next = self.side_scroll as i32 - notches;
            self.side_scroll = next.clamp(0, self.side_max as i32) as usize;
        } else if let Some(b) = &mut self.browser {
            let max = b.rows.len().saturating_sub(5) as i32;
            b.scroll = (b.scroll - notches * 3).clamp(0, max);
        } else {
            let step = self.canvas.px(48.0);
            self.detail_scroll = (self.detail_scroll - notches * step).clamp(0, self.detail_max);
        }
        self.invalidate();
    }

    fn key(&mut self, vk: u16) {
        match vk {
            VK_F5 => self.act(Act::Refresh),
            VK_TAB => {
                // SAFETY: no pointers involved.
                let back = unsafe { GetKeyState(VK_SHIFT as i32) } < 0;
                let n = self.regions.len();
                if n > 0 {
                    let cur = self.focus.unwrap_or(if back { 0 } else { n - 1 });
                    self.focus = Some(if back { (cur + n - 1) % n } else { (cur + 1) % n });
                    self.invalidate();
                }
            }
            VK_RETURN | VK_SPACE => {
                if let Some(a) = self.focus.and_then(|i| self.regions.get(i)).map(|r| r.act.clone()) {
                    self.act(a);
                }
            }
            VK_UP | VK_DOWN if self.browser.is_none() && !self.volumes.is_empty() => {
                let n = self.volumes.len();
                let i = if vk == VK_UP { (self.selected + n - 1) % n } else { (self.selected + 1) % n };
                self.act(Act::Select(i));
            }
            VK_ESCAPE if self.browser.is_some() => self.act(Act::CloseBrowser),
            _ => {}
        }
    }
}

/// Reads the browser's current directory: folders first, then by name.
fn list_into(b: &mut Browser) {
    b.selected = None;
    b.scroll = 0;
    b.rows.clear();
    let Some(fs) = b.fs.clone() else { return };
    let path = format!("/{}", b.path.join("/"));
    let Ok(dir) = resolve(fs.as_ref(), &path) else { return };
    let mut ents: Vec<DirEntry> = vec![];
    let _ = fs.read_dir(dir, 0, &mut |_, e| {
        ents.push(e);
        true
    });
    for e in ents {
        let (kind, size) = fs.stat(e.ino).map_or((e.kind, 0), |s| (s.kind, s.size));
        b.rows.push(Row { name: String::from_utf8_lossy(&e.name).into_owned(), kind, size });
    }
    b.rows.sort_by(|x, y| (x.kind != FileKind::Dir, &x.name).cmp(&(y.kind != FileKind::Dir, &y.name)));
}

fn pick_folder(owner: HWND) -> Option<PathBuf> {
    let title = wide("Export to");
    // SAFETY: an all-zero BROWSEINFOW is valid before its fields are set.
    let mut bi: BROWSEINFOW = unsafe { std::mem::zeroed() };
    bi.hwndOwner = owner;
    bi.lpszTitle = title.as_ptr();
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    // SAFETY: `bi` is valid for the call; the returned list is freed below.
    unsafe {
        let list = SHBrowseForFolderW(&bi);
        if list.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let ok = SHGetPathFromIDListW(list, buf.as_mut_ptr());
        windows_sys::Win32::System::Com::CoTaskMemFree(list as *const _);
        let n = buf.iter().position(|c| *c == 0).unwrap_or(0);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..n]).into())
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // SAFETY: GWLP_USERDATA holds the App set at WM_CREATE, or null before it.
    let app = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut App;
    if app.is_null() {
        return unsafe { DefWindowProcW(hwnd, msg, wp, lp) };
    }
    // SAFETY: the window procedure runs on the one thread that owns the App.
    let a = unsafe { &mut *app };
    let lo = (lp & 0xFFFF) as i16 as i32;
    let hi = ((lp >> 16) & 0xFFFF) as i16 as i32;
    match msg {
        WM_PAINT => {
            a.paint();
            // SAFETY: standard paint bracket on our window.
            unsafe {
                let mut ps = std::mem::zeroed();
                let dc = BeginPaint(hwnd, &mut ps);
                a.canvas.present(dc);
                EndPaint(hwnd, &ps);
            }
            0
        }
        WM_ERASEBKGND => 1,
        WM_SIZE => {
            a.canvas.resize(lo, hi);
            a.invalidate();
            0
        }
        WM_GETMINMAXINFO => {
            // SAFETY: lParam points at a MINMAXINFO for this message.
            let m = unsafe { &mut *(lp as *mut MINMAXINFO) };
            m.ptMinTrackSize = POINT { x: a.canvas.px(820.0), y: a.canvas.px(560.0) };
            0
        }
        WM_DPICHANGED => {
            // SAFETY: lParam points at the suggested RECT for this message.
            let r = unsafe { &*(lp as *const RECT) };
            a.canvas.set_scale((wp & 0xFFFF) as f32 / 96.0);
            // SAFETY: the window is alive.
            unsafe { SetWindowPos(hwnd, null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER) };
            0
        }
        WM_SETTINGCHANGE => {
            a.dark = system_dark();
            a.apply_title_bar();
            a.invalidate();
            0
        }
        WM_MOUSEMOVE => {
            let now = a.hit(lo, hi).map(|r| r.act.clone());
            if now != a.hover {
                a.hover = now;
                a.invalidate();
            }
            let mut tme = TRACKMOUSEEVENT {
                cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                dwFlags: TME_LEAVE,
                hwndTrack: hwnd,
                dwHoverTime: 0,
            };
            // SAFETY: `tme` is valid for the call.
            unsafe { TrackMouseEvent(&mut tme) };
            0
        }
        WM_MOUSELEAVE => {
            if a.hover.take().is_some() {
                a.invalidate();
            }
            0
        }
        WM_SETCURSOR => {
            let id = if a.hover.is_some() { IDC_HAND } else { IDC_ARROW };
            // SAFETY: a stock cursor.
            unsafe { SetCursor(LoadCursorW(null_mut(), id)) };
            1
        }
        WM_LBUTTONUP => {
            a.focus = None;
            if let Some(act) = a.hit(lo, hi).map(|r| r.act.clone()) {
                a.act(act);
            }
            0
        }
        WM_MOUSEWHEEL => {
            let mut p = POINT { x: lo, y: hi };
            // SAFETY: `p` is valid; wheel messages carry screen coordinates.
            unsafe { ScreenToClient(hwnd, &mut p) };
            a.wheel(p.x, ((wp >> 16) & 0xFFFF) as i16 as i32);
            0
        }
        WM_KEYDOWN => {
            a.key(wp as u16);
            0
        }
        WM_TIMER => {
            if wp == TIMER_POLL {
                a.refresh_status();
            } else {
                a.poll_scrub();
            }
            0
        }
        WM_WORKER => {
            // SAFETY: posted by `Wnd::post`, which gave up ownership.
            let m = unsafe { Box::from_raw(lp as *mut Msg) };
            a.receive(*m);
            0
        }
        WM_DESTROY => {
            // SAFETY: stops the message loop.
            unsafe { PostQuitMessage(0) };
            0
        }
        // SAFETY: default handling for everything else.
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

pub fn run() {
    // Raw disks and the service pipe are admin-only by design.
    if !crate::install::elevated() && crate::install::relaunch_elevated("") {
        return;
    }
    let class = wide("NixMountWindow");
    // SAFETY: standard window setup; strings outlive the calls that read them.
    unsafe {
        let inst = GetModuleHandleW(null());
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: inst,
            hIcon: LoadIconW(inst, 1 as *const u16),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hbrBackground: null_mut(),
            lpszMenuName: null(),
            lpszClassName: class.as_ptr(),
            hIconSm: LoadIconW(inst, 1 as *const u16),
        };
        RegisterClassExW(&wc);
        let title = wide("NixMount");
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1000,
            680,
            null_mut(),
            null_mut(),
            inst,
            null(),
        );
        let scale = GetDpiForWindow(hwnd) as f32 / 96.0;
        let (w, h) = ((1000.0 * scale) as i32, (640.0 * scale) as i32);
        SetWindowPos(hwnd, null_mut(), 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
        let mut rc = std::mem::zeroed();
        GetClientRect(hwnd, &mut rc);
        let app = Box::into_raw(Box::new(App {
            hwnd,
            canvas: Canvas::new(rc.right, rc.bottom, scale),
            dark: system_dark(),
            volumes: vec![],
            mounts: vec![],
            autos: vec![],
            choices: vec![],
            winfsp: true,
            service: Service::Unknown,
            selected: 0,
            regions: vec![],
            hover: None,
            focus: None,
            busy: Some("Starting…".into()),
            banner: None,
            browser: None,
            scrub: None,
            scanned: false,
            side_scroll: 0,
            side_max: 0,
            detail_scroll: 0,
            detail_max: 0,
        }));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, app as isize);
        (*app).apply_title_bar();
        (*app).refresh_status();
        ShowWindow(hwnd, SW_SHOW);
        let mut msg = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        drop(Box::from_raw(app));
    }
}

/// Renders the interface with sample data to a BMP, to check the design headlessly.
pub fn screenshot(path: &std::path::Path, dark: bool, scene: &str, width: i32, height: i32, scale: f32) {
    let sample = |label: &str, kind: &str, size: u64, used: u64, removable: bool, feats: &[&str]| Volume {
        target: Target::Partition { disk: 1, part: label.len() as u32 },
        title: "Disk 1 · Partition 2".into(),
        location: "SanDisk Extreme Pro".into(),
        size,
        kind: kind.into(),
        mountable: true,
        label: label.into(),
        uuid: "6a823ff5-4a92-4fce-b538-02dc1d57d87b".into(),
        removable,
        used: Some(used),
        features: feats.iter().map(|f| f.to_string()).collect(),
        ro_reasons: vec![],
        notes: vec![],
        error: None,
    };
    const GB: u64 = 1 << 30;
    let ext4 = [
        "has_journal", "ext_attr", "resize_inode", "dir_index", "orphan_file", "filetype", "extent", "64bit", "flex_bg",
        "metadata_csum_seed", "sparse_super", "large_file", "huge_file", "dir_nlink", "extra_isize", "metadata_csum",
    ];
    let mut quota = sample("backups", "ext4", 1863 * GB, 1770 * GB, false, &["has_journal", "extent", "quota"]);
    quota.ro_reasons = vec!["This volume uses quotas, and writing would leave them out of date".into()];
    let mut volumes = vec![
        sample("home", "ext4", 476 * GB, 199 * GB, false, &ext4),
        sample("fedora-root", "btrfs", 238 * GB, 82 * GB, true, &["free_space_tree", "no_holes", "skinny_metadata", "raid1"]),
        quota,
    ];
    if scene == "many" {
        for i in 0..14 {
            volumes.push(sample(&format!("volume-{i}"), "ext4", (i + 1) * 40 * GB, 8 * GB, false, &ext4));
        }
    }
    if scene == "empty" {
        volumes.clear();
    }
    let hwnd = null_mut();
    let mounts = if scene == "mounted" {
        vec![MountStatus {
            target: volumes[1].target.clone(),
            mount_point: "L:".into(),
            read_only: false,
            ro_reasons: vec![],
            notes: vec!["Journal recovered: 212 blocks replayed".into()],
            total_bytes: 238 * GB,
            free_bytes: 156 * GB,
            reads: 4120,
            writes: 311,
            read_bytes: 1340 << 20,
            written_bytes: 72 << 20,
            subvolumes: vec![("@home".into(), false), ("snapshot-1731000000".into(), true)],
        }]
    } else {
        vec![]
    };
    let browser = (scene == "browser").then(|| {
        let row = |name: &str, kind, size| Row { name: name.into(), kind, size };
        Browser {
            fs: None,
            target: volumes[0].target.clone(),
            path: vec!["home".into(), "maya".into()],
            rows: vec![
                row("Documents", FileKind::Dir, 0),
                row("Music", FileKind::Dir, 0),
                row("Pictures", FileKind::Dir, 0),
                row("projects", FileKind::Dir, 0),
                row("backup-2026.tar.zst", FileKind::File, 8_400_000_000),
                row("current-notes", FileKind::Symlink, 24),
                row("notes.md", FileKind::File, 18_300),
                row("thesis-final-v3.pdf", FileKind::File, 4_180_000),
                row("vacation.mp4", FileKind::File, 2_210_000_000),
            ],
            scroll: 0,
            selected: Some(7),
        }
    });
    let n = volumes.len();
    let mut a = App {
        hwnd,
        canvas: Canvas::new((width as f32 * scale) as i32, (height as f32 * scale) as i32, scale),
        dark,
        volumes,
        mounts,
        autos: vec![],
        choices: vec![Choice::default(); n],
        winfsp: scene != "setup",
        service: if scene == "setup" { Service::Missing } else { Service::Ready },
        selected: match scene {
            "mounted" => 1,
            "readonly" => 2,
            _ => 0,
        },
        regions: vec![],
        hover: None,
        focus: None,
        busy: (scene == "busy").then(|| "Mounting…".to_string()),
        banner: None,
        browser,
        scrub: None,
        scanned: true,
        side_scroll: 0,
        side_max: 0,
        detail_scroll: 0,
        detail_max: 0,
    };
    a.paint();
    let _ = a.canvas.save_bmp(path);
}
