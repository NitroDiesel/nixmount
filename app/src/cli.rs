//! The command line: everything the interface does, for scripts.
use crate::ipc::{self, Request, Response};
use crate::mounts::{MountRequest, Mounts};
use crate::volumes::{self, Target, Volume};
use crate::winfsp::{HostOptions, Mount};
use fscore::{resolve, FileKind, Filesystem, MountOpts};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const USAGE: &str = "\
Causeway: mount ext2/3/4 and Btrfs volumes on Windows.

Usage:
  causeway                        Open the interface
  causeway list                   List Linux volumes
  causeway info <target>          Show a volume's details and write eligibility
  causeway mount <target> [X:]    Mount through the service
      --rw                        Allow writing (the default is read-only)
      --foreground                Mount in this process until Ctrl+C
      --codepage <n>              Decode names with Windows code page n
      --show-dotfiles             Don't mark dotfiles hidden
      --uid <n> --gid <n>         Owner of new files
  causeway unmount <X:>           Commit and detach
  causeway sync                   Commit all mounted volumes now
  causeway ls <target> [path]     List a directory without mounting
  causeway export <target> <path> <dest>   Copy files out without mounting
  causeway scrub <X:>             Verify checksums on a mounted volume
  causeway snapshot <X:> <name> [--read-only]    Snapshot a mounted Btrfs volume
  causeway subvolume <X:> <name>  Create a Btrfs subvolume
  causeway service install|uninstall|run|debug

A target is an image file (optionally file#partition) or disk:partition, e.g. 1:3.";

fn parse_target(s: &str) -> Target {
    if let Some((d, p)) = s.split_once(':') {
        if let (Ok(disk), Ok(part)) = (d.parse(), p.parse()) {
            return Target::Partition { disk, part };
        }
    }
    if let Some((path, part)) = s.rsplit_once('#') {
        if let Ok(n) = part.parse() {
            return Target::Image { path: path.into(), partition: Some(n) };
        }
    }
    Target::Image { path: s.into(), partition: None }
}

fn call(r: &Request) -> Result<Response, String> {
    match ipc::call(r) {
        Ok(Response::Error(e)) => Err(e),
        Ok(r) => Ok(r),
        Err(_) => Err("the Causeway service isn't running: run `causeway service install` as administrator".into()),
    }
}

fn human(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", units[u])
}

fn print_volume(v: &Volume) {
    let t = match &v.target {
        Target::Partition { disk, part } => format!("{disk}:{part}"),
        Target::Image { path, .. } => path.display().to_string(),
        Target::Group { members } => members.iter().map(|m| format!("{}:{}", m.0, m.1)).collect::<Vec<_>>().join("+"),
    };
    let name = if v.label.is_empty() { &v.title } else { &v.label };
    println!("{t:<16} {:<8} {:>10}  {name}  ({})", v.kind, human(v.size), v.location);
}

fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let n = args.len();
    args.retain(|a| a != flag);
    args.len() != n
}

fn take_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    let v = args.get(i + 1).cloned();
    args.drain(i..(i + 2).min(args.len()));
    v
}

fn open_for_reading(t: &str) -> Result<Arc<dyn Filesystem>, String> {
    volumes::open(&parse_target(t), MountOpts::default()).map_err(|e| e.to_string())
}

fn cmd_info(target: &str) -> Result<(), String> {
    let fs = open_for_reading(target)?;
    let i = fs.info();
    println!("Type:       {}", i.fs_type);
    println!("Label:      {}", i.label);
    println!("UUID:       {}", i.uuid);
    println!("Size:       {} ({} free)", human(i.total_bytes), human(i.free_bytes));
    println!("Block size: {}", i.block_size);
    println!("Features:   {}", i.features.join(" "));
    for n in &i.notes {
        println!("Note:       {n}");
    }
    let path_target = parse_target(target);
    if let Target::Image { .. } = path_target {
        if let Ok(w) = volumes::open(&path_target, MountOpts { write: false, cache_bytes: 0 }) {
            let _ = w;
        }
    }
    Ok(())
}

fn cmd_ls(target: &str, path: &str) -> Result<(), String> {
    let fs = open_for_reading(target)?;
    let dir = resolve(fs.as_ref(), path).map_err(|e| e.to_string())?;
    let mut rows = vec![];
    fs.read_dir(dir, 0, &mut |_, e| {
        rows.push(e);
        true
    })
    .map_err(|e| e.to_string())?;
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    for e in rows {
        let st = fs.stat(e.ino).map_err(|e| e.to_string())?;
        let tag = match st.kind {
            FileKind::Dir => 'd',
            FileKind::Symlink => 'l',
            FileKind::File => '-',
            _ => '?',
        };
        println!("{tag}{:04o} {:>6} {:>6} {:>12}  {}", st.mode, st.uid, st.gid, st.size, String::from_utf8_lossy(&e.name));
    }
    Ok(())
}

/// Copies a file or directory tree out of a volume. Names are sanitised, so a hostile
/// volume can't climb out of `dest`; symlinks are skipped rather than followed.
fn export(fs: &dyn Filesystem, ino: fscore::Ino, dest: &Path, count: &mut u64) -> Result<(), String> {
    let st = fs.stat(ino).map_err(|e| e.to_string())?;
    match st.kind {
        FileKind::Dir => {
            std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
            let mut ents = vec![];
            fs.read_dir(ino, 0, &mut |_, e| {
                ents.push(e);
                true
            })
            .map_err(|e| e.to_string())?;
            for e in ents {
                let wide = crate::names::to_wide(&e.name, 0);
                export(fs, e.ino, &dest.join(String::from_utf16_lossy(&wide)), count)?;
            }
        }
        FileKind::File => {
            let mut f = std::fs::File::create(dest).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 1 << 20];
            let mut off = 0;
            loop {
                let n = fs.read(ino, off, &mut buf).map_err(|e| format!("{}: {e}", dest.display()))?;
                if n == 0 {
                    break;
                }
                f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                off += n as u64;
            }
            *count += 1;
        }
        _ => {}
    }
    Ok(())
}

pub fn export_path(target: &Target, path: &str, dest: &Path) -> Result<u64, String> {
    let fs = volumes::open(target, MountOpts::default()).map_err(|e| e.to_string())?;
    let ino = resolve(fs.as_ref(), path).map_err(|e| e.to_string())?;
    let mut count = 0;
    export(fs.as_ref(), ino, dest, &mut count)?;
    Ok(count)
}

fn foreground(req: MountRequest) -> Result<(), String> {
    let opts = MountOpts { write: req.write, cache_bytes: 0 };
    let fs = volumes::open(&req.target, opts).map_err(|e| e.to_string())?;
    let info = fs.info();
    let host = HostOptions {
        read_only: !req.write,
        hide_dotfiles: req.hide_dotfiles,
        codepage: req.codepage,
        uid: req.uid,
        gid: req.gid,
        ..HostOptions::default()
    };
    let point = if req.mount_point.is_empty() { "X:" } else { &req.mount_point };
    let mount = Mount::start(fs.clone(), point, host)?;
    println!("Mounted {} at {} ({})", info.fs_type, point, if info.read_only { "read-only" } else { "read-write" });
    for r in info.ro_reasons.iter().chain(&info.notes) {
        println!("  {r}");
    }
    println!("Press Enter to unmount.");
    let m = Arc::new(Mounts::default());
    m.spawn_committer();
    let keep = fs.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let _ = keep.sync();
    });
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    drop(mount);
    fs.unmount().map_err(|e| e.to_string())?;
    println!("Unmounted cleanly.");
    Ok(())
}

pub fn run(mut args: Vec<String>) -> Result<(), String> {
    let cmd = args.remove(0);
    let arg = |i: usize| args.get(i).cloned().ok_or_else(|| format!("missing argument\n\n{USAGE}"));
    match cmd.as_str() {
        "help" | "--help" | "-h" | "/?" => println!("{USAGE}"),
        "list" => {
            let vols = match ipc::call(&Request::Scan) {
                Ok(Response::Volumes(v)) => v,
                _ => volumes::scan_disks(),
            };
            if vols.is_empty() {
                println!("No Linux volumes found. Reading disks needs administrator rights.");
            }
            vols.iter().for_each(print_volume);
        }
        "info" => cmd_info(&arg(0)?)?,
        "ls" => cmd_ls(&arg(0)?, args.get(1).map_or("/", String::as_str))?,
        "export" => {
            let n = export_path(&parse_target(&arg(0)?), &arg(1)?, &PathBuf::from(arg(2)?))?;
            println!("Exported {n} files.");
        }
        "mount" => {
            let fg = take_flag(&mut args, "--foreground");
            let write = take_flag(&mut args, "--rw");
            let show = take_flag(&mut args, "--show-dotfiles");
            let codepage = take_value(&mut args, "--codepage").and_then(|v| v.parse().ok()).unwrap_or(0);
            let uid = take_value(&mut args, "--uid").and_then(|v| v.parse().ok());
            let gid = take_value(&mut args, "--gid").and_then(|v| v.parse().ok());
            let target = parse_target(&args.first().cloned().ok_or(USAGE)?);
            let req = MountRequest {
                target,
                mount_point: args.get(1).cloned().unwrap_or_default(),
                write,
                hide_dotfiles: !show,
                codepage,
                uid,
                gid,
            };
            if fg {
                return foreground(req);
            }
            if let Response::Mounted(m) = call(&Request::Mount(req))? {
                println!("Mounted at {} ({})", m.mount_point, if m.read_only { "read-only" } else { "read-write" });
                for r in m.ro_reasons.iter().chain(&m.notes) {
                    println!("  {r}");
                }
            }
        }
        "unmount" => {
            call(&Request::Unmount { point: arg(0)? })?;
            println!("Unmounted.");
        }
        "sync" => {
            call(&Request::Sync)?;
        }
        "scrub" => {
            let point = arg(0)?;
            call(&Request::Scrub { point })?;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let Response::Scrub(s) = call(&Request::ScrubProgress)? else { break };
                if !s.running {
                    println!("Scanned {}, {} repaired, {} errors.", human(s.scanned_bytes), s.repaired, s.errors.len());
                    s.errors.iter().for_each(|e| println!("  {e}"));
                    break;
                }
            }
        }
        "snapshot" => {
            let read_only = take_flag(&mut args, "--read-only");
            call(&Request::Snapshot { point: args.first().cloned().ok_or(USAGE)?, name: args.get(1).cloned().ok_or(USAGE)?, read_only })?;
        }
        "subvolume" => {
            call(&Request::CreateSubvolume { point: arg(0)?, name: arg(1)? })?;
        }
        "service" => match arg(0)?.as_str() {
            "install" => crate::service::install()?,
            "uninstall" => crate::service::uninstall()?,
            "run" => crate::service::run()?,
            "debug" => crate::service::run_foreground()?,
            _ => return Err(USAGE.into()),
        },
        _ => return Err(format!("unknown command `{cmd}`\n\n{USAGE}")),
    }
    Ok(())
}
