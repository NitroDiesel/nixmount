//! Lossless translation between Linux byte names and Windows UTF-16 names.
//!
//! Linux allows `:` `*` `?` and trailing dots, which Windows would misparse (`a:b` opens
//! a stream). Such characters move to the private-use range U+F000+c, the convention
//! Cygwin and WSL also use, and invalid UTF-8 bytes to U+F700+byte, so every name
//! survives a round trip and none can smuggle in path syntax.
use std::path::Component;

const CHAR_BASE: u32 = 0xF000;
const BYTE_BASE: u32 = 0xF700;

/// `/` can't appear in a real Linux name, but a crafted disk can hold one, and Windows
/// reads it as a path separator.
fn unsafe_on_windows(c: char) -> bool {
    (c as u32) < 0x20 || matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
}

/// Turns a name from a volume into one path component for a real Windows folder, or None
/// if it can only refer to somewhere else. This is the boundary that keeps a hostile
/// volume's names from escaping an export destination.
pub fn host_component(name: &[u8]) -> Option<String> {
    if name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    let mut wide = to_wide(name, 0);
    let text = String::from_utf16_lossy(&wide).to_uppercase();
    let stem = text.split('.').next().unwrap_or("");
    let numbered = stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit();
    // Windows reserves device names, even with an extension.
    if matches!(stem, "CON" | "PRN" | "AUX" | "NUL") || numbered {
        wide[0] = (CHAR_BASE + wide[0] as u32) as u16;
    }
    Some(String::from_utf16_lossy(&wide))
}

/// Linux name to Windows name.
pub fn to_wide(name: &[u8], codepage: u32) -> Vec<u16> {
    if codepage != 0 {
        return decode_codepage(name, codepage);
    }
    let mut out = Vec::with_capacity(name.len());
    let mut buf = [0u16; 2];
    for chunk in name.utf8_chunks() {
        let valid = chunk.valid();
        for (i, c) in valid.char_indices() {
            let last = i + c.len_utf8() == valid.len() && chunk.invalid().is_empty();
            let end_of_name = last && std::ptr::eq(valid.as_bytes().as_ptr_range().end, name.as_ptr_range().end);
            if unsafe_on_windows(c) || (end_of_name && matches!(c, '.' | ' ') && name != b"." && name != b"..") {
                out.push((CHAR_BASE + c as u32) as u16);
            } else {
                out.extend_from_slice(c.encode_utf16(&mut buf));
            }
        }
        out.extend(chunk.invalid().iter().map(|b| (BYTE_BASE + *b as u32) as u16));
    }
    out
}

/// Windows name to Linux name. Returns None for names that aren't valid UTF-16.
pub fn from_wide(name: &[u16], codepage: u32) -> Option<Vec<u8>> {
    if codepage != 0 {
        return encode_codepage(name, codepage);
    }
    let mut out = Vec::with_capacity(name.len());
    let mut utf8 = [0u8; 4];
    for c in char::decode_utf16(name.iter().copied()) {
        let c = c.ok()?;
        let v = c as u32;
        if (BYTE_BASE..BYTE_BASE + 0x100).contains(&v) {
            out.push((v - BYTE_BASE) as u8);
        } else if (CHAR_BASE..CHAR_BASE + 0x80).contains(&v) {
            out.push((v - CHAR_BASE) as u8);
        } else {
            out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
        }
    }
    Some(out)
}

/// Rewrites a symlink target to a relative Windows path that stays inside the volume.
///
/// `dir` is the components of the directory holding the link. Absolute targets are
/// taken from the volume root and `..` stops at it, as a chroot would, so a link can
/// never point outside the mounted volume.
pub fn safe_link_target(dir: &[Vec<u8>], target: &[u8], codepage: u32) -> Vec<u16> {
    let mut stack: Vec<Vec<u8>> = if target.first() == Some(&b'/') { vec![] } else { dir.to_vec() };
    for part in target.split(|b| *b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                stack.pop();
            }
            p => stack.push(p.to_vec()),
        }
    }
    let common = dir.iter().zip(&stack).take_while(|(a, b)| a == b).count();
    let mut out: Vec<u16> = vec![];
    let sep = u16::from(b'\\');
    for _ in common..dir.len() {
        out.extend_from_slice(&[b'.' as u16, b'.' as u16, sep]);
    }
    for (i, p) in stack[common..].iter().enumerate() {
        if i > 0 {
            out.push(sep);
        }
        out.extend(to_wide(p, codepage));
    }
    if out.last() == Some(&sep) {
        out.pop();
    }
    if out.is_empty() {
        out.push(b'.' as u16);
    }
    out
}

/// Turns a Windows symlink target into a Linux one. Absolute paths aren't representable
/// on a volume that moves between machines, so they are refused.
pub fn link_from_windows(target: &[u16], codepage: u32) -> Option<Vec<u8>> {
    let text = String::from_utf16(target).ok()?;
    let path = std::path::Path::new(&text);
    if path.is_absolute() || matches!(path.components().next(), Some(Component::Prefix(_) | Component::RootDir)) {
        return None;
    }
    let mut parts: Vec<Vec<u8>> = vec![];
    for part in target.split(|c| *c == u16::from(b'\\') || *c == u16::from(b'/')) {
        if !part.is_empty() {
            parts.push(from_wide(part, codepage)?);
        }
    }
    Some(parts.join(&b'/'))
}

#[cfg(windows)]
fn decode_codepage(name: &[u8], cp: u32) -> Vec<u16> {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;
    let mut out = vec![0u16; name.len() * 2 + 2];
    // SAFETY: both buffers are valid for the lengths passed.
    let n = unsafe { MultiByteToWideChar(cp, 0, name.as_ptr(), name.len() as i32, out.as_mut_ptr(), out.len() as i32) };
    out.truncate(n.max(0) as usize);
    out
}

#[cfg(windows)]
fn encode_codepage(name: &[u16], cp: u32) -> Option<Vec<u8>> {
    use windows_sys::Win32::Globalization::WideCharToMultiByte;
    let mut out = vec![0u8; name.len() * 4 + 4];
    // SAFETY: both buffers are valid for the lengths passed.
    let n = unsafe {
        WideCharToMultiByte(cp, 0, name.as_ptr(), name.len() as i32, out.as_mut_ptr(), out.len() as i32, std::ptr::null(), std::ptr::null_mut())
    };
    if n <= 0 && !name.is_empty() {
        return None;
    }
    out.truncate(n.max(0) as usize);
    Some(out)
}

#[cfg(not(windows))]
fn decode_codepage(name: &[u8], _: u32) -> Vec<u16> {
    String::from_utf8_lossy(name).encode_utf16().collect()
}

#[cfg(not(windows))]
fn encode_codepage(name: &[u16], _: u32) -> Option<Vec<u8>> {
    String::from_utf16(name).ok().map(String::into_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(n: &[u8]) {
        assert_eq!(from_wide(&to_wide(n, 0), 0).as_deref(), Some(n), "{n:?}");
    }

    #[test]
    fn names_round_trip() {
        for n in [
            &b"plain.txt"[..],
            b"has:colon",
            b"star*q?",
            b"trailing.",
            b"trailing ",
            b"tab\there",
            "ünï-çödé".as_bytes(),
            b"bad\xFF\xFEutf8",
            b".hidden",
            b"..double",
        ] {
            round(n);
        }
    }

    #[test]
    fn colon_cannot_address_a_stream() {
        assert!(!to_wide(b"a:b", 0).contains(&u16::from(b':')));
    }

    #[test]
    fn hostile_names_cannot_leave_an_export_folder() {
        for bad in [&b"."[..], b"..", b""] {
            assert_eq!(host_component(bad), None);
        }
        for tricky in [&b"..\\..\\evil"[..], b"../../evil", b"a/b", b"C:\\x", b"NUL", b"con.txt", b"COM1", b"lpt9.log"] {
            let safe = host_component(tricky).unwrap();
            let path = std::path::Path::new(r"D:\dest").join(&safe);
            assert_eq!(path.parent(), Some(std::path::Path::new(r"D:\dest")), "{safe}");
            assert!(!safe.contains(['/', '\\', ':']), "{safe}");
            assert!(!matches!(safe.to_uppercase().split('.').next(), Some("NUL" | "CON" | "COM1" | "LPT9")));
        }
        assert_eq!(host_component(b"console.txt").as_deref(), Some("console.txt"));
    }

    #[test]
    fn links_cannot_escape_the_volume() {
        let dir = vec![b"home".to_vec(), b"me".to_vec()];
        let wide = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(safe_link_target(&dir, b"../../../../../etc/passwd", 0), wide("..\\..\\etc\\passwd"));
        assert_eq!(safe_link_target(&dir, b"/etc/passwd", 0), wide("..\\..\\etc\\passwd"));
        assert_eq!(safe_link_target(&dir, b"docs/a.txt", 0), wide("docs\\a.txt"));
        assert_eq!(safe_link_target(&dir, b"C:\\Windows", 0), to_wide(b"C:\\Windows", 0));
        assert_eq!(safe_link_target(&[], b"..", 0), wide("."));
    }

    #[test]
    fn absolute_windows_links_are_refused() {
        let wide = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(link_from_windows(&wide("C:\\Windows"), 0), None);
        assert_eq!(link_from_windows(&wide("..\\a\\b"), 0), Some(b"../a/b".to_vec()));
    }
}
