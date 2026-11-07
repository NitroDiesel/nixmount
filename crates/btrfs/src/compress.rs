//! Decompression of the three Btrfs codecs. Output is bounded by the size the extent
//! declares, so a hostile stream cannot balloon memory.
use fscore::{FsError, Le, Result};
use std::io::Read;

pub const ZLIB: u8 = 1;
pub const LZO: u8 = 2;
pub const ZSTD: u8 = 3;

fn bad<T>(what: &str) -> Result<T> {
    Err(FsError::Corrupt(format!("{what} stream is invalid")))
}

pub fn decompress(kind: u8, src: &[u8], ram_bytes: usize, sector: usize) -> Result<Vec<u8>> {
    let mut out = match kind {
        ZLIB => match miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(src, ram_bytes) {
            Ok(v) => v,
            // A stream that decodes past the limit still yields the bytes we need.
            Err(e) if e.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput => e.output,
            Err(_) => return bad("zlib"),
        },
        LZO => lzo_extent(src, ram_bytes, sector)?,
        ZSTD => {
            let dec = ruzstd::decoding::StreamingDecoder::new(src);
            let Ok(dec) = dec else { return bad("zstd") };
            let mut v = Vec::with_capacity(ram_bytes);
            if dec.take(ram_bytes as u64).read_to_end(&mut v).is_err() {
                return bad("zstd");
            }
            v
        }
        _ => return Err(FsError::Unsupported(format!("compression type {kind}"))),
    };
    // Compressed data may legitimately end early: the rest of the extent reads as zeroes.
    out.resize(ram_bytes, 0);
    Ok(out)
}

/// Btrfs frames LZO as a total length, then per-sector segments whose length headers
/// never straddle a sector boundary.
fn lzo_extent(src: &[u8], ram: usize, sector: usize) -> Result<Vec<u8>> {
    let total = (src.u32_at(0) as usize).min(src.len());
    let mut out = Vec::with_capacity(ram);
    let mut p = 4;
    while p + 4 <= total && out.len() < ram {
        if sector - p % sector < 4 {
            p = p.div_ceil(sector) * sector;
            continue;
        }
        let n = src.u32_at(p) as usize;
        p += 4;
        let Some(seg) = src.get(p..p + n) else { return bad("lzo") };
        let before = out.len();
        lzo1x(seg, &mut out, ram).map_err(|_| {
            let head: Vec<String> = seg.iter().take(8).map(|b| format!("{b:02x}")).collect();
            FsError::Corrupt(format!(
                "lzo stream is invalid: segment at {p}/{total}, {n} bytes starting {}, decoded {} of {ram} from {before}",
                head.join(""),
                out.len()
            ))
        })?;
        p += n;
    }
    Ok(out)
}

/// LZO1X decoder. Every read and back-reference is bounds-checked.
fn lzo1x(src: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let byte = |i: usize| src.get(i).copied().map(usize::from).ok_or(());
    let run = |ip: &mut usize, base: usize| -> std::result::Result<usize, ()> {
        let mut n = base;
        while byte(*ip)? == 0 {
            n += 255;
            *ip += 1;
            if n > 1 << 24 {
                return Err(());
            }
        }
        n += byte(*ip)?;
        *ip += 1;
        Ok(n)
    };
    let body = |out: &mut Vec<u8>| -> std::result::Result<(), ()> {
        let lit = |ip: &mut usize, n: usize, out: &mut Vec<u8>| -> std::result::Result<(), ()> {
            let s = src.get(*ip..*ip + n).ok_or(())?;
            if out.len() + n > limit {
                return Err(());
            }
            out.extend_from_slice(s);
            *ip += n;
            Ok(())
        };
        let mut ip = 0;
        let mut state = 0usize;
        if byte(0)? > 17 {
            let t = byte(0)? - 17;
            ip = 1;
            lit(&mut ip, t, out)?;
            state = t.min(4);
        }
        loop {
            let t = byte(ip)?;
            ip += 1;
            let (len, dist, next);
            if t >= 64 {
                len = (t >> 5) + 1;
                dist = (byte(ip)? << 3) + ((t >> 2) & 7) + 1;
                ip += 1;
                next = t & 3;
            } else if t >= 32 {
                let n = t & 31;
                len = if n == 0 { run(&mut ip, 31)? } else { n } + 2;
                let w = byte(ip)? | byte(ip + 1)? << 8;
                ip += 2;
                dist = (w >> 2) + 1;
                next = w & 3;
            } else if t >= 16 {
                let n = t & 7;
                len = if n == 0 { run(&mut ip, 7)? } else { n } + 2;
                let w = byte(ip)? | byte(ip + 1)? << 8;
                ip += 2;
                dist = ((t & 8) << 11) + (w >> 2) + 16384;
                if dist == 16384 {
                    return Ok(());
                }
                next = w & 3;
            } else if state == 0 {
                let n = if t == 0 { run(&mut ip, 15)? } else { t } + 3;
                lit(&mut ip, n, out)?;
                state = 4;
                continue;
            } else {
                let far = if state == 4 { 2049 } else { 1 };
                dist = (t >> 2) + (byte(ip)? << 2) + far;
                ip += 1;
                len = if state == 4 { 3 } else { 2 };
                next = t & 3;
            }
            if dist > out.len() || out.len() + len > limit {
                return Err(());
            }
            let from = out.len() - dist;
            for i in 0..len {
                out.push(out[from + i]);
            }
            lit(&mut ip, next, out)?;
            state = next;
        }
    };
    body(out).or_else(|()| bad("lzo"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzo_literal_stream_and_eof() {
        // Literal run of 4 ("abcd"), then the end-of-stream marker.
        let seg = [21u8, b'a', b'b', b'c', b'd', 0x11, 0, 0];
        let mut out = vec![];
        lzo1x(&seg, &mut out, 16).unwrap();
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn lzo_rejects_back_reference_before_start() {
        let seg = [0x40u8, 0xFF];
        assert!(lzo1x(&seg, &mut vec![], 16).is_err());
    }
}
