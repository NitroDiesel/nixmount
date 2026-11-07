//! Directory-index name hashes, as defined by the ext4 on-disk format.

const EOF_HASH: u32 = 0x7fff_ffff;

fn str2hashbuf(msg: &[u8], out: &mut [u32], signed: bool) {
    let num = out.len();
    let mut pad = msg.len() as u32 | ((msg.len() as u32) << 8);
    pad |= pad << 16;
    let mut val = pad;
    let len = msg.len().min(num * 4);
    let mut w = 0;
    for (i, &c) in msg[..len].iter().enumerate() {
        let c = if signed { c as i8 as i32 as u32 } else { c as u32 };
        val = c.wrapping_add(val << 8);
        if i % 4 == 3 {
            out[w] = val;
            w += 1;
            val = pad;
        }
    }
    if w < num {
        out[w] = val;
        w += 1;
    }
    out[w..].fill(pad);
}

fn half_md4(buf: &mut [u32; 4], i: &[u32; 8]) {
    let f = |x: u32, y: u32, z: u32| z ^ (x & (y ^ z));
    let g = |x: u32, y: u32, z: u32| (x & y).wrapping_add((x ^ y) & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let [mut a, mut b, mut c, mut d] = *buf;
    macro_rules! r {
        ($f:ident,$a:ident,$b:ident,$c:ident,$d:ident,$x:expr,$s:expr) => {
            $a = $a.wrapping_add($f($b, $c, $d)).wrapping_add($x).rotate_left($s)
        };
    }
    for k in [0usize, 4] {
        r!(f, a, b, c, d, i[k], 3);
        r!(f, d, a, b, c, i[k + 1], 7);
        r!(f, c, d, a, b, i[k + 2], 11);
        r!(f, b, c, d, a, i[k + 3], 19);
    }
    const K2: u32 = 0x5A82_7999;
    for k in [1usize, 0] {
        r!(g, a, b, c, d, i[k].wrapping_add(K2), 3);
        r!(g, d, a, b, c, i[k + 2].wrapping_add(K2), 5);
        r!(g, c, d, a, b, i[k + 4].wrapping_add(K2), 9);
        r!(g, b, c, d, a, i[k + 6].wrapping_add(K2), 13);
    }
    const K3: u32 = 0x6ED9_EBA1;
    for (p, q, s, t) in [(3, 7, 2, 6), (1, 5, 0, 4)] {
        r!(h, a, b, c, d, i[p].wrapping_add(K3), 3);
        r!(h, d, a, b, c, i[q].wrapping_add(K3), 9);
        r!(h, c, d, a, b, i[s].wrapping_add(K3), 11);
        r!(h, b, c, d, a, i[t].wrapping_add(K3), 15);
    }
    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

fn tea(buf: &mut [u32; 4], i: &[u32; 4]) {
    let (mut b0, mut b1, mut sum) = (buf[0], buf[1], 0u32);
    for _ in 0..16 {
        sum = sum.wrapping_add(0x9E37_79B9);
        b0 = b0.wrapping_add(
            (b1 << 4).wrapping_add(i[0]) ^ b1.wrapping_add(sum) ^ (b1 >> 5).wrapping_add(i[1]),
        );
        b1 = b1.wrapping_add(
            (b0 << 4).wrapping_add(i[2]) ^ b0.wrapping_add(sum) ^ (b0 >> 5).wrapping_add(i[3]),
        );
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

fn legacy(name: &[u8], signed: bool) -> u32 {
    let (mut h0, mut h1) = (0x12a3_fe2du32, 0x37ab_e8f9u32);
    for &c in name {
        let c = if signed { c as i8 as i32 as u32 } else { c as u32 };
        let mut h = h1.wrapping_add(h0 ^ c.wrapping_mul(7_152_373));
        if h & 0x8000_0000 != 0 {
            h = h.wrapping_sub(0x7fff_ffff);
        }
        h1 = h0;
        h0 = h;
    }
    h0 << 1
}

/// Computes the htree hash of `name`. `version` is the on-disk version with the
/// superblock's unsigned-char adjustment already applied (0-2 signed, 3-5 unsigned).
pub fn dx_hash(name: &[u8], version: u8, seed: &[u32; 4]) -> u32 {
    let mut buf = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    if seed.iter().any(|s| *s != 0) {
        buf = *seed;
    }
    let signed = version < 3;
    let hash = match version {
        0 | 3 => legacy(name, signed),
        2 | 5 => {
            // Padding depends on the bytes remaining from each chunk onward.
            for p in (0..name.len()).step_by(16) {
                let mut i = [0u32; 4];
                str2hashbuf(&name[p..], &mut i, signed);
                tea(&mut buf, &i);
            }
            buf[0]
        }
        _ => {
            for p in (0..name.len()).step_by(32) {
                let mut i = [0u32; 8];
                str2hashbuf(&name[p..], &mut i, signed);
                half_md4(&mut buf, &i);
            }
            buf[1]
        }
    };
    let hash = hash & !1;
    if hash == EOF_HASH << 1 {
        (EOF_HASH - 1) << 1
    } else {
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_never_returns_eof_marker_and_clears_low_bit() {
        for v in 0..6 {
            let h = dx_hash(b"some-file-name.txt", v, &[1, 2, 3, 4]);
            assert_eq!(h & 1, 0);
            assert_ne!(h, EOF_HASH << 1);
        }
    }
}
