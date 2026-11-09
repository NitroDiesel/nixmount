//! A small software canvas over a GDI DIB: antialiased shapes are rasterised here and
//! text goes through GDI. No GPU context and no toolkit, which keeps the whole interface
//! at a few megabytes and costs nothing between repaints.
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{RECT, SIZE};
use windows_sys::Win32::Graphics::Gdi::*;

pub type Color = u32;

/// Builds a colour from a 0xRRGGBB value.
pub const fn rgb(v: u32) -> Color {
    v & 0xFF_FFFF
}

fn blend(dst: u32, src: Color, a: u32) -> u32 {
    let mix = |d: u32, s: u32| (d * (255 - a) + s * a) / 255;
    let (dr, dg, db) = ((dst >> 16) & 255, (dst >> 8) & 255, dst & 255);
    let (sr, sg, sb) = ((src >> 16) & 255, (src >> 8) & 255, src & 255);
    mix(dr, sr) << 16 | mix(dg, sg) << 8 | mix(db, sb)
}

#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }
    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.x && y >= self.y && x < self.x + self.w && y < self.y + self.h
    }
    pub fn right(&self) -> i32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }
    pub fn inset(&self, d: i32) -> Rect {
        Rect::new(self.x + d, self.y + d, self.w - 2 * d, self.h - 2 * d)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Font {
    Small,
    Body,
    Strong,
    Title,
    Heading,
    Icon,
    IconLarge,
    IconSmall,
    IconHero,
}

const FONTS: [Font; 9] =
    [Font::Small, Font::Body, Font::Strong, Font::Title, Font::Heading, Font::Icon, Font::IconLarge, Font::IconSmall, Font::IconHero];

pub struct Canvas {
    pub w: i32,
    pub h: i32,
    pub scale: f32,
    dc: HDC,
    bmp: HBITMAP,
    bits: *mut u32,
    fonts: [HFONT; 9],
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

impl Canvas {
    pub fn new(w: i32, h: i32, scale: f32) -> Canvas {
        // SAFETY: a memory DC compatible with the screen.
        let dc = unsafe { CreateCompatibleDC(null_mut()) };
        let mut c = Canvas { w: 0, h: 0, scale, dc, bmp: null_mut(), bits: null_mut(), fonts: [null_mut(); 9] };
        c.make_fonts();
        c.resize(w, h);
        c
    }

    /// Whether a font family is installed. Windows 10 lacks the newer Segoe families, and
    /// GDI's own fallback for a missing icon font draws empty boxes.
    fn has_font(&self, name: &str) -> bool {
        unsafe extern "system" fn found(_: *const LOGFONTW, _: *const TEXTMETRICW, _: u32, flag: isize) -> i32 {
            // SAFETY: `flag` is the bool passed below, alive for the call.
            unsafe { *(flag as *mut bool) = true };
            0
        }
        // SAFETY: an all-zero LOGFONTW is valid before its fields are set.
        let mut lf: LOGFONTW = unsafe { std::mem::zeroed() };
        lf.lfCharSet = DEFAULT_CHARSET;
        for (d, s) in lf.lfFaceName.iter_mut().zip(name.encode_utf16().take(31)) {
            *d = s;
        }
        let mut seen = false;
        // SAFETY: `lf` and `seen` outlive the call.
        unsafe { EnumFontFamiliesExW(self.dc, &lf, Some(found), (&raw mut seen) as isize, 0) };
        seen
    }

    fn make_fonts(&mut self) {
        let family = |wanted: &str, fallback: &str| -> Vec<u16> {
            let name = if self.has_font(wanted) { wanted } else { fallback };
            name.encode_utf16().chain([0]).collect()
        };
        let text = family("Segoe UI Variable Text", "Segoe UI");
        let display = family("Segoe UI Variable Display", "Segoe UI");
        let icons = family("Segoe Fluent Icons", "Segoe MDL2 Assets");
        for (i, f) in FONTS.iter().enumerate() {
            let (px, weight, face) = match f {
                Font::Small => (12.0, 400, &text),
                Font::Body => (14.0, 400, &text),
                Font::Strong => (14.0, 600, &text),
                Font::Heading => (16.0, 600, &display),
                Font::Title => (24.0, 600, &display),
                Font::Icon => (16.0, 400, &icons),
                Font::IconLarge => (20.0, 400, &icons),
                Font::IconSmall => (10.0, 400, &icons),
                Font::IconHero => (40.0, 400, &icons),
            };
            let h = -(px * self.scale).round() as i32;
            // SAFETY: `face` is NUL-terminated; GDI falls back if the family is missing.
            self.fonts[i] = unsafe {
                CreateFontW(h, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, CLEARTYPE_QUALITY as u32, 0, face.as_ptr())
            };
        }
    }

    fn free_fonts(&mut self) {
        for f in self.fonts {
            // SAFETY: fonts were created by this canvas and are not selected at this point.
            unsafe { DeleteObject(f) };
        }
    }

    pub fn set_scale(&mut self, scale: f32) {
        self.free_fonts();
        self.scale = scale;
        self.make_fonts();
    }

    pub fn resize(&mut self, w: i32, h: i32) {
        let (w, h) = (w.max(1), h.max(1));
        if (w, h) == (self.w, self.h) {
            return;
        }
        // SAFETY: an all-zero BITMAPINFO is valid before the header fields are set.
        let mut info: BITMAPINFO = unsafe { std::mem::zeroed() };
        info.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        info.bmiHeader.biWidth = w;
        info.bmiHeader.biHeight = -h;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        let mut bits = null_mut();
        // SAFETY: `info` describes a 32bpp top-down DIB.
        let bmp = unsafe { CreateDIBSection(self.dc, &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0) };
        // SAFETY: the new bitmap replaces the old one in the DC before the old is freed.
        unsafe {
            SelectObject(self.dc, bmp);
            if !self.bmp.is_null() {
                DeleteObject(self.bmp);
            }
            SetBkMode(self.dc, TRANSPARENT as i32);
        }
        self.bmp = bmp;
        self.bits = bits.cast();
        self.w = w;
        self.h = h;
    }

    fn pixels(&mut self) -> &mut [u32] {
        // SAFETY: `bits` points at w*h pixels for the lifetime of the bitmap.
        unsafe { std::slice::from_raw_parts_mut(self.bits, (self.w * self.h) as usize) }
    }

    /// The GDI font behind `f`, for native controls that must match painted text.
    pub fn hfont(&self, f: Font) -> HFONT {
        self.fonts[FONTS.iter().position(|x| *x == f).unwrap_or(1)]
    }

    pub fn px(&self, v: f32) -> i32 {
        (v * self.scale).round() as i32
    }

    pub fn fill(&mut self, r: Rect, c: Color) {
        let (w, h) = (self.w, self.h);
        let (x0, x1) = (r.x.max(0), r.right().min(w));
        let (y0, y1) = (r.y.max(0), r.bottom().min(h));
        if x0 >= x1 {
            return;
        }
        let p = self.pixels();
        for y in y0..y1 {
            p[(y * w + x0) as usize..(y * w + x1) as usize].fill(c);
        }
    }

    /// Fills a rounded rectangle, antialiased by distance to the corner arc.
    pub fn round(&mut self, r: Rect, radius: i32, c: Color) {
        let rad = (radius as f32).min(r.w as f32 / 2.0).min(r.h as f32 / 2.0);
        let (w, h) = (self.w, self.h);
        let n = rad.ceil() as i32;
        let p = self.pixels();
        for y in r.y.max(0)..r.bottom().min(h) {
            let in_cap = y < r.y + n || y >= r.bottom() - n;
            for x in r.x.max(0)..r.right().min(w) {
                let i = (y * w + x) as usize;
                if !in_cap || (x >= r.x + n && x < r.right() - n) {
                    p[i] = c;
                    continue;
                }
                // Distance from this pixel's centre to the corner's arc.
                let cx = if x < r.x + n { r.x as f32 + rad } else { r.right() as f32 - rad };
                let cy = if y < r.y + n { r.y as f32 + rad } else { r.bottom() as f32 - rad };
                let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
                let cov = (rad + 0.5 - (dx * dx + dy * dy).sqrt()).clamp(0.0, 1.0);
                if cov > 0.0 {
                    p[i] = blend(p[i], c, (cov * 255.0) as u32);
                }
            }
        }
    }

    /// A rounded rectangle with a hairline border.
    pub fn card(&mut self, r: Rect, radius: i32, fill: Color, border: Color) {
        let t = self.px(1.0).max(1);
        self.round(r, radius, border);
        self.round(r.inset(t), (radius - t).max(0), fill);
    }

    /// An antialiased outline following a rounded rectangle's edge, drawn inside `r`.
    pub fn ring(&mut self, r: Rect, radius: i32, width: i32, c: Color) {
        let (w, h) = (self.w, self.h);
        let (hw, hh) = (r.w as f32 / 2.0, r.h as f32 / 2.0);
        let (cx, cy) = (r.x as f32 + hw, r.y as f32 + hh);
        let rad = (radius as f32).min(hw).min(hh);
        let t = width as f32;
        let p = self.pixels();
        for y in r.y.max(0)..r.bottom().min(h) {
            for x in r.x.max(0)..r.right().min(w) {
                // Signed distance to the edge: negative inside.
                let qx = (x as f32 + 0.5 - cx).abs() - hw + rad;
                let qy = (y as f32 + 0.5 - cy).abs() - hh + rad;
                let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
                let d = outside + qx.max(qy).min(0.0) - rad;
                let cov = (0.5 - d).clamp(0.0, 1.0) * (0.5 + d + t).clamp(0.0, 1.0);
                if cov > 0.0 {
                    let i = (y * w + x) as usize;
                    p[i] = blend(p[i], c, (cov * 255.0) as u32);
                }
            }
        }
    }

    pub fn circle(&mut self, cx: i32, cy: i32, radius: i32, c: Color) {
        self.round(Rect::new(cx - radius, cy - radius, radius * 2, radius * 2), radius, c);
    }

    fn select(&self, f: Font, c: Color) {
        let i = FONTS.iter().position(|x| *x == f).unwrap_or(1);
        let bgr = ((c & 0xFF) << 16) | (c & 0xFF00) | ((c >> 16) & 0xFF);
        // SAFETY: the DC and font are live.
        unsafe {
            SelectObject(self.dc, self.fonts[i]);
            SetTextColor(self.dc, bgr);
        }
    }

    pub fn measure(&self, s: &str, f: Font) -> (i32, i32) {
        self.select(f, 0);
        let t = wide(s);
        let mut sz = SIZE { cx: 0, cy: 0 };
        // SAFETY: `t` is valid for its length.
        unsafe { GetTextExtentPoint32W(self.dc, t.as_ptr(), t.len() as i32, &mut sz) };
        (sz.cx, sz.cy)
    }

    /// Single-line text in `r`, vertically centred and truncated with an ellipsis.
    pub fn text(&mut self, r: Rect, s: &str, f: Font, c: Color, center: bool) {
        // DrawTextW reads through the pointer even for a zero length, and an empty Vec's
        // pointer is dangling.
        if s.is_empty() {
            return;
        }
        self.select(f, c);
        let mut t = wide(s);
        let mut rc = RECT { left: r.x, top: r.y, right: r.right(), bottom: r.bottom() };
        let align = if center { DT_CENTER } else { DT_LEFT };
        let flags = DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS | align;
        // SAFETY: `t` is valid and DrawTextW only reads it without DT_MODIFYSTRING.
        unsafe { DrawTextW(self.dc, t.as_mut_ptr(), t.len() as i32, &mut rc, flags) };
    }

    /// Single-line text aligned to the right edge of `r`, so numbers line up in a column.
    pub fn text_right(&mut self, r: Rect, s: &str, f: Font, c: Color) {
        if s.is_empty() {
            return;
        }
        self.select(f, c);
        let mut t = wide(s);
        let mut rc = RECT { left: r.x, top: r.y, right: r.right(), bottom: r.bottom() };
        let flags = DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_RIGHT;
        // SAFETY: `t` is valid and DrawTextW only reads it without DT_MODIFYSTRING.
        unsafe { DrawTextW(self.dc, t.as_mut_ptr(), t.len() as i32, &mut rc, flags) };
    }

    /// Height `s` takes when wrapped to `width`, without drawing it.
    pub fn wrapped_height(&self, s: &str, f: Font, width: i32) -> i32 {
        if s.is_empty() {
            return 0;
        }
        self.select(f, 0);
        let mut t = wide(s);
        let mut rc = RECT { left: 0, top: 0, right: width, bottom: 0 };
        // SAFETY: as in `text`; DT_CALCRECT only measures.
        unsafe { DrawTextW(self.dc, t.as_mut_ptr(), t.len() as i32, &mut rc, DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT) }
    }

    /// Word-wrapped text from the top of `r`. Returns the height used.
    pub fn paragraph(&mut self, r: Rect, s: &str, f: Font, c: Color) -> i32 {
        if s.is_empty() {
            return 0;
        }
        self.select(f, c);
        let mut t = wide(s);
        let mut rc = RECT { left: r.x, top: r.y, right: r.right(), bottom: r.bottom() };
        // SAFETY: as in `text`; the first call only measures.
        unsafe {
            let h = DrawTextW(self.dc, t.as_mut_ptr(), t.len() as i32, &mut rc, DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
            rc = RECT { left: r.x, top: r.y, right: r.right(), bottom: r.y + h };
            DrawTextW(self.dc, t.as_mut_ptr(), t.len() as i32, &mut rc, DT_WORDBREAK | DT_NOPREFIX);
            h
        }
    }

    pub fn present(&self, target: HDC) {
        // SAFETY: both DCs are live and the source holds a w*h bitmap.
        unsafe { BitBlt(target, 0, 0, self.w, self.h, self.dc, 0, 0, SRCCOPY) };
    }

    /// Writes the canvas as a BMP, for checking the design without a screen.
    pub fn save_bmp(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let (w, h) = (self.w as u32, self.h as u32);
        let size = 54 + w * h * 4;
        let mut b = Vec::with_capacity(size as usize);
        b.extend_from_slice(b"BM");
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&54u32.to_le_bytes());
        b.extend_from_slice(&40u32.to_le_bytes());
        b.extend_from_slice(&w.to_le_bytes());
        b.extend_from_slice(&(-(h as i32)).to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&32u16.to_le_bytes());
        b.extend_from_slice(&[0; 24]);
        for p in self.pixels() {
            b.extend_from_slice(&(*p | 0xFF00_0000).to_le_bytes());
        }
        std::fs::write(path, b)
    }
}

impl Drop for Canvas {
    fn drop(&mut self) {
        self.free_fonts();
        // SAFETY: objects are owned by this canvas.
        unsafe {
            DeleteObject(self.bmp);
            DeleteDC(self.dc);
        }
    }
}
