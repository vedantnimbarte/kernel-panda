//! A text console drawn directly into the linear framebuffer.
//!
//! There is no VGA text buffer to write to. UEFI hands off in graphics mode and
//! 0xB8000 simply is not there, so on-screen text means rasterising glyphs
//! ourselves. The BIOS path is no different: the bootloader sets a graphics mode
//! either way and reports it through `BootInfo`.
//!
//! Beyond Phase 1 this is also the first real exercise of the display hardware,
//! which is what Phase 4's compositor will eventually build on.

use core::fmt;

use bootloader_api::info::{FrameBufferInfo, PixelFormat};

use super::font::{self, GLYPH_HEIGHT, GLYPH_WIDTH};
use crate::sync::{Mutex, Once};

/// Blank pixels between the bottom of one text row and the top of the next.
const LINE_SPACING: usize = 2;
/// Blank border around the text area, so glyphs do not touch the screen edge.
const MARGIN: usize = 8;

const CELL_HEIGHT: usize = GLYPH_HEIGHT + LINE_SPACING;

/// Light grey rather than pure white: easier to read against black for long
/// stretches, and it leaves headroom for a future highlight colour.
const FOREGROUND: Colour = Colour { r: 0xDD, g: 0xDD, b: 0xDD };
const BACKGROUND: Colour = Colour { r: 0x00, g: 0x00, b: 0x00 };

#[derive(Clone, Copy)]
struct Colour {
    r: u8,
    g: u8,
    b: u8,
}

pub struct FrameBufferConsole {
    buffer: &'static mut [u8],
    info: FrameBufferInfo,
    /// Pixel coordinates of the next glyph's top-left corner.
    x: usize,
    y: usize,
}

impl FrameBufferConsole {
    fn new(info: FrameBufferInfo, buffer: &'static mut [u8]) -> Self {
        Self { buffer, info, x: MARGIN, y: MARGIN }
    }

    pub fn clear(&mut self) {
        self.buffer.fill(0);
        self.x = MARGIN;
        self.y = MARGIN;
    }

    fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.x = MARGIN,
            b'\t' => {
                for _ in 0..4 {
                    self.write_byte(b' ');
                }
            }
            _ => {
                if self.x + GLYPH_WIDTH + MARGIN > self.info.width {
                    self.newline();
                }
                self.draw_glyph(byte as char);
                self.x += GLYPH_WIDTH;
            }
        }
    }

    fn newline(&mut self) {
        self.x = MARGIN;
        self.y += CELL_HEIGHT;
        if self.y + GLYPH_HEIGHT + MARGIN > self.info.height {
            self.scroll();
        }
    }

    /// Shift the whole framebuffer up by one text row and blank the strip that
    /// scrolls in at the bottom.
    fn scroll(&mut self) {
        let row_bytes = self.info.stride * self.info.bytes_per_pixel;
        let shift = CELL_HEIGHT * row_bytes;
        // `stride` can exceed `width`, and `byte_len` is authoritative, so clamp
        // rather than trusting height * stride to fit.
        let total = (self.info.height * row_bytes).min(self.buffer.len());

        if shift >= total {
            // Screen too short to hold even one row; nothing meaningful to keep.
            self.clear();
            return;
        }

        self.buffer.copy_within(shift..total, 0);
        self.buffer[total - shift..total].fill(0);
        self.y -= CELL_HEIGHT;
    }

    fn draw_glyph(&mut self, c: char) {
        let bitmap = font::glyph(c);
        for (dy, row) in bitmap.iter().enumerate() {
            for dx in 0..GLYPH_WIDTH {
                // Bit 7 is the leftmost pixel.
                let lit = row & (0x80 >> dx) != 0;
                let colour = if lit { FOREGROUND } else { BACKGROUND };
                self.set_pixel(self.x + dx, self.y + dy, colour);
            }
        }
    }

    fn set_pixel(&mut self, x: usize, y: usize, colour: Colour) {
        if x >= self.info.width || y >= self.info.height {
            return;
        }

        let bpp = self.info.bytes_per_pixel;
        // `stride` is measured in pixels, not bytes, and is not always equal to
        // `width` -- hardware often pads rows out to an alignment boundary.
        let offset = (y * self.info.stride + x) * bpp;
        let Some(pixel) = self.buffer.get_mut(offset..offset + bpp) else {
            return;
        };

        match self.info.pixel_format {
            PixelFormat::Rgb => {
                pixel[0] = colour.r;
                pixel[1] = colour.g;
                pixel[2] = colour.b;
            }
            PixelFormat::Bgr => {
                pixel[0] = colour.b;
                pixel[1] = colour.g;
                pixel[2] = colour.r;
            }
            PixelFormat::U8 => {
                // Rec. 601 luma, in integer arithmetic.
                let luma = (colour.r as u32 * 77 + colour.g as u32 * 150 + colour.b as u32 * 29) >> 8;
                pixel[0] = luma as u8;
            }
            // A format the bootloader could not classify. BGR is overwhelmingly
            // the common case on PC hardware, so guess that rather than showing
            // nothing at all.
            _ => {
                pixel[0] = colour.b;
                pixel[1] = colour.g;
                pixel[2] = colour.r;
            }
        }
    }
}

impl fmt::Write for FrameBufferConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

static CONSOLE: Once<Mutex<FrameBufferConsole>> = Once::new();

/// Adopt the bootloader's framebuffer and clear the screen.
///
/// Ignored if called more than once.
pub fn init(info: FrameBufferInfo, buffer: &'static mut [u8]) {
    CONSOLE.call_once(|| {
        let mut console = FrameBufferConsole::new(info, buffer);
        console.clear();
        Mutex::new(console)
    });
}

/// Whether a framebuffer was handed to us at boot.
pub fn is_available() -> bool {
    CONSOLE.get().is_some()
}

/// How many bytes of the framebuffer are currently non-zero.
///
/// Diagnostic only, and deliberately not cheap. It exists so the test suite can
/// assert that glyph rasterisation actually reached the hardware -- otherwise the
/// only way to know this module works is for a human to look at a screen, which
/// a headless test run cannot do.
pub fn non_zero_byte_count() -> usize {
    match CONSOLE.get() {
        Some(console) => console.lock().buffer.iter().filter(|b| **b != 0).count(),
        None => 0,
    }
}

/// Virtual address of the framebuffer, if one was adopted.
///
/// Lets a test translate it and confirm it falls inside the display
/// controller's PCI base address register -- tying the bootloader's view of the
/// hardware to the kernel's own.
pub fn buffer_address() -> Option<u64> {
    CONSOLE
        .get()
        .map(|console| console.lock().buffer.as_ptr() as u64)
}

/// Bytes the framebuffer spans.
pub fn buffer_len() -> usize {
    CONSOLE.get().map_or(0, |console| console.lock().buffer.len())
}

/// Blank the screen and return the cursor to the top-left.
pub fn clear() {
    if let Some(console) = CONSOLE.get() {
        console.lock().clear();
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    if let Some(console) = CONSOLE.get() {
        let _ = console.lock().write_fmt(args);
    }
}
