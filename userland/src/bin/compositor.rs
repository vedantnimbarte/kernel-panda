//! The Sovereign compositor.
//!
//! Owns the screen and nothing else. The display reaches it as a shared buffer
//! handle and what to draw reaches it as a message; it never touches hardware.
//!
//! Three things distinguish this from a blitter:
//!
//! * **Z-order.** Surfaces are kept in a table and composed back to front, so
//!   what ends up on top is decided by the surface's depth rather than by which
//!   client happened to send its message last.
//! * **Damage.** Only the tiles of the screen that actually changed are
//!   recomposed and copied out. A client updating a corner of the screen should
//!   not cost a full-screen redraw, and at 1024x768x3 a full redraw is over two
//!   megabytes.
//! * **Double buffering.** Composition happens in an off-screen buffer and
//!   reaches the display in a single copy. Drawing surfaces straight into the
//!   scanout means the display controller can read the screen halfway through
//!   -- with overlapping surfaces that is a visible flicker of whatever was
//!   underneath.
//!
//! It also owns the pointer. A cursor is drawn over everything, a click raises
//! and focuses the surface under it, and key events go to the focused client
//! and nobody else. Key and pointer events are believed only from the input
//! daemon the kernel named, or from the kernel itself: every client holds
//! `SEND` on this endpoint, and one that could post key events could type into
//! another client's window.

#![no_std]
#![no_main]

use panda_user::{self as user, input};

user::entry!(main);

const TAG_PRESENT: u64 = 2;

/// Surfaces the compositor will track at once. Fixed, because there is no
/// allocator here and a display server that can be made to allocate without
/// limit by a client is a display server that can be made to die.
const MAX_SURFACES: usize = 16;

#[derive(Clone, Copy)]
struct Surface {
    /// Buffer handle, or zero for an empty slot.
    buffer: u64,
    /// Where the client's pixels are mapped in this process.
    base: u64,
    x: u64,
    y: u64,
    width: u64,
    height: u64,
    stride: u64,
    /// Higher is nearer the viewer.
    z: u64,
    /// The thread that presented it, as the kernel stamped it.
    owner: u64,
}

impl Surface {
    const EMPTY: Surface = Surface {
        buffer: 0,
        base: 0,
        x: 0,
        y: 0,
        width: 0,
        height: 0,
        stride: 0,
        z: 0,
        owner: 0,
    };
}

/// The pointer, 11 by 16. `X` is outline, `#` is fill, anything else shows
/// what is underneath.
const CURSOR: [&[u8; 11]; 16] = [
    b"X..........",
    b"XX.........",
    b"X#X........",
    b"X##X.......",
    b"X###X......",
    b"X####X.....",
    b"X#####X....",
    b"X######X...",
    b"X#######X..",
    b"X########X.",
    b"X#####XXXXX",
    b"X##X##X....",
    b"X#X.X##X...",
    b"XX..X##X...",
    b"X....X##X..",
    b".....XXXX..",
];
const CURSOR_WIDTH: u64 = 11;
const CURSOR_HEIGHT: u64 = 16;

/// A half-open rectangle. `right <= left` means empty.
#[derive(Clone, Copy)]
struct Rect {
    left: u64,
    top: u64,
    right: u64,
    bottom: u64,
}

impl Rect {
    fn is_empty(&self) -> bool {
        self.right <= self.left || self.bottom <= self.top
    }

    fn intersect(self, other: Rect) -> Rect {
        Rect {
            left: self.left.max(other.left),
            top: self.top.max(other.top),
            right: self.right.min(other.right),
            bottom: self.bottom.min(other.bottom),
        }
    }
}

/// Damage, as a grid of screen tiles.
///
/// A single accumulated rectangle is wrong in a specific way: a surface that
/// moves across the screen damages where it was and where it went, and one
/// rectangle covering both recomposes everything in between. A list of
/// rectangles fixes that until it fills, and then has to merge -- so a workload
/// of many small scattered updates, a cursor over a busy screen, degraded back
/// toward the bounding box.
///
/// A bitmap cannot fill. Damage is rounded out to whole tiles, which costs at
/// most a tile's width of recomposition at each edge, and any number of
/// scattered updates costs exactly the tiles they touch. Fixed size, because
/// there is no allocator here: one 128-bit row per tile row.
const TILE_COLUMNS: u64 = 128;
const TILE_ROWS: usize = 80;

struct Damage {
    rows: [u128; TILE_ROWS],
    /// Tile edge in pixels. 32, or larger on a screen too big for the grid.
    tile: u64,
}

impl Damage {
    fn new(width: u64, height: u64) -> Self {
        let tile = 32
            .max(width.div_ceil(TILE_COLUMNS))
            .max(height.div_ceil(TILE_ROWS as u64));
        Self {
            rows: [0; TILE_ROWS],
            tile,
        }
    }

    fn is_empty(&self) -> bool {
        self.rows.iter().all(|row| *row == 0)
    }

    fn add(&mut self, area: Rect) {
        if area.is_empty() {
            return;
        }
        let last_column = TILE_COLUMNS - 1;
        let first = (area.left / self.tile).min(last_column);
        let last = ((area.right - 1) / self.tile).min(last_column);
        // Bits `first..=last`, built without shifting a u128 by 128.
        let span = (u128::MAX >> (last_column - (last - first))) << first;

        let top = (area.top / self.tile) as usize;
        let bottom = ((area.bottom - 1) / self.tile) as usize;
        for row in top.min(TILE_ROWS - 1)..=bottom.min(TILE_ROWS - 1) {
            self.rows[row] |= span;
        }
    }

    /// Clear the grid, handing each horizontal run of damaged tiles to `each`
    /// as one rectangle. Adjacent tiles in a row are composed together rather
    /// than one at a time.
    fn drain(&mut self, mut each: impl FnMut(Rect)) {
        let rows = core::mem::replace(&mut self.rows, [0; TILE_ROWS]);
        for (row, mut remaining) in rows.into_iter().enumerate() {
            while remaining != 0 {
                let start = remaining.trailing_zeros() as u64;
                let length = (remaining >> start).trailing_ones() as u64;
                each(Rect {
                    left: start * self.tile,
                    top: row as u64 * self.tile,
                    right: (start + length) * self.tile,
                    bottom: (row as u64 + 1) * self.tile,
                });
                remaining &= !((u128::MAX >> (TILE_COLUMNS - length)) << start);
            }
        }
    }
}

struct Compositor {
    scanout_base: u64,
    /// Where composition happens. Copied to the scanout once per frame.
    back_base: u64,
    screen: user::BufferInfo,
    surfaces: [Surface; MAX_SURFACES],
    damage: Damage,
    /// Tip of the pointer.
    cursor_x: u64,
    cursor_y: u64,
    /// Hidden until the first pointer event: a machine with no mouse should not
    /// have an arrow parked in the middle of the screen.
    cursor_visible: bool,
    buttons: u64,
    /// The thread whose key and pointer events are believed, besides the kernel.
    input_source: Option<u64>,
    /// The thread whose surface was last clicked.
    focus: Option<u64>,
    /// `(thread, endpoint)`: where a client wants its key events.
    listeners: [(u64, u64); MAX_SURFACES],
}

impl Compositor {
    fn depth(&self) -> u64 {
        self.screen.bytes_per_pixel as u64
    }

    fn screen_rect(&self) -> Rect {
        Rect {
            left: 0,
            top: 0,
            right: self.screen.width as u64,
            bottom: self.screen.height as u64,
        }
    }

    /// Record a surface, replacing any earlier one with the same handle.
    ///
    /// Both the old and the new position are damaged: moving a surface leaves a
    /// hole where it was, and redrawing only the destination would let the old
    /// image sit there for as long as nothing else touched it.
    fn track(&mut self, surface: Surface) {
        let mut slot = None;
        for (index, existing) in self.surfaces.iter().enumerate() {
            if existing.buffer == surface.buffer {
                slot = Some(index);
                break;
            }
            if existing.buffer == 0 && slot.is_none() {
                slot = Some(index);
            }
        }

        let Some(index) = slot else {
            // Full. Refusing is the honest answer: silently dropping the oldest
            // would make the screen depend on arrival order in a way no client
            // can see or predict.
            user::write("  [compositor] surface table full\n");
            return;
        };

        let previous = self.surfaces[index];
        if previous.buffer != 0 {
            self.damage.add(bounds_of(&previous));
        }
        self.damage.add(bounds_of(&surface));
        self.surfaces[index] = surface;
    }

    /// Recompose every damaged region and put them on the screen.
    fn compose(&mut self) {
        if self.damage.is_empty() {
            return;
        }

        let screen = self.screen_rect();
        let mut order = [0usize; MAX_SURFACES];
        let count = self.sorted_by_depth(&mut order);

        // Drained into a local first: composing borrows `self` for the blits.
        let mut damage = core::mem::replace(&mut self.damage, Damage::new(0, 0));
        damage.drain(|region| {
            let area = region.intersect(screen);
            if area.is_empty() {
                return;
            }

            // Clear first, so a surface that shrank or moved does not leave its
            // old pixels behind.
            self.clear(area);

            // Back to front. Composing in z order is the whole point: the
            // surface nearest the viewer must be drawn last whatever order the
            // messages arrived in.
            for &index in order.iter().take(count) {
                let surface = self.surfaces[index];
                self.blit(&surface, area);
            }
            self.draw_cursor(area);

            self.flush(area);
        });
        self.damage = damage;
    }

    fn cursor_rect(&self) -> Rect {
        Rect {
            left: self.cursor_x,
            top: self.cursor_y,
            right: self.cursor_x + CURSOR_WIDTH,
            bottom: self.cursor_y + CURSOR_HEIGHT,
        }
    }

    /// Move the pointer, and act on a left button that has just gone down.
    fn pointer(&mut self, dx: i64, dy: i64, buttons: u64) {
        if self.cursor_visible {
            self.damage.add(self.cursor_rect());
        }
        let screen = self.screen_rect();
        self.cursor_x = (self.cursor_x as i64 + dx).clamp(0, screen.right as i64 - 1) as u64;
        self.cursor_y = (self.cursor_y as i64 + dy).clamp(0, screen.bottom as i64 - 1) as u64;
        self.cursor_visible = true;
        self.damage.add(self.cursor_rect());

        let pressed = buttons & !self.buttons;
        self.buttons = buttons;
        if pressed & 1 != 0 {
            self.raise_at(self.cursor_x, self.cursor_y);
        }
    }

    /// Bring the topmost surface under a point to the front and give its owner
    /// the keyboard. A click on nothing takes the keyboard away from everyone.
    fn raise_at(&mut self, x: u64, y: u64) {
        let mut order = [0usize; MAX_SURFACES];
        let count = self.sorted_by_depth(&mut order);

        let hit = order[..count].iter().rev().copied().find(|&index| {
            let bounds = bounds_of(&self.surfaces[index]);
            (bounds.left..bounds.right).contains(&x) && (bounds.top..bounds.bottom).contains(&y)
        });
        let Some(index) = hit else {
            self.focus = None;
            return;
        };

        let top = order[count - 1];
        if top != index {
            self.surfaces[index].z = self.surfaces[top].z + 1;
            self.damage.add(bounds_of(&self.surfaces[index]));
        }
        self.focus = Some(self.surfaces[index].owner);
    }

    /// Hand a key event to whoever has focus, if they asked for keys.
    fn key(&self, words: [u64; 4]) {
        let Some(focus) = self.focus else {
            return;
        };
        let Some(&(_, endpoint)) = self
            .listeners
            .iter()
            .find(|(owner, endpoint)| *owner == focus && *endpoint != 0)
        else {
            return;
        };
        let message = user::Message {
            tag: input::TAG_KEY,
            words,
            sender: 0,
        };
        // A client that stopped listening loses the key, not the compositor.
        user::ipc_send(endpoint, &message);
    }

    /// Record where `owner` wants its keys, replacing any earlier choice.
    fn listen(&mut self, owner: u64, endpoint: u64) {
        let slot = self
            .listeners
            .iter()
            .position(|(existing, _)| *existing == owner)
            .or_else(|| self.listeners.iter().position(|(_, endpoint)| *endpoint == 0));
        match slot {
            Some(index) => self.listeners[index] = (owner, endpoint),
            None => {
                user::write("  [compositor] listener table full\n");
            }
        }
    }

    fn draw_cursor(&self, area: Rect) {
        if !self.cursor_visible {
            return;
        }
        let visible = self.cursor_rect().intersect(area);
        let depth = self.depth();
        let stride = self.screen.stride as u64;

        for y in visible.top..visible.bottom {
            for x in visible.left..visible.right {
                let value = match CURSOR[(y - self.cursor_y) as usize][(x - self.cursor_x) as usize] {
                    b'X' => 0x00,
                    b'#' => 0xFF,
                    _ => continue,
                };
                let pixel = self.back_base + y * stride + x * depth;
                // SAFETY: `visible` is inside `area`, which the caller clipped
                // to the screen, and the back buffer is the screen's size.
                unsafe { core::ptr::write_bytes(pixel as *mut u8, value, depth as usize) };
            }
        }
    }

    /// Indices of the live surfaces, lowest z first.
    ///
    /// Insertion sort over a fixed array. With sixteen slots, anything cleverer
    /// would be longer than the thing it replaced.
    fn sorted_by_depth(&self, order: &mut [usize; MAX_SURFACES]) -> usize {
        let mut count = 0;
        for index in 0..MAX_SURFACES {
            if self.surfaces[index].buffer == 0 {
                continue;
            }

            let mut position = count;
            while position > 0 && self.surfaces[order[position - 1]].z > self.surfaces[index].z {
                order[position] = order[position - 1];
                position -= 1;
            }
            order[position] = index;
            count += 1;
        }
        count
    }

    fn clear(&self, area: Rect) {
        let depth = self.depth();
        let stride = self.screen.stride as u64;
        for row in area.top..area.bottom {
            let start = self.back_base + row * stride + area.left * depth;
            let width = (area.right - area.left) * depth;
            // SAFETY: the row lies inside the back buffer -- `area` was
            // intersected with the screen rectangle, and the back buffer is the
            // same dimensions as the screen.
            unsafe { core::ptr::write_bytes(start as *mut u8, 0, width as usize) };
        }
    }

    /// Draw the part of `surface` that falls inside `area` into the back buffer.
    fn blit(&self, surface: &Surface, area: Rect) {
        let visible = bounds_of(surface).intersect(area);
        if visible.is_empty() {
            return;
        }

        let depth = self.depth();
        let screen_stride = self.screen.stride as u64;
        let width = (visible.right - visible.left) * depth;

        for row in visible.top..visible.bottom {
            let source =
                surface.base + (row - surface.y) * surface.stride + (visible.left - surface.x) * depth;
            let destination = self.back_base + row * screen_stride + visible.left * depth;

            // SAFETY: `visible` is the surface's own bounds intersected with a
            // rectangle already clipped to the screen, so the source lies
            // inside the client's buffer and the destination inside the back
            // buffer. Both are mapped by this process.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    source as *const u8,
                    destination as *mut u8,
                    width as usize,
                );
            }
        }
    }

    /// Copy the composed region to the display, one whole pixel per write.
    ///
    /// The display reads its memory whenever it likes, so a pixel written a
    /// byte at a time can be latched half old and half new -- and a row `memcpy`
    /// copies in eight-byte strides, which split three-byte pixels. So every
    /// pixel goes out as a single four-byte store.
    ///
    /// At three bytes a pixel, the fourth byte of that store belongs to the next
    /// pixel, and it carries the value *already on the display* rather than the
    /// back buffer's. Inside the damaged area the next store overwrites it
    /// anyway; outside it the two buffers need not agree, and writing the back
    /// buffer's byte would change a pixel nobody asked to change. The very last
    /// pixel of the display has no byte after it, so its store ends at the pixel
    /// and carries the byte before instead.
    fn flush(&self, area: Rect) {
        let depth = self.depth();
        let stride = self.screen.stride as u64;
        let end = self.screen.size;

        for row in area.top..area.bottom {
            for x in area.left..area.right {
                let offset = row * stride + x * depth;
                let back = (self.back_base + offset) as *const u8;
                let screen = self.scanout_base + offset;

                // SAFETY: `area` is clipped to the screen, both buffers are the
                // screen's dimensions, and every read and write below stays
                // inside `0..end` of the display -- the last-pixel case is what
                // keeps the four-byte store from running off it.
                unsafe {
                    if depth != 3 {
                        core::ptr::copy_nonoverlapping(back, screen as *mut u8, depth as usize);
                        continue;
                    }
                    let pixel = u32::from_le_bytes([*back, *back.add(1), *back.add(2), 0]);
                    if offset + 4 <= end {
                        let after = core::ptr::read_unaligned(screen as *const u32) & 0xFF00_0000;
                        core::ptr::write_unaligned(screen as *mut u32, pixel | after);
                    } else {
                        let before = core::ptr::read_unaligned((screen - 1) as *const u32) & 0xFF;
                        core::ptr::write_unaligned((screen - 1) as *mut u32, pixel << 8 | before);
                    }
                }
            }
        }
    }
}

fn bounds_of(surface: &Surface) -> Rect {
    Rect {
        left: surface.x,
        top: surface.y,
        right: surface.x + surface.width,
        bottom: surface.y + surface.height,
    }
}

extern "C" fn main(endpoint: u64) {
    let scanout = user::scanout();
    if scanout < 0 {
        user::write("  [compositor] refused the scanout buffer\n");
        user::exit(1);
    }
    let scanout = scanout as u64;

    let scanout_base = user::buffer_map(scanout);
    if scanout_base < 0 {
        user::write("  [compositor] could not map the screen\n");
        user::exit(1);
    }

    let mut screen = user::BufferInfo::default();
    if user::buffer_info(scanout, &mut screen) < 0 {
        user::write("  [compositor] could not measure the screen\n");
        user::exit(1);
    }

    // The back buffer is the compositor's own, the same size as the display.
    let back = user::buffer_create(screen.width as u64, screen.height as u64);
    if back < 0 {
        user::write("  [compositor] could not allocate a back buffer\n");
        user::exit(1);
    }
    let back_base = user::buffer_map(back as u64);
    if back_base < 0 {
        user::write("  [compositor] could not map the back buffer\n");
        user::exit(1);
    }

    let mut compositor = Compositor {
        scanout_base: scanout_base as u64,
        back_base: back_base as u64,
        screen,
        surfaces: [Surface::EMPTY; MAX_SURFACES],
        damage: Damage::new(screen.width as u64, screen.height as u64),
        cursor_x: screen.width as u64 / 2,
        cursor_y: screen.height as u64 / 2,
        cursor_visible: false,
        buttons: 0,
        input_source: None,
        focus: None,
        listeners: [(0, 0); MAX_SURFACES],
    };

    loop {
        let mut message = user::Message::default();
        if user::ipc_receive(endpoint, &mut message) < 0 {
            user::exit(1);
        }

        let from_kernel = message.sender == user::KERNEL_SENDER;
        let from_input = from_kernel || compositor.input_source == Some(message.sender);

        match message.tag {
            input::TAG_INPUT_SOURCE if from_kernel => {
                compositor.input_source = Some(message.words[0]);
            }
            input::TAG_SHUTDOWN if from_input => user::exit(0),
            input::TAG_POINTER if from_input => {
                compositor.pointer(
                    message.words[0] as i64,
                    message.words[1] as i64,
                    message.words[2],
                );
                compositor.compose();
            }
            input::TAG_KEY if from_input => compositor.key(message.words),
            input::TAG_LISTEN => compositor.listen(message.sender, message.words[0]),
            TAG_PRESENT => {
                let [buffer, x, y, z] = message.words;
                if let Some(surface) = adopt(buffer, x, y, z, message.sender) {
                    compositor.track(surface);
                    compositor.compose();
                }
            }
            // Anything else, including input from someone who is not the input
            // daemon, is ignored rather than treated as an error.
            _ => {}
        }
    }
}

/// Map a client's buffer and describe it, or `None` if it cannot be reached.
fn adopt(buffer: u64, x: u64, y: u64, z: u64, owner: u64) -> Option<Surface> {
    let base = user::buffer_map(buffer);
    if base < 0 {
        return None;
    }

    let mut info = user::BufferInfo::default();
    if user::buffer_info(buffer, &mut info) < 0 {
        return None;
    }

    Some(Surface {
        buffer,
        base: base as u64,
        x,
        y,
        width: info.width as u64,
        height: info.height as u64,
        stride: info.stride as u64,
        z,
        owner,
    })
}
