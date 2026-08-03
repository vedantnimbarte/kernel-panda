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
//! * **Damage.** Only the regions that actually changed are recomposed and
//!   copied out, tracked as a list rather than one bounding box. A client
//!   updating a corner of the screen should not cost a full-screen redraw, and
//!   at 1024x768x3 a full redraw is over two megabytes.
//! * **Double buffering.** Composition happens in an off-screen buffer and
//!   reaches the display in a single copy. Drawing surfaces straight into the
//!   scanout means the display controller can read the screen halfway through
//!   -- with overlapping surfaces that is a visible flicker of whatever was
//!   underneath.

#![no_std]
#![no_main]

use panda_user as user;

user::entry!(main);

const TAG_SHUTDOWN: u64 = 0;
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
    };
}

/// A half-open rectangle. `right <= left` means empty.
#[derive(Clone, Copy)]
struct Rect {
    left: u64,
    top: u64,
    right: u64,
    bottom: u64,
}

impl Rect {
    const EMPTY: Rect = Rect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };

    fn is_empty(&self) -> bool {
        self.right <= self.left || self.bottom <= self.top
    }

    /// The smallest rectangle containing both.
    fn union(self, other: Rect) -> Rect {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        Rect {
            left: min(self.left, other.left),
            top: min(self.top, other.top),
            right: max(self.right, other.right),
            bottom: max(self.bottom, other.bottom),
        }
    }

    fn intersect(self, other: Rect) -> Rect {
        Rect {
            left: max(self.left, other.left),
            top: max(self.top, other.top),
            right: min(self.right, other.right),
            bottom: min(self.bottom, other.bottom),
        }
    }

    fn overlaps(self, other: Rect) -> bool {
        !self.intersect(other).is_empty()
    }

    fn area(self) -> u64 {
        if self.is_empty() {
            0
        } else {
            (self.right - self.left) * (self.bottom - self.top)
        }
    }
}

/// Damaged regions, kept apart rather than merged into one bounding box.
///
/// A single accumulated rectangle is simple and wrong in a specific way: a
/// surface that moves across the screen damages where it was and where it went,
/// and one rectangle covering both means recomposing everything in between. For
/// a surface crossing the screen that is the screen.
///
/// A fixed array rather than a list, because there is no allocator here. When it
/// is full, the two regions whose merged box wastes the least are combined --
/// so it degrades toward the single-rectangle behaviour under pressure rather
/// than failing.
const MAX_DAMAGE: usize = 8;

struct Damage {
    regions: [Rect; MAX_DAMAGE],
    count: usize,
}

impl Damage {
    const fn new() -> Self {
        Self {
            regions: [Rect::EMPTY; MAX_DAMAGE],
            count: 0,
        }
    }

    fn clear(&mut self) {
        self.count = 0;
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn add(&mut self, area: Rect) {
        if area.is_empty() {
            return;
        }

        // Merge into anything it already touches. Two overlapping regions would
        // composite the shared part twice -- correct, but paid for twice.
        for index in 0..self.count {
            if self.regions[index].overlaps(area) {
                self.regions[index] = self.regions[index].union(area);
                self.coalesce(index);
                return;
            }
        }

        if self.count < MAX_DAMAGE {
            self.regions[self.count] = area;
            self.count += 1;
            return;
        }

        // Full. Merge whichever pairing wastes the least -- the merged box
        // minus the two areas it replaces -- so what gets joined is whatever
        // was already close together.
        let mut best = (0usize, 1usize);
        let mut best_waste = u64::MAX;
        for a in 0..self.count {
            for b in (a + 1)..self.count {
                let merged = self.regions[a].union(self.regions[b]);
                let waste = merged
                    .area()
                    .saturating_sub(self.regions[a].area() + self.regions[b].area());
                if waste < best_waste {
                    best_waste = waste;
                    best = (a, b);
                }
            }
        }

        let (a, b) = best;
        self.regions[a] = self.regions[a].union(self.regions[b]);
        self.regions[b] = self.regions[self.count - 1];
        self.count -= 1;
        self.regions[self.count] = area;
        self.count += 1;
    }

    /// Absorb any other region the one at `index` now overlaps.
    ///
    /// Growing a region can make it touch a neighbour it did not before.
    fn coalesce(&mut self, index: usize) {
        let mut index = index;
        let mut other = 0;
        while other < self.count {
            if other == index || !self.regions[index].overlaps(self.regions[other]) {
                other += 1;
                continue;
            }

            self.regions[index] = self.regions[index].union(self.regions[other]);

            // Swap-remove `other`. If the region being grown was the one moved
            // down to fill the gap, it now lives at `other` -- following the
            // stale index would grow whatever landed there instead.
            let last = self.count - 1;
            self.regions[other] = self.regions[last];
            self.count -= 1;
            if index == last {
                index = other;
            }

            // Start again: the union may now reach something already passed.
            other = 0;
        }
    }
}

fn min(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}

fn max(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

struct Compositor {
    scanout_base: u64,
    /// Where composition happens. Copied to the scanout once per frame.
    back_base: u64,
    screen: user::BufferInfo,
    surfaces: [Surface; MAX_SURFACES],
    damage: Damage,
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

        // Taken before composing: the regions are independent of each other, and
        // iterating them while `self` is borrowed for the blits is what the
        // borrow checker would otherwise object to.
        let regions = self.damage.regions;
        let region_count = self.damage.count;
        self.damage.clear();

        for region in regions.iter().take(region_count) {
            let area = region.intersect(screen);
            if area.is_empty() {
                continue;
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

            self.flush(area);
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

    /// Copy the composed region to the display, one row at a time.
    fn flush(&self, area: Rect) {
        let depth = self.depth();
        let stride = self.screen.stride as u64;
        let width = (area.right - area.left) * depth;

        for row in area.top..area.bottom {
            let offset = row * stride + area.left * depth;
            // SAFETY: both buffers are the screen's dimensions and `area` is
            // clipped to them, so this row is inside each.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.back_base + offset) as *const u8,
                    (self.scanout_base + offset) as *mut u8,
                    width as usize,
                );
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
        damage: Damage::new(),
    };

    loop {
        let mut message = user::Message::default();
        if user::ipc_receive(endpoint, &mut message) < 0 {
            user::exit(1);
        }

        match message.tag {
            TAG_SHUTDOWN => user::exit(0),
            TAG_PRESENT => {
                if let Some(surface) = adopt(message.words[0], message.words[1], message.words[2], message.words[3]) {
                    compositor.track(surface);
                    compositor.compose();
                }
            }
            // Key events and anything else are ignored rather than treated as
            // an error -- the input daemon shares this endpoint.
            _ => {}
        }
    }
}

/// Map a client's buffer and describe it, or `None` if it cannot be reached.
fn adopt(buffer: u64, x: u64, y: u64, z: u64) -> Option<Surface> {
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
    })
}
