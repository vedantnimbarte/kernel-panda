//! The Sovereign compositor.
//!
//! Maps the scanout buffer once, then blits client surfaces into it as their
//! handles arrive over IPC. It never touches hardware: the screen reaches it as
//! a shared buffer handle, and what to draw reaches it as a message.

#![no_std]
#![no_main]

use panda_user as user;

user::entry!(main);

const TAG_SHUTDOWN: u64 = 0;
const TAG_PRESENT: u64 = 2;

extern "C" fn main(endpoint: u64) {
    let scanout = user::scanout();
    if scanout < 0 {
        user::write("  [compositor] refused the scanout buffer\n");
        user::exit(1);
    }
    let scanout = scanout as u64;

    let base = user::buffer_map(scanout);
    if base < 0 {
        user::write("  [compositor] could not map the screen\n");
        user::exit(1);
    }
    let base = base as u64;

    let mut screen = user::BufferInfo::default();
    user::buffer_info(scanout, &mut screen);

    loop {
        let mut message = user::Message::default();
        if user::ipc_receive(endpoint, &mut message) < 0 {
            user::exit(1);
        }

        match message.tag {
            TAG_SHUTDOWN => user::exit(0),
            TAG_PRESENT => present(
                base,
                &screen,
                message.words[0],
                message.words[1],
                message.words[2],
            ),
            // Key events and anything else are ignored rather than treated as
            // an error -- the input daemon shares this endpoint.
            _ => {}
        }
    }
}

fn present(screen_base: u64, screen: &user::BufferInfo, buffer: u64, x: u64, y: u64) {
    let source = user::buffer_map(buffer);
    if source < 0 {
        return;
    }
    let source = source as u64;

    let mut info = user::BufferInfo::default();
    if user::buffer_info(buffer, &mut info) < 0 {
        return;
    }

    let depth = screen.bytes_per_pixel as u64;

    for row in 0..info.height as u64 {
        // Clip rather than trust. A surface asking to be drawn past the bottom
        // of the screen would otherwise walk off the end of the framebuffer --
        // and the compositor is the one process with the whole screen mapped.
        if y + row >= screen.height as u64 {
            break;
        }

        let destination = screen_base + (y + row) * screen.stride as u64 + x * depth;
        let origin = source + row * info.stride as u64;

        let remaining = (screen.width as u64).saturating_sub(x) * depth;
        let width = (info.stride as u64).min(remaining);

        // SAFETY: both ranges lie inside buffers this process has mapped, and
        // the row length is clipped to what is left of the screen.
        unsafe {
            core::ptr::copy_nonoverlapping(
                origin as *const u8,
                destination as *mut u8,
                width as usize,
            );
        }
    }
}
