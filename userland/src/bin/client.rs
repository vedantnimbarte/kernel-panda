//! A graphics client.
//!
//! Allocates a buffer, fills it with one colour, shares it with the compositor
//! and asks for it to be shown. The whole surface lifecycle from a process that
//! has no privilege of any kind.

#![no_std]
#![no_main]

use panda_user as user;

user::entry!(main);

/// Start-up parameters, written into a page by the kernel before entry. There
/// are more of them than the single argument register can carry, so the
/// argument is a pointer to this instead.
#[repr(C)]
struct Parameters {
    colour: u64,
    x: u64,
    y: u64,
    endpoint: u64,
    width: u64,
    height: u64,
    compositor: u64,
    bytes_per_pixel: u64,
}

const TAG_PRESENT: u64 = 2;

extern "C" fn main(parameters: u64) {
    // SAFETY: the kernel maps this page writable and fills it in before entry.
    let parameters = unsafe { &*(parameters as *const Parameters) };

    let buffer = user::buffer_create(parameters.width, parameters.height);
    if buffer < 0 {
        user::write("  [client] could not allocate a buffer\n");
        user::exit(1);
    }
    let buffer = buffer as u64;

    let base = user::buffer_map(buffer);
    if base < 0 {
        user::write("  [client] could not map its own buffer\n");
        user::exit(1);
    }

    fill(base as u64, parameters);

    if user::buffer_share(buffer, parameters.compositor) < 0 {
        user::write("  [client] could not share with the compositor\n");
        user::exit(1);
    }

    let message = user::Message {
        tag: TAG_PRESENT,
        words: [buffer, parameters.x, parameters.y, 0],
        sender: 0,
    };
    user::ipc_send(parameters.endpoint, &message);
}

/// Paint the buffer one flat colour.
///
/// Written a byte at a time rather than as `u32`s: the display is 24-bit, so a
/// four-byte write per pixel would shear the image a little further right on
/// every row.
fn fill(base: u64, parameters: &Parameters) {
    let depth = parameters.bytes_per_pixel;
    let pixels = parameters.width * parameters.height;

    for index in 0..pixels {
        let pixel = base + index * depth;
        // SAFETY: inside a buffer this process allocated and mapped, and the
        // loop covers exactly width * height pixels of `depth` bytes each.
        unsafe {
            for byte in 0..depth {
                let component = (parameters.colour >> (8 * byte)) as u8;
                core::ptr::write_volatile((pixel + byte) as *mut u8, component);
            }
        }
    }
}
