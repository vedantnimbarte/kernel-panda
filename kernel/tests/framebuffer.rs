//! Verifies the framebuffer text console without anyone having to look at a
//! screen.
//!
//! Rasterisation is otherwise only observable visually, which a headless test
//! run cannot check. These cases assert on the framebuffer's actual contents
//! instead.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::console::framebuffer;
use panda_kernel::{arch::x86_64::halt_loop, println, testing, BOOTLOADER_CONFIG};

entry_point!(test_kernel_main, config = &BOOTLOADER_CONFIG);

fn test_kernel_main(boot_info: &'static mut BootInfo) -> ! {
    panda_kernel::init(boot_info);
    test_main();
    halt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    testing::panic_handler(info)
}

#[test_case]
fn bootloader_provided_a_framebuffer() {
    assert!(
        framebuffer::is_available(),
        "no framebuffer in BootInfo; the console has nothing to draw on"
    );
}

#[test_case]
fn printing_lights_pixels() {
    framebuffer::clear();
    assert_eq!(
        framebuffer::non_zero_byte_count(),
        0,
        "clear() left non-zero bytes behind"
    );

    // A row of dense glyphs, so the assertion does not hinge on one thin stroke.
    println!("MMMMMMMMMMMMMMMM");

    assert!(
        framebuffer::non_zero_byte_count() > 0,
        "printing changed nothing in the framebuffer -- glyphs are not reaching \
         the hardware, or the pixel format is being decoded wrongly"
    );
}

#[test_case]
fn scrolling_stays_in_bounds() {
    framebuffer::clear();

    // Comfortably more lines than fit on any plausible screen, which forces the
    // scroll path to run many times. An off-by-one in the row arithmetic shows
    // up here as a page fault rather than as a cosmetic glitch.
    for line in 0..300 {
        println!("scroll test line {line}");
    }

    assert!(
        framebuffer::non_zero_byte_count() > 0,
        "the screen ended up blank after scrolling"
    );
}

#[test_case]
fn every_printable_ascii_character_renders() {
    framebuffer::clear();

    // Walks the whole font table, including the last entry -- an off-by-one in
    // the glyph lookup would index out of bounds and panic here.
    for code in 0x20u8..=0x7E {
        println!("{}", code as char);
    }

    assert!(framebuffer::non_zero_byte_count() > 0);
}
