//! Page table management: map, write through the mapping, translate, unmap.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::memory::paging::{self, MapError};
use panda_kernel::memory::frame;
use panda_kernel::{arch::x86_64::halt_loop, testing, BOOTLOADER_CONFIG};
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

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

const RW: PageTableFlags = PageTableFlags::from_bits_truncate(
    PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits(),
);

/// Addresses well clear of the kernel, the heap at 0x4444_4444_0000, and
/// anything the bootloader mapped.
fn scratch_page(index: u64) -> Page<Size4KiB> {
    Page::containing_address(VirtAddr::new(0x_5555_0000_0000 + index * 0x1000))
}

#[test_case]
fn a_mapped_page_is_writable_and_translates() {
    let page = scratch_page(0);
    let frame = paging::map(page, RW).expect("mapping failed");

    let ptr = page.start_address().as_mut_ptr::<u64>();
    const PATTERN: u64 = 0xDEAD_BEEF_CAFE_F00D;

    // SAFETY: `page` was just mapped to a freshly allocated frame that nothing
    // else references, so this address is valid, writable, and unaliased.
    unsafe {
        ptr.write_volatile(PATTERN);
        assert_eq!(
            ptr.read_volatile(),
            PATTERN,
            "value written through a fresh mapping did not read back"
        );
    }

    assert_eq!(
        paging::translate(page.start_address()),
        Some(frame.start_address()),
        "translate disagrees with the frame that was mapped"
    );

    paging::unmap_and_free(page).expect("unmap failed");
}

#[test_case]
fn unmapping_releases_the_frame_and_the_translation() {
    let page = scratch_page(1);
    paging::map(page, RW).expect("mapping failed");

    let before = frame::with(|allocator| allocator.free_frames());
    paging::unmap_and_free(page).expect("unmap failed");

    assert_eq!(
        frame::with(|allocator| allocator.free_frames()),
        before + 1,
        "unmap_and_free did not return the frame to the allocator"
    );
    assert_eq!(
        paging::translate(page.start_address()),
        None,
        "the address still translates after being unmapped"
    );
}

#[test_case]
fn mapping_an_already_mapped_page_is_rejected_without_leaking() {
    let page = scratch_page(2);
    paging::map(page, RW).expect("first mapping failed");

    let before = frame::with(|allocator| allocator.free_frames());
    assert_eq!(paging::map(page, RW), Err(MapError::AlreadyMapped));
    assert_eq!(
        frame::with(|allocator| allocator.free_frames()),
        before,
        "the rejected mapping leaked the frame it had speculatively allocated"
    );

    paging::unmap_and_free(page).expect("unmap failed");
}

#[test_case]
fn unmapped_addresses_do_not_translate() {
    // Never mapped by anyone.
    assert_eq!(paging::translate(VirtAddr::new(0x_6666_0000_0000)), None);
}

#[test_case]
fn many_pages_can_be_mapped_and_released() {
    const COUNT: u64 = 64;
    let before = frame::with(|allocator| allocator.free_frames());

    for index in 0..COUNT {
        let page = scratch_page(16 + index);
        paging::map(page, RW).expect("mapping failed");

        // Touch every page, so a mapping that is present but wrong faults here
        // rather than silently passing.
        let ptr = page.start_address().as_mut_ptr::<u64>();
        // SAFETY: just mapped to a private frame.
        unsafe { ptr.write_volatile(index) };
        // SAFETY: as above.
        assert_eq!(unsafe { ptr.read_volatile() }, index);
    }

    for index in 0..COUNT {
        paging::unmap_and_free(scratch_page(16 + index)).expect("unmap failed");
    }

    assert_eq!(
        frame::with(|allocator| allocator.free_frames()),
        before,
        "mapping and unmapping {COUNT} pages did not balance"
    );
}
