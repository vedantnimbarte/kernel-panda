//! Physical frame allocator.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::memory::frame;
use panda_kernel::{arch::x86_64::halt_loop, testing, BOOTLOADER_CONFIG};
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

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
fn accounting_is_self_consistent() {
    frame::with(|allocator| {
        assert!(allocator.total_frames() > 0, "no frames tracked at all");
        assert!(allocator.free_frames() > 0, "no free memory after boot");
        assert!(
            allocator.used_frames() > 0,
            "nothing marked used -- the kernel's own frames must not be allocatable"
        );
        assert_eq!(
            allocator.total_frames(),
            allocator.free_frames() + allocator.used_frames()
        );
    });
}

#[test_case]
fn the_bitmap_is_not_absurdly_large() {
    frame::with(|allocator| {
        // Sizing the bitmap from the highest address in the memory map rather
        // than the highest *usable* one pulls in the firmware's MMIO window near
        // the top of the address space, which costs tens of MiB of real RAM.
        // 16 GiB of tracked frames is far more than any test machine has.
        let tracked_bytes = allocator.total_frames() as u64 * 4096;
        assert!(
            tracked_bytes < 16 * 1024 * 1024 * 1024,
            "tracking {tracked_bytes} bytes of frames; the bitmap is covering an MMIO hole"
        );
    });
}

#[test_case]
fn allocations_are_distinct_and_returnable() {
    frame::with(|allocator| {
        let before = allocator.free_frames();

        let first = allocator.allocate().expect("out of frames");
        let second = allocator.allocate().expect("out of frames");
        assert_ne!(first, second, "the same frame was handed out twice");
        assert_eq!(allocator.free_frames(), before - 2);

        allocator.deallocate(first);
        allocator.deallocate(second);
        assert_eq!(
            allocator.free_frames(),
            before,
            "freed frames did not return to the pool"
        );
    });
}

#[test_case]
fn physical_address_zero_is_never_handed_out() {
    frame::with(|allocator| {
        let mut taken = [None; 64];
        for slot in taken.iter_mut() {
            let frame = allocator.allocate().expect("out of frames");
            assert_ne!(
                frame.start_address().as_u64(),
                0,
                "frame 0 was allocated; a null physical address must stay an error signal"
            );
            *slot = Some(frame);
        }
        for frame in taken.into_iter().flatten() {
            allocator.deallocate(frame);
        }
    });
}

#[test_case]
fn contiguous_allocation_returns_an_unbroken_run() {
    const COUNT: u64 = 8;

    frame::with(|allocator| {
        let before = allocator.free_frames();

        let start = allocator
            .allocate_contiguous(COUNT as usize)
            .expect("no run of 8 free frames");
        let base = start.start_address().as_u64();
        assert_eq!(base % 4096, 0, "run does not start on a frame boundary");
        assert_eq!(allocator.free_frames(), before - COUNT as usize);

        for index in 0..COUNT {
            let frame: PhysFrame<Size4KiB> =
                PhysFrame::containing_address(PhysAddr::new(base + index * 4096));
            allocator.deallocate(frame);
        }
        assert_eq!(allocator.free_frames(), before);
    });
}

#[test_case]
fn many_allocations_round_trip() {
    frame::with(|allocator| {
        let before = allocator.free_frames();

        // Enough churn to walk past the search hint and force it to wrap.
        for _ in 0..512 {
            let frame = allocator.allocate().expect("out of frames");
            allocator.deallocate(frame);
        }

        assert_eq!(allocator.free_frames(), before);
    });
}
