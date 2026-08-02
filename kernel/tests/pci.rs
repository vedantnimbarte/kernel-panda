//! PCI / PCI Express enumeration.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::console::framebuffer;
use panda_kernel::memory::paging;
use panda_kernel::pci::{self, Address, Bar};
use panda_kernel::{arch::x86_64::halt_loop, testing, BOOTLOADER_CONFIG};
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

#[test_case]
fn the_bus_has_devices_on_it() {
    let devices = pci::enumerate();
    assert!(
        !devices.is_empty(),
        "no PCI devices answered; the configuration ports are not working"
    );
}

#[test_case]
fn there_is_a_host_bridge_at_the_root() {
    let devices = pci::enumerate();
    let root = devices
        .iter()
        .find(|device| device.address == Address::new(0, 0, 0))
        .expect("nothing at 00:00.0");

    assert_eq!(
        root.class, 0x06,
        "the device at 00:00.0 is not a bridge, so the scan is misreading config space"
    );
    assert_eq!(root.subclass, 0x00, "00:00.0 is not a host bridge");
}

#[test_case]
fn every_device_has_a_distinct_address() {
    let devices = pci::enumerate();
    for (index, device) in devices.iter().enumerate() {
        for other in &devices[index + 1..] {
            assert_ne!(
                device.address, other.address,
                "the same bus address was reported twice"
            );
        }
    }
}

#[test_case]
fn absent_devices_are_not_invented() {
    // Nothing lives this far out on QEMU's machine model. A floating bus reads
    // back all-ones, which must be recognised as absence rather than as a device
    // with vendor 0xFFFF.
    let devices = pci::enumerate();
    assert!(
        !devices.iter().any(|device| device.vendor_id == 0xFFFF),
        "an all-ones read was mistaken for a real device"
    );
}

#[test_case]
fn the_display_controller_is_found() {
    let display = pci::find_display().expect("no display controller on the bus");
    assert_eq!(display.class, pci::CLASS_DISPLAY);
}

#[test_case]
fn probing_a_bar_leaves_it_unchanged() {
    // Sizing a BAR works by writing all-ones and reading back which bits stuck,
    // which points the register somewhere meaningless until it is restored. If
    // the restore were wrong, the device would be remapped out from under
    // whatever is using it -- here, the framebuffer the console is drawing on.
    let display = pci::find_display().expect("no display controller");

    let before = pci::read_config(display.address, 0x10);
    let _ = pci::read_bar(display.address, 0);
    let after = pci::read_config(display.address, 0x10);

    assert_eq!(
        before, after,
        "BAR0 was left modified after being sized; the device has been remapped"
    );
}

#[test_case]
fn the_framebuffer_lives_inside_the_display_bar() {
    // The bootloader found the framebuffer by its own means. If enumeration is
    // correct, the address it handed us must fall inside the display
    // controller's memory BAR -- two independent routes to the same hardware.
    let display = pci::find_display().expect("no display controller");

    let Some(Bar::Memory { address, size, .. }) = pci::read_bar(display.address, 0) else {
        panic!("the display controller has no memory BAR0");
    };

    let virtual_base = framebuffer::buffer_address().expect("no framebuffer adopted");
    let physical = paging::translate(VirtAddr::new(virtual_base))
        .expect("the framebuffer is not mapped")
        .as_u64();

    assert!(
        physical >= address && physical < address + size,
        "the framebuffer at {physical:#x} is outside BAR0 ({address:#x}..{:#x})",
        address + size
    );

    assert!(
        framebuffer::buffer_len() as u64 <= size,
        "the framebuffer is larger than the BAR that is supposed to contain it"
    );
}
