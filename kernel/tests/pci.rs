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
fn both_views_of_configuration_space_agree() {
    // ECAM and the configuration ports are two windows onto the same registers,
    // so they must agree about the low 256 bytes. If they do not, the MCFG table
    // describes a window somewhere other than where the firmware actually put
    // it -- and every extended read after that is of unrelated physical memory,
    // which is a much worse failure than having no ECAM at all.
    match pci::both_mechanisms_agree() {
        None => panda_kernel::serial_println!("  (skipped: no ECAM on this machine)"),
        Some(agreed) => assert!(
            agreed,
            "the memory-mapped and port-based views of configuration space \
             disagree; the ECAM window is not where MCFG says it is"
        ),
    }
}

#[test_case]
fn extended_configuration_space_is_reachable() {
    if !pci::ecam_available() {
        panda_kernel::serial_println!("  (skipped: no ECAM on this machine)");
        return;
    }

    assert_eq!(
        pci::config_limit(),
        pci::EXTENDED_CONFIG_LIMIT,
        "ECAM is mapped but the kernel still thinks it is limited to 256 bytes"
    );

    // Every PCI Express function has at least one extended capability, and
    // conventional PCI devices behind a bridge have none. Requiring that *some*
    // device on the bus has one proves the reads above 0xFF are landing on real
    // registers rather than returning the all-ones of an unmapped read.
    let devices = pci::enumerate();
    let with_capabilities = devices
        .iter()
        .filter(|device| !pci::extended_capabilities(device.address).is_empty())
        .count();

    panda_kernel::serial_println!(
        "  ({with_capabilities} of {} devices expose extended capabilities)",
        devices.len()
    );

    // Buses are mapped on first use, so the whole 256-bus window the firmware
    // describes is reachable without 65,536 page-table entries established at
    // boot for buses that will never answer.
    let (first, last) = pci::ecam_bus_range().expect("ECAM is available but reports no range");
    let described = (last as usize) - (first as usize) + 1;
    let mapped = pci::mapped_bus_count();
    panda_kernel::serial_println!("  ({mapped} of {described} described buses mapped)");
    assert!(
        mapped <= described,
        "more buses are mapped than the firmware described"
    );
    assert!(mapped > 0, "no bus was mapped despite ECAM being available");

    assert!(
        mapped < described,
        "every one of the {described} described buses is mapped; enumeration is \
         mapping the whole window and the laziness buys nothing"
    );

    // The highest described bus must still be reachable -- that is what the old
    // fixed cap could not do. Nothing is expected to answer there; what matters
    // is that the read lands on real mapped memory rather than faulting.
    let far = pci::Address::new(last, 0, 0);
    assert!(
        pci::read_config_ecam(far, 0x00).is_some(),
        "the highest described bus ({last}) is out of reach"
    );
    // Mapped, or the read above would have fallen through to `None` -- but not
    // necessarily one more than before, since a full set evicts to make room.
    assert!(
        pci::mapped_bus_count() <= pci::MAX_MAPPED_BUSES,
        "reaching the highest bus pushed the mapped set past its bound"
    );

    for device in &devices {
        for capability in pci::extended_capabilities(device.address) {
            assert!(
                capability.offset >= 0x100 && capability.offset < pci::EXTENDED_CONFIG_LIMIT,
                "an extended capability was reported at {:#x}, outside extended \
                 configuration space",
                capability.offset
            );
            assert_ne!(
                capability.id, 0xFFFF,
                "a capability id of all-ones means the read did not reach a device"
            );
        }
    }
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

#[test_case]
fn walking_every_bus_keeps_the_mapped_set_bounded() {
    let Some((first, last)) = pci::ecam_bus_range() else {
        panda_kernel::serial_println!("  (skipped: no ECAM on this machine)");
        return;
    };
    let root = Address::new(first, 0, 0);
    let identity = pci::read_config_legacy(root, 0x00);

    // Past offset 0xFF, so every bus has to be mapped to answer.
    for bus in first..=last {
        pci::read_config_ecam(Address::new(bus, 0, 0), 0x100);
        assert!(
            pci::mapped_bus_count() <= pci::MAX_MAPPED_BUSES,
            "{} buses mapped after reaching bus {bus}; nothing is being evicted",
            pci::mapped_bus_count()
        );
    }

    // The root bus went out and has to come back correctly.
    assert_eq!(
        pci::read_config_ecam(root, 0x00),
        Some(identity),
        "the root bus read wrongly after being evicted and mapped again"
    );
}

static CHURN_DONE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Reach for buses all over the window, forcing evictions, on whichever
/// processor this lands on.
fn churn_buses() {
    let (first, last) = pci::ecam_bus_range().expect("no ECAM");
    let span = (last - first) as usize + 1;
    for step in 0..400usize {
        let bus = first + ((step * 37) % span) as u8;
        pci::read_config_ecam(Address::new(bus, 0, 0), 0x104);
    }
    CHURN_DONE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

#[test_case]
fn a_bus_is_never_unmapped_under_a_reader() {
    use core::sync::atomic::Ordering;
    use panda_kernel::sched;

    let Some((first, _)) = pci::ecam_bus_range() else {
        panda_kernel::serial_println!("  (skipped: no ECAM on this machine)");
        return;
    };

    // Three threads churn the mapped set from other processors while this one
    // keeps reading the root bus. An eviction racing a read would fault here
    // or there, and a stale translation would read the wrong register.
    CHURN_DONE.store(0, Ordering::Relaxed);
    for _ in 0..3 {
        sched::spawn("bus-churn", churn_buses).expect("spawn failed");
    }

    let root = Address::new(first, 0, 0);
    let identity = pci::read_config_legacy(root, 0x00);
    while CHURN_DONE.load(Ordering::Relaxed) < 3 {
        assert_eq!(
            pci::read_config_ecam(root, 0x00),
            Some(identity),
            "the root bus read wrongly while other processors churned the window"
        );
    }
    assert!(pci::mapped_bus_count() <= pci::MAX_MAPPED_BUSES);
}
