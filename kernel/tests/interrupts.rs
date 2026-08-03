//! Hardware interrupt delivery via the Local APIC timer.
//!
//! Every case here has a bounded spin rather than a `hlt` wait. If interrupt
//! delivery is broken -- which is precisely what these tests exist to detect --
//! a `hlt` loop never wakes and the run dies on the host's timeout with no
//! diagnostic. A bounded spin fails with a message instead.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::arch::x86_64::apic;
use panda_kernel::{arch::x86_64::halt_loop, println, sync, testing, time, BOOTLOADER_CONFIG};

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

/// Generous enough that a slow host does not cause a false failure, small
/// enough to fail well inside the harness timeout.
const SPIN_BUDGET: u64 = 2_000_000_000;

/// Spin until `condition` holds, or give up.
fn wait_for(condition: impl Fn() -> bool) -> bool {
    for _ in 0..SPIN_BUDGET {
        if condition() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

#[test_case]
fn the_apic_came_up() {
    assert!(
        apic::is_initialised(),
        "the Local APIC was never mapped or enabled"
    );
}

#[test_case]
fn interrupts_are_enabled_after_init() {
    assert!(
        sync::interrupts_enabled(),
        "init finished with interrupts still masked"
    );
}

#[test_case]
fn the_timer_actually_fires() {
    let start = time::ticks();
    assert!(
        wait_for(|| time::ticks() > start),
        "no timer interrupt arrived within the spin budget -- the APIC is \
         enabled but nothing is being delivered"
    );
}

#[test_case]
fn ticks_keep_arriving() {
    // One tick could be a fluke of boot ordering. Ten means the timer is in
    // periodic mode and the handler is acknowledging properly -- a missing EOI
    // delivers exactly one interrupt and then goes silent forever.
    let target = time::ticks() + 10;
    assert!(
        wait_for(|| time::ticks() >= target),
        "the timer stopped after the first few ticks; the handler is probably \
         not sending an end-of-interrupt"
    );
}

#[test_case]
fn uptime_advances() {
    assert_eq!(
        time::frequency_hz(),
        apic::TIMER_HZ as u64,
        "the recorded tick rate does not match what the timer was programmed for"
    );

    let start = time::uptime_ms();
    assert!(
        wait_for(|| time::uptime_ms() > start),
        "uptime never moved"
    );
}

#[test_case]
fn the_apic_has_no_cacheable_alias() {
    use panda_kernel::memory::paging;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    // The APIC's registers are mapped uncached at their own address. The
    // bootloader's physical-memory window maps every physical address including
    // that one, so without care there is a second mapping of the same device
    // memory with different cache attributes -- which the architecture leaves
    // undefined, and which in practice means a speculative read through the
    // cacheable view can hold a value the device has since changed.
    let physical = apic::physical_base();
    if physical == 0 {
        println!("  (skipped: no APIC)");
        return;
    }

    let alias = paging::physical_offset() + physical;
    let Some(flags) = paging::flags(alias) else {
        // No alias at all is the ideal outcome.
        return;
    };

    println!(
        "  (alias maps a {} KiB page)",
        paging::mapping_size(alias).unwrap_or(0) / 1024
    );

    assert!(
        flags.contains(PageTableFlags::NO_CACHE),
        "the physical-memory window maps the APIC cacheable while the kernel's \
         own mapping is uncached; two views of one device with different memory \
         types"
    );
    let _ = VirtAddr::new(0);
}

#[test_case]
fn serial_input_is_routed_through_the_io_apic() {
    use panda_kernel::arch::x86_64::ioapic;

    if !ioapic::is_initialised() {
        println!("  (skipped: no I/O APIC on this machine)");
        return;
    }

    let topology = panda_kernel::smp::topology().expect("ACPI reported nothing");
    let (gsi, _) = topology.resolve_irq(panda_kernel::console::uart::COM1_IRQ);
    let (_, pin) = topology
        .pin_for_gsi(gsi, ioapic::inputs_of)
        .expect("no I/O APIC owns the serial interrupt");

    assert!(
        ioapic::serial_is_routed(),
        "the I/O APIC is present but serial input was never routed, so the \
         console is still being polled from the timer"
    );
    assert_eq!(
        ioapic::vector_of(pin),
        Some(apic::SERIAL_VECTOR),
        "pin {pin} does not deliver the serial vector"
    );
    assert_eq!(
        ioapic::is_masked(pin),
        Some(false),
        "the serial interrupt is routed but still masked, so nothing will \
         ever be delivered"
    );
}

#[test_case]
fn pin_ownership_asks_the_chip_how_many_inputs_it_has() {
    use panda_kernel::acpi::IoApic;
    use panda_kernel::arch::x86_64::ioapic;

    if !ioapic::is_initialised() {
        return;
    }

    let topology = panda_kernel::smp::topology().expect("ACPI reported nothing");
    let first = *topology.io_apics.first().expect("no I/O APIC reported");
    let inputs = ioapic::inputs_of(first).expect("the chip did not report its inputs") as u32;
    assert!(inputs > 0, "the chip reports no input pins");

    // An interrupt past the end of this chip's pins belongs to no chip on a
    // single-I/O-APIC machine. Deciding ownership by base address alone -- the
    // obvious shortcut, since the MADT gives a starting interrupt and no length
    // -- would attribute it to this one anyway, and the redirection entry would
    // be written to a register that does not exist.
    let past_the_end = first.gsi_base + inputs;
    assert!(
        topology.pin_for_gsi(past_the_end, ioapic::inputs_of).is_none(),
        "interrupt {past_the_end} was attributed to a chip whose last input is \
         {}; ownership is not consulting the chip",
        first.gsi_base + inputs - 1
    );

    // The last pin it really does have must still resolve.
    assert_eq!(
        topology
            .pin_for_gsi(first.gsi_base + inputs - 1, ioapic::inputs_of)
            .map(|(_, pin)| pin as u32),
        Some(inputs - 1),
        "the chip's own last pin did not resolve to it"
    );

    // A chip the firmware never reported has nothing to say.
    let imaginary = IoApic {
        address: 0xDEAD_0000,
        gsi_base: 0,
    };
    assert_eq!(
        ioapic::inputs_of(imaginary),
        None,
        "an unmapped chip reported an input count"
    );
}

#[test_case]
fn an_unrouted_pin_stays_masked() {
    use panda_kernel::arch::x86_64::ioapic;

    if !ioapic::is_initialised() {
        return;
    }

    // The chip comes out of reset with every entry masked, and nothing here
    // unmasks a pin it has not been asked to route. A pin that is live without
    // a handler behind it delivers to whatever vector the firmware left in the
    // entry, which on a level-triggered line means forever.
    let pins = ioapic::pin_count();
    assert!(pins > 0, "the I/O APIC reports no input pins");

    let topology = panda_kernel::smp::topology().expect("ACPI reported nothing");
    let (gsi, _) = topology.resolve_irq(panda_kernel::console::uart::COM1_IRQ);
    let routed = topology.pin_for_gsi(gsi, ioapic::inputs_of).map(|(_, pin)| pin);

    for pin in 0..pins {
        if Some(pin) == routed {
            continue;
        }
        assert_eq!(
            ioapic::is_masked(pin),
            Some(true),
            "pin {pin} is unmasked and nothing routed it"
        );
    }
}

#[test_case]
fn only_one_processor_keeps_the_clock() {
    // Every core has its own APIC timer and every one of them reaches the same
    // handler. Counting the clock on all of them makes uptime run at the number
    // of cores times real speed, and any duration measured in ticks come out
    // short by the same factor -- which is invisible from inside, because
    // everything is measured against the same wrong clock.
    let start = time::ticks();
    assert!(wait_for(|| time::ticks() >= start + 5), "the clock stopped");

    let clock = time::ticks();
    let boot_cpu = time::cpu_ticks(0);

    // The clock is the boot processor's own interrupt count. A handful of ticks
    // of slack: the two are read one after the other, not atomically.
    assert!(
        clock.abs_diff(boot_cpu) <= 4,
        "the clock reads {clock} but the boot processor has taken {boot_cpu} \
         timer interrupts; something else is advancing it"
    );

    let others: u64 = (1..panda_kernel::smp::MAX_CPUS)
        .map(time::cpu_ticks)
        .sum();
    if panda_kernel::smp::online_count() > 1 {
        assert!(
            others > 0,
            "no processor other than the boot one is taking timer interrupts, \
             so this case is not testing anything"
        );
    }
}

#[test_case]
fn the_console_survives_printing_under_interrupt_pressure() {
    // The console lock is taken with interrupts disabled on this CPU. Before
    // that fix, a timer interrupt landing while the lock was held would deadlock
    // the handler against the code it interrupted. This hammers that window.
    let start = time::ticks();
    for line in 0..200 {
        println!("interrupt pressure line {line}");
    }
    assert!(
        time::ticks() > start,
        "no ticks arrived during 200 prints -- interrupts are being lost"
    );
}
