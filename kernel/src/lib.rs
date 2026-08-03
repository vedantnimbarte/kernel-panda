//! Kernel Panda: a bare-metal microkernel written in `no_std` Rust.
//!
//! Everything lives in the library so that the boot binary (`src/main.rs`) and
//! every integration test kernel under `tests/` share exactly one implementation.

#![no_std]
// Required for `extern "x86-interrupt"` exception handlers, which need the
// compiler to emit an iret-based epilogue and preserve the full register set.
#![feature(abi_x86_interrupt)]
// An `unsafe fn` body is not automatically an unsafe block. Every unsafe
// operation has to be written out and justified individually, even inside a
// function that is already unsafe to call -- otherwise "this function is unsafe"
// silently licenses every dereference in it, which is exactly the blanket
// permission the auditability requirement is meant to rule out.
#![deny(unsafe_op_in_unsafe_fn)]

// The kernel heap is set up during `init`, after which `Box`, `Vec` and friends
// are available. Nothing before that point may allocate.
extern crate alloc;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::BootInfo;

pub mod acpi;
pub mod allocator;
pub mod arch;
pub mod console;
pub mod elf;
pub mod gbm;
pub mod ipc;
pub mod memory;
pub mod pci;
pub mod sched;
pub mod smp;
pub mod sync;
pub mod syscall;
pub mod testing;
pub mod time;
pub mod userspace;

/// Boot-time requests handed to the bootloader.
///
/// This is a `const` rather than a `static` on purpose: `entry_point!` serialises
/// it inside a const initialiser, and reading a `static` in const context is not
/// allowed.
pub const BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();

    // Map all of physical memory at a fixed virtual offset. This populates
    // `BootInfo::physical_memory_offset`, without which none of the Phase 2
    // page-table work is possible -- so it goes in from the very first boot
    // rather than being retrofitted later.
    config.mappings.physical_memory = Some(Mapping::Dynamic);

    // The default stack is tight for unoptimised debug builds, whose stack
    // frames are several times larger than release ones.
    config.kernel_stack_size = 128 * 1024;

    config
};

/// Bring up the subsystems every entry point needs before it can do anything
/// observable. Call exactly once, first thing.
///
/// Hands `boot_info` back so the caller can go on to use the rest of it: the
/// framebuffer is borrowed out of it here, and returning it is what keeps that
/// borrow from swallowing the whole structure.
pub fn init(boot_info: &'static mut BootInfo) -> &'static mut BootInfo {
    // Serial first: everything after this point can report its own failures.
    let serial_ok = console::init();

    // Then the descriptor tables, so a fault during the rest of boot produces a
    // readable diagnostic instead of a silent reset.
    arch::x86_64::init();

    // Before any mapping is created, because NX has to be enabled before a page
    // table entry may carry the bit.
    arch::x86_64::enable_memory_protections();

    adopt_framebuffer(boot_info);

    // Memory last: it needs the console up to report the map it finds, and the
    // IDT installed so a bad mapping surfaces as a page fault with an address
    // rather than as a reset. It ends by turning `alloc` on.
    memory::init(boot_info);
    // The scheduler needs the heap for thread stacks, and it must exist before
    // the first timer tick -- that handler preempts through it.
    sched::init();

    // Read the firmware tables before interrupts, so the APIC address the timer
    // uses can be cross-checked against what ACPI reports.
    if let Some(rsdp) = boot_info.rsdp_addr.into_option() {
        // SAFETY: the address comes from the bootloader, and physical memory is
        // mapped by this point.
        match unsafe { acpi::topology(rsdp) } {
            Ok(found) => smp::record_topology(found),
            Err(error) => crate::println!("warning: could not read ACPI tables: {error:?}"),
        }
    }

    // Interrupts last of all. The APIC needs its MMIO page mapped, so it cannot
    // come up before memory does -- and nothing may be unmasked until the
    // console lock is interrupt-safe, which it now is.
    if let Err(error) = arch::x86_64::enable_interrupts() {
        // Survivable: the kernel just has no sense of time.
        crate::println!("warning: could not start the APIC timer: {error:?}");
    }

    // Device interrupts, which need both the firmware tables and a Local APIC
    // to deliver to. Every failure here is survivable -- the timer handler keeps
    // polling the console when routing did not happen -- so each one reports and
    // carries on.
    route_device_interrupts();

    // Memory-mapped PCI configuration, if the firmware describes a window.
    // Survivable too: without it the port mechanism still reaches everything
    // below offset 0x100, which is all the kernel reads today.
    if let Some(rsdp) = boot_info.rsdp_addr.into_option() {
        map_pci_config(rsdp);
    }

    // Other processors last of all: they need the APIC calibrated, the heap for
    // their stacks, and the scheduler ready to adopt them.
    //
    // SAFETY: called once, from the boot processor, with everything they depend
    // on already up.
    let started = unsafe { smp::start_application_processors() };
    if started > 0 {
        crate::println!(
            "smp: {} of {} processors online",
            smp::online_count(),
            smp::processor_count()
        );
    }

    if !serial_ok {
        crate::println!("warning: UART loopback self-test failed; serial output may be lost");
    }

    boot_info
}

/// Bring up the I/O APIC and point the serial port's interrupt at this
/// processor.
///
/// Serial input was polled from the timer handler before this, which capped
/// throughput at the tick rate and meant a keystroke waited up to a full
/// quantum to be noticed. It was not laziness: routing IRQ 4 needs an I/O APIC,
/// and finding one needs ACPI, so it had to wait for both.
fn route_device_interrupts() {
    let Some(topology) = smp::topology() else {
        return;
    };
    let Some(io_apic) = topology.io_apics.first().copied() else {
        crate::println!("warning: the firmware reported no I/O APIC; console input stays polled");
        return;
    };

    // SAFETY: the address came from the firmware's own MADT, and this runs once
    // during boot with paging up.
    if let Err(error) = unsafe { arch::x86_64::ioapic::init(io_apic) } {
        crate::println!("warning: could not map the I/O APIC: {error:?}");
        return;
    }

    let apic_id = arch::x86_64::apic::id();
    match arch::x86_64::ioapic::route_serial(&topology, apic_id) {
        Ok(()) => crate::println!("ioapic: serial input on vector {:#x}", arch::x86_64::apic::SERIAL_VECTOR),
        Err(error) => crate::println!("warning: could not route serial input: {error:?}"),
    }
}

/// Map the memory-mapped PCI configuration window, if there is one.
///
/// The port mechanism reaches only the first 256 bytes of each function's
/// configuration space, because its selector has nowhere to put a wider offset.
/// Everything PCI Express added -- MSI-X, AER, link control -- lives above that.
fn map_pci_config(rsdp: u64) {
    // SAFETY: the address comes from the bootloader, and physical memory is
    // mapped by this point.
    let regions = match unsafe { acpi::ecam_regions(rsdp) } {
        Ok(regions) => regions,
        Err(acpi::AcpiError::NoSuchTable) => {
            // Expected on anything predating PCI Express. Not worth a warning.
            return;
        }
        Err(error) => {
            crate::println!("warning: could not read the PCI config table: {error:?}");
            return;
        }
    };

    let Some(region) = regions.first().copied() else {
        return;
    };

    // SAFETY: the region came from the firmware's own MCFG table, and this runs
    // once during boot with paging up.
    match unsafe { pci::init_ecam(region) } {
        Ok(()) => {
            // The mapped range, not the described one: firmware routinely
            // claims all 256 buses and the window is clamped.
            let (first, last) = pci::ecam_bus_range().unwrap_or((0, 0));
            crate::println!(
                "pci: extended config at {:#x}, buses {first}-{last} of {}-{}",
                region.base,
                region.start_bus,
                region.end_bus
            );
        }
        Err(error) => {
            crate::println!("warning: could not map PCI extended config: {error:?}");
        }
    }
}

/// Give back everything a thread was holding.
///
/// Called from `sched::exit_current`, while the thread is still running: it can
/// take locks and free memory there. Doing it from `reap` instead would mean
/// freeing memory inside the timer interrupt with the scheduler lock held, which
/// is a deadlock waiting for the right moment.
///
/// Lives here rather than in `sched` so the scheduler does not have to know what
/// an endpoint or a graphics buffer is.
pub fn release_thread_resources(thread: sched::ThreadId) {
    gbm::release_thread(thread);
    ipc::release_thread(thread);
    userspace::release_slot(thread);
}

/// Hand the bootloader's framebuffer to the console.
fn adopt_framebuffer(boot_info: &mut BootInfo) {
    let Some(framebuffer) = boot_info.framebuffer.as_mut() else {
        return;
    };

    let info = framebuffer.info();
    let slice = framebuffer.buffer_mut();
    let ptr = slice.as_mut_ptr();
    let len = slice.len();

    // SAFETY: widening this borrow to 'static is sound because the bootloader
    // maps the framebuffer for the entire life of the kernel and never reclaims
    // it. `framebuffer::init` is the sole consumer and stores it behind a `Once`,
    // so the buffer is installed exactly once and never aliased -- the borrow we
    // took from `boot_info` ends here, leaving `boot_info` usable by callers.
    let buffer: &'static mut [u8] = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    console::init_framebuffer(info, buffer);
}
