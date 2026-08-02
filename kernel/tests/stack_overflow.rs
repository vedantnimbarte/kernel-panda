//! The test that actually proves the Interrupt Stack Table works.
//!
//! A stack overflow pushes the stack pointer onto a guard page. The CPU then
//! tries to push an exception frame for the resulting page fault, which faults
//! again -- a double fault. If the double-fault handler ran on that same broken
//! stack it would fault a third time and the machine would reset.
//!
//! So: a *double* fault here means the IST switched stacks correctly. A triple
//! fault means it did not. The distinction is invisible without this test,
//! because both look like "it crashed".
//!
//! This one drives itself rather than using `#[test_case]` -- it never returns,
//! and it needs an IDT whose double-fault handler reports success instead of
//! panicking.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::arch::x86_64::gdt;
use panda_kernel::arch::x86_64::qemu::{self, ExitCode};
use panda_kernel::sync::Lazy;
use panda_kernel::{serial_print, serial_println, testing, BOOTLOADER_CONFIG};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

entry_point!(test_kernel_main, config = &BOOTLOADER_CONFIG);

fn test_kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    serial_print!("stack_overflow::double_fault_not_triple_fault ... ");

    // The GDT (and therefore the IST stack) comes from the kernel proper; only
    // the IDT is replaced.
    panda_kernel::console::init();
    gdt::init();
    TEST_IDT.load();

    provoke_stack_overflow();

    panic!("the stack overflow did not fault");
}

#[allow(unconditional_recursion)]
fn provoke_stack_overflow() {
    provoke_stack_overflow();

    // Recursing in tail position would be optimised into a plain jump and the
    // stack would never grow. A volatile read after the call forces the compiler
    // to keep a real frame alive across it.
    unsafe { core::ptr::read_volatile(&0u8) };
}

static TEST_IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    // SAFETY: index 0 of the IST was populated by `gdt::init` above with a
    // dedicated 20 KiB stack, which is the entire point of this test.
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }
    idt
});

extern "x86-interrupt" fn double_fault_handler(_frame: InterruptStackFrame, _code: u64) -> ! {
    serial_println!("[ok]");
    qemu::exit(ExitCode::Success)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    testing::panic_handler(info)
}
