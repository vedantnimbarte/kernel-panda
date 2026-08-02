//! Global Descriptor Table and Task State Segment.
//!
//! In 64-bit mode segmentation is mostly vestigial, but the GDT is still needed
//! for two things: valid code and data segment selectors, and a TSS. The TSS is
//! the reason this module exists at all -- its Interrupt Stack Table lets the CPU
//! switch to a known-good stack when an exception fires.
//!
//! This must be loaded *before* the IDT. A double fault raised while the stack
//! pointer is invalid -- which is exactly what a stack overflow produces -- cannot
//! push an exception frame, so the CPU escalates straight to a triple fault and
//! the machine resets. The IST stack is what breaks that chain.

use x86_64::instructions::segmentation::{Segment, CS, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::sync::Lazy;

/// IST slot reserved for the double-fault handler. Referenced by `idt.rs`.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// 20 KiB. Only has to hold the handler's own frame plus the formatting
/// machinery it calls to print diagnostics.
const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5;

/// The System V ABI requires 16-byte stack alignment; an unaligned stack breaks
/// any handler that touches SSE registers, which `core::fmt` does.
#[repr(align(16))]
// The bytes are never read through this field -- only the CPU touches them, via
// the address handed to the IST. The field exists to reserve the space.
#[allow(dead_code)]
struct Stack([u8; DOUBLE_FAULT_STACK_SIZE]);

static mut DOUBLE_FAULT_STACK: Stack = Stack([0; DOUBLE_FAULT_STACK_SIZE]);

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        // `&raw const` rather than `&`: taking a reference to a `static mut`
        // is undefined behaviour if anything else ever aliases it. We only need
        // the address.
        let bottom = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK);
        // x86 stacks grow downward, so the CPU wants the *top* address.
        bottom + DOUBLE_FAULT_STACK_SIZE as u64
    };
    tss
});

struct Selectors {
    code: SegmentSelector,
    data: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    let tss = gdt.append(Descriptor::tss_segment(&TSS));
    (gdt, Selectors { code, data, tss })
});

/// Load the GDT, reload the segment registers, and install the TSS.
pub fn init() {
    let (gdt, selectors) = &*GDT;
    gdt.load();

    // SAFETY: the selectors were produced by `append` on the GDT loaded on the
    // line above, so each indexes a valid descriptor of the right type. Reloading
    // CS and SS from a live GDT is the architecturally prescribed sequence, and
    // the TSS descriptor points at a `'static` TaskStateSegment that outlives
    // every use.
    unsafe {
        CS::set_reg(selectors.code);
        SS::set_reg(selectors.data);
        load_tss(selectors.tss);
    }
}
