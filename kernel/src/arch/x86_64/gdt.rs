//! Global Descriptor Table and Task State Segment.
//!
//! In 64-bit mode segmentation is mostly vestigial, but the GDT is still needed
//! for three things: valid code and data selectors for each privilege level, a
//! TSS holding the stack the CPU switches to when it enters Ring 0, and the
//! Interrupt Stack Table.
//!
//! This must be loaded *before* the IDT. A double fault raised while the stack
//! pointer is invalid -- which is exactly what a stack overflow produces --
//! cannot push an exception frame, so the CPU escalates straight to a triple
//! fault and the machine resets. The IST stack is what breaks that chain.
//!
//! ## Descriptor order
//!
//! The order below is not arbitrary. `SYSCALL` derives SS from CS+8, and
//! `SYSRET` derives its two selectors from a single base +8 and +16. Keeping the
//! conventional kernel-code, kernel-data, user-data, user-code layout costs
//! nothing today -- entry is through an interrupt gate -- and leaves the door
//! open to switching to `SYSCALL` later without shuffling every selector.

use core::cell::UnsafeCell;

use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
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

/// The TSS has to be mutable after the GDT is built: `privilege_stack_table[0]`
/// is the stack the CPU switches to when it takes an interrupt from Ring 3, and
/// that must point at the *current* thread's kernel stack, so it is rewritten on
/// every context switch.
///
/// An `UnsafeCell` rather than a `static mut` because the descriptor needs the
/// TSS's address while later writes go through the same memory; going through
/// the cell keeps that from being an aliasing violation.
#[repr(transparent)]
struct TssCell(UnsafeCell<TaskStateSegment>);

// SAFETY: the only writes are to `privilege_stack_table[0]`, from
// `set_kernel_stack`, which the scheduler calls with interrupts disabled on the
// single core this kernel supports. The CPU itself only ever reads the TSS.
unsafe impl Sync for TssCell {}

static TSS: TssCell = TssCell(UnsafeCell::new(TaskStateSegment::new()));

pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
    pub tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    // Populate the TSS before any descriptor is built from it.
    //
    // SAFETY: this closure runs once, before the GDT is loaded and therefore
    // before the CPU can read the TSS. Nothing else holds a reference to it.
    unsafe {
        let tss = TSS.0.get();
        let bottom = VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK);
        // x86 stacks grow downward, so the CPU wants the *top* address.
        (*tss).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            bottom + DOUBLE_FAULT_STACK_SIZE as u64;
    }

    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data = gdt.append(Descriptor::kernel_data_segment());
    let user_data = gdt.append(Descriptor::user_data_segment());
    let user_code = gdt.append(Descriptor::user_code_segment());

    // SAFETY: the TSS lives in a `static`, so this pointer is valid for the
    // lifetime of the kernel -- which is what the unchecked variant asks for.
    // The checked variant cannot be used because it wants a `&'static` shared
    // reference to memory we intend to keep mutating.
    let tss = gdt.append(unsafe { Descriptor::tss_segment_unchecked(TSS.0.get()) });

    (
        gdt,
        Selectors {
            kernel_code,
            kernel_data,
            user_data,
            user_code,
            tss,
        },
    )
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
        CS::set_reg(selectors.kernel_code);
        SS::set_reg(selectors.kernel_data);
        DS::set_reg(selectors.kernel_data);
        ES::set_reg(selectors.kernel_data);
        load_tss(selectors.tss);
    }
}

pub fn selectors() -> &'static Selectors {
    &GDT.1
}

/// Point `privilege_stack_table[0]` at `top`.
///
/// This is the stack the CPU switches to the instant it takes an interrupt while
/// executing Ring 3 code, so it must name the kernel stack belonging to the
/// thread that is currently on the CPU. The scheduler updates it on every switch;
/// getting it wrong means a user thread's trap lands on some other thread's
/// stack and quietly corrupts it.
pub fn set_kernel_stack(top: VirtAddr) {
    // SAFETY: the only mutation of the TSS, performed with interrupts disabled
    // on a single core, so the CPU cannot be reading the field concurrently.
    unsafe {
        (*TSS.0.get()).privilege_stack_table[0] = top;
    }
}
