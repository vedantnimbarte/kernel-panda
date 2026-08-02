//! Global Descriptor Tables and Task State Segments, one set per CPU.
//!
//! In 64-bit mode segmentation is mostly vestigial, but the GDT is still needed
//! for three things: valid code and data selectors for each privilege level, a
//! TSS holding the stack the CPU switches to when it enters Ring 0, and the
//! Interrupt Stack Table.
//!
//! Every one of those is per-CPU. `privilege_stack_table[0]` names the stack
//! *this* processor traps onto, and the IST names the stack *this* processor
//! takes a double fault on. Sharing either between cores means two CPUs landing
//! on the same stack at the same time and quietly destroying each other's
//! frames -- a failure that looks like random corruption rather than a fault.
//!
//! This must be loaded before the IDT. A double fault raised while the stack
//! pointer is invalid -- which is exactly what a stack overflow produces --
//! cannot push an exception frame, so the CPU escalates straight to a triple
//! fault and the machine resets. The IST stack is what breaks that chain.
//!
//! ## Descriptor order
//!
//! `SYSCALL` derives SS from CS+8, and `SYSRET` derives its two selectors from a
//! single base +8 and +16. Keeping the conventional kernel-code, kernel-data,
//! user-data, user-code layout costs nothing today -- entry is through an
//! interrupt gate -- and leaves the door open to switching later.

use core::cell::UnsafeCell;

use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::smp::MAX_CPUS;

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

/// One double-fault stack per CPU.
static mut DOUBLE_FAULT_STACKS: [Stack; MAX_CPUS] =
    [const { Stack([0; DOUBLE_FAULT_STACK_SIZE]) }; MAX_CPUS];

/// Per-CPU tables.
///
/// `UnsafeCell` rather than plain statics because the descriptor needs each
/// TSS's address while later writes go through the same memory; going through
/// the cell keeps that from being an aliasing violation.
struct CpuTables {
    gdt: UnsafeCell<GlobalDescriptorTable>,
    tss: UnsafeCell<TaskStateSegment>,
    selectors: UnsafeCell<Option<Selectors>>,
}

// SAFETY: each entry is touched only by the CPU it belongs to, and only from
// `init_for_cpu` (once, during that CPU's start-up) and `set_kernel_stack`
// (with interrupts disabled). No entry is ever accessed by another processor.
unsafe impl Sync for CpuTables {}

static TABLES: [CpuTables; MAX_CPUS] = [const {
    CpuTables {
        gdt: UnsafeCell::new(GlobalDescriptorTable::new()),
        tss: UnsafeCell::new(TaskStateSegment::new()),
        selectors: UnsafeCell::new(None),
    }
}; MAX_CPUS];

#[derive(Clone, Copy)]
pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
    pub tss: SegmentSelector,
}

/// Build and load this CPU's descriptor tables.
///
/// `cpu` is the dense processor index; it selects which set of tables and which
/// double-fault stack this processor owns.
pub fn init_for_cpu(cpu: usize) {
    assert!(cpu < MAX_CPUS, "processor index {cpu} exceeds MAX_CPUS");
    let tables = &TABLES[cpu];

    // SAFETY: this runs once, on the processor that owns these tables, before
    // the GDT is loaded and therefore before the CPU can read the TSS. Nothing
    // else holds a reference to either.
    let selectors = unsafe {
        let tss = tables.tss.get();

        // `&raw mut` rather than a reference: taking one to a `static mut` is
        // undefined behaviour the moment anything else aliases it, and only the
        // address is wanted.
        let stack = &raw mut DOUBLE_FAULT_STACKS[cpu];
        let bottom = VirtAddr::from_ptr(stack);
        // x86 stacks grow downward, so the CPU wants the *top* address.
        (*tss).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            bottom + DOUBLE_FAULT_STACK_SIZE as u64;

        let gdt = tables.gdt.get();
        let kernel_code = (*gdt).append(Descriptor::kernel_code_segment());
        let kernel_data = (*gdt).append(Descriptor::kernel_data_segment());
        let user_data = (*gdt).append(Descriptor::user_data_segment());
        let user_code = (*gdt).append(Descriptor::user_code_segment());
        // The unchecked constructor takes a pointer, which is what allows the
        // TSS to keep changing after the descriptor is built.
        let tss_selector = (*gdt).append(Descriptor::tss_segment_unchecked(tss));

        let selectors = Selectors {
            kernel_code,
            kernel_data,
            user_data,
            user_code,
            tss: tss_selector,
        };
        *tables.selectors.get() = Some(selectors);

        (*gdt).load_unsafe();
        selectors
    };

    // SAFETY: the selectors index descriptors in the GDT loaded on the line
    // above. Reloading CS and SS from a live GDT is the architecturally
    // prescribed sequence.
    unsafe {
        CS::set_reg(selectors.kernel_code);
        SS::set_reg(selectors.kernel_data);
        DS::set_reg(selectors.kernel_data);
        ES::set_reg(selectors.kernel_data);
        load_tss(selectors.tss);
    }
}

/// Load the boot processor's tables.
pub fn init() {
    init_for_cpu(0);
}

/// This CPU's selectors.
pub fn selectors() -> Selectors {
    let cpu = crate::smp::cpu_index();
    // SAFETY: written once by `init_for_cpu` on this processor before anything
    // can call this, and never mutated afterwards.
    unsafe { (*TABLES[cpu].selectors.get()).expect("descriptor tables not loaded on this CPU") }
}

/// Point this CPU's `privilege_stack_table[0]` at `top`.
///
/// This is the stack the CPU switches to the instant it takes an interrupt while
/// executing Ring 3 code, so it must name the kernel stack belonging to the
/// thread currently on *this* processor. The scheduler updates it on every
/// switch; getting it wrong means a user thread's trap lands on some other
/// thread's stack and quietly corrupts it.
pub fn set_kernel_stack(top: VirtAddr) {
    let cpu = crate::smp::cpu_index();
    // SAFETY: the only mutation of this CPU's TSS, performed with interrupts
    // disabled by the scheduler, and no other processor ever touches this entry.
    unsafe {
        (*TABLES[cpu].tss.get()).privilege_stack_table[0] = top;
    }
}
