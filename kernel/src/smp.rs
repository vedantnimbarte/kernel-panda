//! Symmetric multiprocessing: starting the other CPUs and keeping per-CPU state.
//!
//! An application processor comes out of reset in 16-bit real mode, so there is
//! no way to start one without a trampoline that walks it back up through
//! protected mode to long mode. That trampoline has to live below 1 MiB, at a
//! page-aligned physical address, and it has to be identity mapped -- once it
//! turns paging on it keeps executing at the same address it was already at.
//!
//! Everything the trampoline needs is written into the same page by the boot
//! processor: two GDTs, their pointers, and a parameter block. Nothing is
//! patched at runtime, because every address inside the page is a compile-time
//! constant offset from [`TRAMPOLINE_BASE`].

use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::acpi::Topology;
use crate::memory::paging;
use crate::sync::{without_interrupts, Mutex};

/// Where the trampoline is copied. Must be page aligned, below 1 MiB so real
/// mode can reach it, and outside anything the firmware still needs.
pub const TRAMPOLINE_BASE: u64 = 0x8000;

/// Ceiling on supported processors. Bounds every per-CPU array, so raising it
/// costs memory rather than correctness.
pub const MAX_CPUS: usize = 16;

// Offsets within the trampoline page. The assembly refers to these as absolute
// addresses, which is why they are constants rather than computed.
const GDT32_OFFSET: u64 = 0xF00;
const GDT64_OFFSET: u64 = 0xF18;
const GDT32_POINTER: u64 = 0xF30;
const GDT64_POINTER: u64 = 0xF38;
const PARAM_CR3: u64 = 0xF40;
const PARAM_STACK: u64 = 0xF48;
const PARAM_ENTRY: u64 = 0xF50;
const PARAM_INDEX: u64 = 0xF58;

/// Stack for each application processor while it boots and idles.
const AP_STACK_SIZE: usize = 32 * 1024;

core::arch::global_asm!(
    ".section .rodata",
    ".balign 16",
    ".global AP_TRAMPOLINE_START",
    "AP_TRAMPOLINE_START:",
    ".code16",
    "  cli",
    "  cld",
    "  xorw %ax, %ax",
    "  movw %ax, %ds",
    "  movw %ax, %es",
    "  movw %ax, %ss",
    // The GDT pointer sits at a fixed absolute address inside this page, which
    // real mode can reach because the whole page is below 64 KiB.
    "  lgdtl (0x8F30)",
    "  movl %cr0, %eax",
    "  orl $1, %eax",
    "  movl %eax, %cr0",
    // Far jump into 32-bit protected mode. The target is computed at assembly
    // time from the label's offset within this block, so nothing needs patching.
    "  ljmpl $0x08, $(0x8000 + 2f - AP_TRAMPOLINE_START)",
    ".code32",
    "2:",
    "  movw $0x10, %ax",
    "  movw %ax, %ds",
    "  movw %ax, %es",
    "  movw %ax, %ss",
    // Physical Address Extension, required before long mode.
    "  movl %cr4, %eax",
    "  orl $(1 << 5), %eax",
    "  movl %eax, %cr4",
    // The boot processor's page tables. Sharing them is what makes the kernel
    // mappings -- including this page -- valid the instant paging comes on.
    "  movl (0x8F40), %eax",
    "  movl %eax, %cr3",
    // EFER: long mode enable, and no-execute enable so this CPU honours the NX
    // bits already present in those tables. Without NXE here, every kernel data
    // page would fault on first touch.
    "  movl $0xC0000080, %ecx",
    "  rdmsr",
    "  orl $((1 << 8) | (1 << 11)), %eax",
    "  wrmsr",
    "  movl %cr0, %eax",
    "  orl $(1 << 31), %eax",
    "  movl %eax, %cr0",
    "  lgdtl (0x8F38)",
    "  ljmpl $0x08, $(0x8000 + 3f - AP_TRAMPOLINE_START)",
    ".code64",
    "3:",
    "  movq (0x8F48), %rsp",
    "  movq (0x8F58), %rdi",
    "  movq (0x8F50), %rax",
    "  callq *%rax",
    // The entry never returns; park if it somehow does.
    "4:",
    "  hlt",
    "  jmp 4b",
    ".code64",
    ".global AP_TRAMPOLINE_END",
    "AP_TRAMPOLINE_END:",
    ".section .text",
    options(att_syntax),
);

extern "C" {
    static AP_TRAMPOLINE_START: u8;
    static AP_TRAMPOLINE_END: u8;
}

/// Flat 32-bit code: base 0, limit 4 GiB, present, ring 0, executable.
const GDT32_CODE: u64 = 0x00CF_9A00_0000_FFFF;
/// Flat 32-bit data.
const GDT32_DATA: u64 = 0x00CF_9200_0000_FFFF;
/// 64-bit code. Bit 53 (L) set, bit 54 (D) clear -- setting both is illegal.
const GDT64_CODE: u64 = 0x00AF_9A00_0000_FFFF;
/// 64-bit data. Most fields are ignored in long mode.
const GDT64_DATA: u64 = 0x00AF_9200_0000_FFFF;

static TOPOLOGY: Mutex<Option<Topology>> = Mutex::new(None);

/// APIC id of each CPU, indexed by the dense CPU index the kernel uses.
///
/// A lock-free mirror of what ACPI reported, rather than the `Vec` it arrives
/// in. `cpu_index` is called from the timer handler, from every scheduler
/// operation and from every wake, and it used to take a lock and search a `Vec`
/// to answer -- putting a contended shared lock on the hottest path in the
/// kernel, which is exactly what the scheduler had just been restructured to
/// avoid. The fan-out below used to *clone* that `Vec`, so a TLB shootdown
/// allocated.
///
/// Written once, during `record_topology`, before any application processor
/// exists. `NO_CPU` marks a slot the firmware did not fill.
const NO_CPU: u8 = u8::MAX;
static APIC_ID_OF: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(NO_CPU) }; MAX_CPUS];

/// The reverse map: APIC id to dense index, biased by one so zero means
/// "not a processor we know about".
static INDEX_OF: [AtomicU8; 256] = [const { AtomicU8::new(0) }; 256];

/// How many entries of `APIC_ID_OF` the firmware filled.
static PROCESSORS: AtomicUsize = AtomicUsize::new(0);

/// How many processors have reported for duty, boot processor included.
static ONLINE: AtomicUsize = AtomicUsize::new(1);

/// Set by an application processor once it has finished its own setup.
static HANDSHAKE: AtomicU64 = AtomicU64::new(0);

pub fn record_topology(topology: Topology) {
    // Published before anything reads it: this runs during boot, on the boot
    // processor, with no application processor started and interrupts off.
    let count = topology.processors.len().min(MAX_CPUS);
    for (index, apic_id) in topology.processors.iter().take(MAX_CPUS).enumerate() {
        APIC_ID_OF[index].store(*apic_id, Ordering::Relaxed);
        INDEX_OF[*apic_id as usize].store(index as u8 + 1, Ordering::Relaxed);
    }
    PROCESSORS.store(count, Ordering::Release);

    without_interrupts(|| {
        *TOPOLOGY.lock() = Some(topology);
    });
}

/// What the firmware reported, if it was readable.
///
/// Cloned rather than borrowed: the caller would otherwise hold the lock for
/// as long as it looked at the result, and one of them programs an I/O APIC.
pub fn topology() -> Option<Topology> {
    without_interrupts(|| TOPOLOGY.lock().clone())
}

/// Processors the firmware reported, boot processor included.
pub fn processor_count() -> usize {
    PROCESSORS.load(Ordering::Acquire).max(1)
}

/// Processors that have actually come up.
pub fn online_count() -> usize {
    ONLINE.load(Ordering::Acquire)
}

/// Bit per CPU index, set once that processor can take an interrupt.
///
/// A processor is only in here after it has its own IDT. Sending it a vector
/// before that point faults on a CPU with nowhere to record the fault, which
/// takes it out entirely -- so the set exists to be the thing IPIs are addressed
/// from, rather than the "all except self" shorthand.
static ONLINE_MASK: AtomicU64 = AtomicU64::new(1);

/// Call `f` with the index and APIC id of every online processor except this
/// one.
///
/// Takes no lock and allocates nothing. It is reached from TLB shootdown, which
/// runs with the scheduler mid-switch and sometimes with interrupts already
/// masked; cloning a `Vec` to answer it meant a page unmap could end up inside
/// the heap allocator.
pub fn for_each_other_online_processor(mut f: impl FnMut(usize, u8)) {
    let mask = ONLINE_MASK.load(Ordering::Acquire);
    if mask.count_ones() <= 1 {
        return;
    }
    let self_index = cpu_index();

    let count = PROCESSORS.load(Ordering::Acquire).min(MAX_CPUS);
    for (index, slot) in APIC_ID_OF.iter().enumerate().take(count) {
        let apic_id = slot.load(Ordering::Relaxed);
        if index != self_index && apic_id != NO_CPU && mask & (1 << index) != 0 {
            f(index, apic_id);
        }
    }
}

/// This CPU's dense index.
///
/// Derived from the Local APIC id rather than stored somewhere per-CPU, because
/// there is nowhere per-CPU to store it until this function already works. The
/// APIC id register is a single uncached read.
pub fn cpu_index() -> usize {
    let apic_id = crate::arch::x86_64::apic::id();
    match INDEX_OF[apic_id as usize].load(Ordering::Relaxed) {
        // Zero means the table has not been filled in yet, which is true for
        // every call before ACPI is parsed. There is only one processor running
        // at that point, and it is the boot one.
        0 => 0,
        biased => biased as usize - 1,
    }
}

/// Start every application processor the firmware reported.
///
/// # Safety
///
/// Call once, from the boot processor, after the APIC, the heap and the
/// scheduler are up.
pub unsafe fn start_application_processors() -> usize {
    let count = PROCESSORS.load(Ordering::Acquire).min(MAX_CPUS);
    if count <= 1 {
        return 0;
    }
    // SAFETY: called once during boot, before anything else can touch the
    // trampoline page.
    unsafe { install_trampoline() };

    let boot_apic_id = crate::arch::x86_64::apic::id();
    let mut started = 0;

    for (index, slot) in APIC_ID_OF.iter().enumerate().take(count) {
        let apic_id = slot.load(Ordering::Relaxed);
        if apic_id == boot_apic_id || apic_id == NO_CPU {
            continue;
        }

        // A dedicated stack, leaked deliberately: it is this CPU's for as long
        // as the machine runs, and nothing will ever free it.
        let stack = alloc::vec![0u8; AP_STACK_SIZE].into_boxed_slice();
        let stack_top = (stack.as_ptr() as u64 + AP_STACK_SIZE as u64) & !0xF;
        core::mem::forget(stack);

        // SAFETY: the trampoline page is installed and the parameters below are
        // exactly what it reads.
        unsafe {
            write_parameter(PARAM_STACK, stack_top);
            write_parameter(PARAM_INDEX, index as u64);
        }
        HANDSHAKE.store(0, Ordering::Release);

        // SAFETY: `apic_id` came from the firmware's own processor list.
        unsafe { crate::arch::x86_64::apic::start_processor(apic_id, TRAMPOLINE_BASE) };

        // Wait for the CPU to say it is up. Bounded, so one processor that
        // refuses to start does not stop the machine booting.
        let mut spins = 0u64;
        while HANDSHAKE.load(Ordering::Acquire) == 0 {
            spins += 1;
            if spins > 200_000_000 {
                crate::println!("warning: processor {apic_id} did not start");
                break;
            }
            core::hint::spin_loop();
        }
        if HANDSHAKE.load(Ordering::Acquire) != 0 {
            started += 1;
        }
    }

    started
}

/// Copy the trampoline into low memory and fill in everything it reads.
///
/// # Safety
///
/// Call once, before any processor is started.
unsafe fn install_trampoline() {
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(TRAMPOLINE_BASE));
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(TRAMPOLINE_BASE));

    // Identity mapped, and it has to be: the moment the trampoline enables
    // paging it carries on executing at the address it is already at. Anything
    // else and the next instruction fetch faults on a CPU with no fault handler.
    //
    // Not executable-restricted and not user-accessible; it is kernel code that
    // happens to live at a low address.
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    // SAFETY: the frame allocator holds the whole first megabyte back precisely
    // so this page is never handed to anything else. It is reported as usable
    // memory and would otherwise be allocated like any other frame -- which is
    // exactly what happened before that reservation existed.
    let _ = unsafe { paging::map_to_frame_in(&paging::kernel_space(), page, frame, flags) };

    let start = &raw const AP_TRAMPOLINE_START;
    let end = &raw const AP_TRAMPOLINE_END;
    let length = end as usize - start as usize;
    assert!(
        length as u64 <= GDT32_OFFSET,
        "the trampoline overruns its own data area"
    );

    // SAFETY: the page is mapped writable, and the source is a static blob in
    // the kernel image.
    unsafe {
        core::ptr::copy_nonoverlapping(start, TRAMPOLINE_BASE as *mut u8, length);

        // Two GDTs: one to reach 32-bit protected mode, one to reach long mode.
        write_parameter(GDT32_OFFSET, 0);
        write_parameter(GDT32_OFFSET + 8, GDT32_CODE);
        write_parameter(GDT32_OFFSET + 16, GDT32_DATA);
        write_parameter(GDT64_OFFSET, 0);
        write_parameter(GDT64_OFFSET + 8, GDT64_CODE);
        write_parameter(GDT64_OFFSET + 16, GDT64_DATA);

        // `lgdt` in 32-bit mode reads a 16-bit limit then a 32-bit base.
        write_gdt_pointer(GDT32_POINTER, TRAMPOLINE_BASE + GDT32_OFFSET);
        write_gdt_pointer(GDT64_POINTER, TRAMPOLINE_BASE + GDT64_OFFSET);

        // The boot processor's page tables, so kernel mappings are live the
        // instant the AP turns paging on.
        let (cr3, _) = x86_64::registers::control::Cr3::read();
        write_parameter(PARAM_CR3, cr3.start_address().as_u64());
        write_parameter(PARAM_ENTRY, application_processor_entry as *const () as u64);
    }
}

/// # Safety
///
/// The trampoline page must be mapped writable, and `offset` inside it.
unsafe fn write_parameter(offset: u64, value: u64) {
    // SAFETY: forwarded from this function's contract.
    unsafe { core::ptr::write_volatile((TRAMPOLINE_BASE + offset) as *mut u64, value) };
}

/// # Safety
///
/// As `write_parameter`.
unsafe fn write_gdt_pointer(offset: u64, table: u64) {
    // Written as bytes rather than a u16 then a u32. The descriptor the CPU
    // wants is a 16-bit limit immediately followed by a 32-bit base, which puts
    // the base at a two-byte boundary -- a `write_volatile` of a `u32` there is
    // misaligned, which is undefined behaviour and panics in a debug build.
    //
    // The limit is one less than the table's length, as the architecture
    // defines it: three descriptors of eight bytes.
    let limit: u16 = 24 - 1;
    let mut descriptor = [0u8; 6];
    descriptor[..2].copy_from_slice(&limit.to_le_bytes());
    descriptor[2..].copy_from_slice(&(table as u32).to_le_bytes());

    // SAFETY: forwarded from this function's contract.
    unsafe {
        core::ptr::copy_nonoverlapping(
            descriptor.as_ptr(),
            (TRAMPOLINE_BASE + offset) as *mut u8,
            descriptor.len(),
        );
    }
}

/// Where an application processor arrives, in long mode, on its own stack.
///
/// From here it looks like any other CPU: its own GDT and TSS, the shared IDT,
/// its own Local APIC, and then into the scheduler.
extern "C" fn application_processor_entry(index: u64) -> ! {
    // Descriptor tables first. The TSS is per-CPU because it holds the stack
    // this processor switches to on a privilege change -- sharing one would have
    // two CPUs taking traps onto the same stack.
    crate::arch::x86_64::gdt::init_for_cpu(index as usize);
    crate::arch::x86_64::idt::init();

    // NX and SMEP are per-CPU: EFER and CR4 are not shared. The trampoline set
    // NXE already, since the page tables it loaded have NX bits in them, but
    // SMEP has to be set here.
    crate::arch::x86_64::enable_memory_protections();

    // Each processor drives its own Local APIC and its own timer.
    // SAFETY: runs once per CPU, with interrupts disabled.
    let _ = unsafe { crate::arch::x86_64::apic::init_for_secondary() };

    // Published only now, with descriptor tables and the APIC in place. Before
    // this point an IPI addressed here would land on a processor that cannot
    // handle it.
    ONLINE_MASK.fetch_or(1 << index, Ordering::AcqRel);
    ONLINE.fetch_add(1, Ordering::AcqRel);
    HANDSHAKE.store(index + 1, Ordering::Release);

    crate::sched::adopt_secondary_cpu();

    x86_64::instructions::interrupts::enable();
    crate::arch::x86_64::halt_loop()
}
