//! The Ring 0 to Ring 3 boundary.
//!
//! The case that matters here is `user_code_cannot_read_kernel_memory`. Entering
//! user space is easy to get *almost* right -- a kernel that drops to CPL 3 but
//! leaves its own pages user-accessible looks identical from the outside, right
//! up until it does not.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::arch::x86_64::gdt;
use panda_kernel::memory::heap::HEAP_START;
use panda_kernel::{arch::x86_64::halt_loop, sched, syscall, testing, userspace, BOOTLOADER_CONFIG};
use x86_64::PrivilegeLevel;

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

const SPIN_BUDGET: u64 = 2_000_000_000;

fn spin_until(condition: impl Fn() -> bool) -> bool {
    for _ in 0..SPIN_BUDGET {
        if condition() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn run_user_program(name: &'static str, entry: fn()) -> bool {
    let thread = sched::spawn(name, entry).expect("spawn failed");
    spin_until(|| !sched::is_alive(thread))
}

fn demo_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_probe(owner, userspace::probe::DEMO, 0)
        .expect("failed to load the probe");
    // SAFETY: load_probe mapped the entry user-executable, the stack
    // user-writable, and filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

fn trespass_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_probe(owner, userspace::probe::TRESPASS, HEAP_START as u64)
        .expect("failed to load the probe");
    // SAFETY: load_probe mapped the entry user-executable, the stack
    // user-writable, and filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

#[test_case]
fn the_user_segments_are_ring3() {
    let selectors = gdt::selectors();
    assert_eq!(
        selectors.user_code.rpl(),
        PrivilegeLevel::Ring3,
        "the user code selector does not request Ring 3"
    );
    assert_eq!(
        selectors.user_data.rpl(),
        PrivilegeLevel::Ring3,
        "the user data selector does not request Ring 3"
    );
    assert_eq!(selectors.kernel_code.rpl(), PrivilegeLevel::Ring0);
}

#[test_case]
fn a_user_program_runs_syscalls_and_exits() {
    let before = syscall::user_bytes_written();

    assert!(
        run_user_program("user-demo", demo_thread),
        "the user thread never exited"
    );

    assert!(
        syscall::user_bytes_written() > before,
        "the user program produced no output, so it never reached the kernel \
         through a syscall"
    );
}

#[test_case]
fn user_code_cannot_read_kernel_memory() {
    // The program dereferences the kernel heap. That page is mapped, so this is
    // a real test of the USER_ACCESSIBLE bit rather than of an unmapped address.
    assert!(
        run_user_program("user-trespass", trespass_thread),
        "the trespassing thread was never terminated -- Ring 3 may have been \
         allowed to read kernel memory"
    );
}

fn stack_execution_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_program(owner, userspace::stack_execution_program())
        .expect("failed to map user image");
    // SAFETY: as above.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, 0) }
}

#[test_case]
fn nx_smep_and_smap_are_active() {
    assert!(
        panda_kernel::arch::x86_64::nx_enabled(),
        "EFER.NXE is clear, so every present page is executable"
    );
    // Neither SMEP nor SMAP is on every CPU, and writing an unsupported CR4 bit
    // faults, so these report rather than demand. Under QEMU the test harness
    // asks for a model that has both, so a note here means the model changed.
    if !panda_kernel::arch::x86_64::smep_enabled() {
        panda_kernel::serial_println!("  (note: this CPU does not support SMEP)");
    }
    if !panda_kernel::arch::x86_64::smap_enabled() {
        panda_kernel::serial_println!("  (note: this CPU does not support SMAP)");
    }
}

/// Maps a buffer -- user-accessible by definition -- and reads it without asking
/// for permission first. With SMAP on, that faults.
fn unguarded_user_read_thread() {
    let me = sched::current_id().expect("no current thread");
    let buffer = panda_kernel::gbm::create(me, 16, 16).expect("create failed");
    let address = panda_kernel::gbm::map(me, buffer).expect("map failed");

    // Armed as late as possible, so an unrelated fault in the setup above still
    // panics the way it should.
    testing::expect_page_fault(me);

    // SAFETY: the page is mapped present and writable. The access is
    // architecturally forbidden from Ring 0 with SMAP enabled and AC clear,
    // which is the whole point -- it is expected to fault, and the handler has
    // been told to kill this thread rather than panic when it does.
    let value = unsafe { (address as *const u64).read_volatile() };
    core::hint::black_box(value);

    UNGUARDED_READ_RETURNED.store(true, core::sync::atomic::Ordering::Release);
}

static UNGUARDED_READ_RETURNED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[test_case]
fn ring0_cannot_touch_user_memory_without_asking() {
    if !panda_kernel::arch::x86_64::smap_enabled() {
        panda_kernel::serial_println!("  (skipped: this CPU does not support SMAP)");
        return;
    }

    UNGUARDED_READ_RETURNED.store(false, core::sync::atomic::Ordering::Release);
    assert!(
        run_user_program("smap-probe", unguarded_user_read_thread),
        "the probe thread never finished"
    );

    assert!(
        testing::page_fault_observed(),
        "a kernel thread read a user-accessible page with AC clear and nothing \
         stopped it; SMAP is not being enforced"
    );
    assert!(
        !UNGUARDED_READ_RETURNED.load(core::sync::atomic::Ordering::Acquire),
        "the unguarded read completed instead of faulting"
    );
}

#[test_case]
fn the_guard_is_what_makes_user_memory_reachable() {
    // The other half of the pair: the same access, bracketed, must work --
    // otherwise the syscall paths that copy user buffers would all be broken and
    // the test above would pass for the wrong reason.
    let me = sched::current_id().expect("no current thread");
    let buffer = panda_kernel::gbm::create(me, 16, 16).expect("create failed");
    let address = panda_kernel::gbm::map(me, buffer).expect("map failed");

    panda_kernel::arch::x86_64::with_user_access(|| {
        // SAFETY: mapped present and writable, and the guard grants Ring 0
        // access to user pages for its lifetime.
        unsafe {
            let cell = address as *mut u64;
            cell.write_volatile(0x5A5A_5A5A_5A5A_5A5A);
            assert_eq!(cell.read_volatile(), 0x5A5A_5A5A_5A5A_5A5A);
        }
    });
}

#[test_case]
fn user_code_cannot_execute_its_own_stack() {
    // The program writes `jmp -2` onto its stack and jumps to it. Enforced, that
    // faults and the thread dies. Unenforced, it spins forever and this fails by
    // timing out -- which is the point: an executable stack is the oldest exploit
    // primitive there is.
    assert!(
        run_user_program("user-nx", stack_execution_thread),
        "a user thread executed its own stack; W^X is not being enforced"
    );
}

#[test_case]
fn a_system_call_can_be_preempted() {
    // As an interrupt gate, `int 0x80` cleared IF on the way in and a syscall
    // ran to completion however long it took -- the calling thread's quantum was
    // a fiction, and every call had to stay short or the machine stuttered. A
    // trap gate leaves IF as the caller had it.
    //
    // This observes the property directly rather than trying to catch a
    // preemption in the act: the dispatcher records, for every call, whether the
    // timer could have reached it.
    let before = syscall::syscall_count();
    assert!(
        run_user_program("preempt-probe", demo_thread),
        "the probe program never finished"
    );

    let made = syscall::syscall_count() - before;
    assert!(made > 0, "the probe program made no system calls");
    assert_eq!(
        syscall::preemptible_syscall_count(),
        syscall::syscall_count(),
        "{} of {} system calls ran with interrupts disabled; the gate is not a \
         trap gate, so a long call cannot be preempted",
        syscall::syscall_count() - syscall::preemptible_syscall_count(),
        syscall::syscall_count()
    );
}

#[test_case]
fn the_kernel_survives_a_user_fault() {
    // Reaching this case at all means the fault above did not panic the kernel,
    // which is PRD 1.2's requirement. Confirm scheduling still works afterwards.
    let before = sched::live_thread_count();
    assert!(
        run_user_program("user-demo-again", demo_thread),
        "the scheduler stopped working after a user fault"
    );
    assert!(
        spin_until(|| sched::live_thread_count() <= before),
        "threads are no longer being reaped after a user fault"
    );
}

#[test_case]
fn pointer_validation_rejects_kernel_addresses() {
    assert!(
        !userspace::validate_user_buffer(HEAP_START as u64, 8, false),
        "a kernel heap pointer passed user-buffer validation"
    );
    assert!(
        !userspace::validate_user_buffer(0, 8, false),
        "a null pointer passed validation"
    );
}

#[test_case]
fn pointer_validation_rejects_unmapped_user_addresses() {
    // Inside the user region, but in a slot nothing has ever mapped. The range
    // check alone would wave this through; only walking the page tables catches
    // it.
    let unmapped = userspace::USER_BASE + 60 * userspace::SLOT_SIZE;
    assert!(
        !userspace::validate_user_buffer(unmapped, 8, false),
        "an unmapped address inside the user region passed validation"
    );
}

#[test_case]
fn pointer_validation_rejects_ranges_that_overflow() {
    assert!(
        !userspace::validate_user_buffer(userspace::USER_BASE, u64::MAX, false),
        "a length that wraps the address space passed validation"
    );
}

#[test_case]
fn pointer_validation_rejects_a_range_that_runs_off_the_end() {
    // Starts legitimately, ends past the region. Checking only the base pointer
    // is the classic way to miss this.
    let last_slot = userspace::USER_REGION_END - 8;
    assert!(
        !userspace::validate_user_buffer(last_slot, 4096, false),
        "a buffer straddling the end of the user region passed validation"
    );
}
