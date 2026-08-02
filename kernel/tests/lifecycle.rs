//! Resource lifecycle: what a thread gives back when it dies.
//!
//! Every case here corresponds to a defect that shipped. They are cheap to run
//! and each one fails loudly against the code as it was.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc::{self, EndpointId, Rights};
use panda_kernel::memory::{frame, paging};
use x86_64::VirtAddr;
use panda_kernel::sched::ThreadId;
use panda_kernel::{arch::x86_64::halt_loop, gbm, sched, testing, userspace, BOOTLOADER_CONFIG};

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

fn demo_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_probe(owner, userspace::probe::DEMO, 0)
        .expect("failed to load the probe");
    // SAFETY: load_probe mapped the entry user-executable, the stack
    // user-writable, and filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

fn run_to_completion(name: &'static str, entry: fn()) {
    let thread = sched::spawn(name, entry).expect("spawn failed");
    assert!(
        spin_until(|| !sched::is_alive(thread)),
        "{name} never finished"
    );
}

#[test_case]
fn more_user_programs_than_slots_can_run() {
    // Slots used to be indexed by thread id, which only ever increases, so the
    // seventeenth user program indexed past the end of the region and panicked
    // the kernel outright. Running comfortably more than MAX_SLOTS programs is
    // the whole test.
    let rounds = userspace::MAX_SLOTS + 6;
    for _ in 0..rounds {
        run_to_completion("slot-cycle", demo_thread);
    }
}

#[test_case]
fn slots_are_returned_when_a_thread_exits() {
    let baseline = userspace::slots_in_use();
    run_to_completion("slot-probe", demo_thread);

    assert!(
        spin_until(|| userspace::slots_in_use() <= baseline),
        "a finished user program kept its address-space slot; {} in use against \
         a baseline of {baseline}",
        userspace::slots_in_use()
    );
}

#[test_case]
fn a_user_program_returns_its_frames() {
    // Warm the slot first, then measure. The first program to use a slot also
    // causes intermediate page tables to be allocated for that address range,
    // and those are never reclaimed -- `unmap_and_free` releases the leaf frame
    // and leaves the tables above it standing. That is a separate leak, recorded
    // in the README; measuring across a warm slot isolates the thing this case
    // is actually about, which is whether a program's own pages come back.
    run_to_completion("frame-warmup", demo_thread);
    for _ in 0..50 {
        sched::yield_now();
    }

    let baseline = frame::with(|allocator| allocator.free_frames());
    run_to_completion("frame-probe", demo_thread);

    assert!(
        spin_until(|| frame::with(|allocator| allocator.free_frames()) >= baseline),
        "a user program leaked physical frames: {} free against a baseline of \
         {baseline}",
        frame::with(|allocator| allocator.free_frames())
    );
}

static PARKED: AtomicU64 = AtomicU64::new(0);

fn park_forever() {
    PARKED.store(1, Ordering::Release);
    loop {
        sched::yield_now();
    }
}

#[test_case]
fn kernel_stacks_have_a_guard_page() {
    // A stack on the heap has nothing beneath it but more heap, so an overflow
    // writes silently into another allocation and surfaces later as corruption
    // with no path back to its cause. An unmapped page turns that into a fault
    // on the first byte past the end.
    PARKED.store(0, Ordering::Release);
    let thread = sched::spawn("guarded", park_forever).expect("spawn failed");
    assert!(
        spin_until(|| PARKED.load(Ordering::Acquire) == 1),
        "the probe thread never ran"
    );

    let (guard, bottom) = sched::stack_bounds_of(thread).expect("the thread owns no stack");

    assert_eq!(
        guard + 4096,
        bottom,
        "the guard page does not sit immediately below the stack"
    );
    assert!(
        paging::flags(VirtAddr::new(bottom)).is_some(),
        "the stack itself is not mapped"
    );
    assert!(
        paging::flags(VirtAddr::new(guard)).is_none(),
        "the page below the stack is mapped, so an overflow would land in real \
         memory instead of faulting"
    );
}

static PEEK_TARGET: AtomicU64 = AtomicU64::new(0);

fn peek_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_probe(owner, userspace::probe::PEEK, PEEK_TARGET.load(Ordering::Acquire))
        .expect("failed to load the probe");
    // SAFETY: as above.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

#[test_case]
fn one_process_cannot_read_another_address_space() {
    // The boot thread maps a buffer, which lands at an address inside the user
    // region of *its* address space.
    let buffer = gbm::create(sched::current_id().unwrap(), 64, 64).expect("create failed");
    let address = gbm::map(sched::current_id().unwrap(), buffer).expect("map failed");

    // SAFETY: just mapped present and writable.
    unsafe { (address as *mut u64).write_volatile(0xFEED_FACE) };

    PEEK_TARGET.store(address, Ordering::Release);
    let before = panda_kernel::syscall::user_bytes_written();

    // A separate process is handed that exact address. With one shared address
    // space it would simply read it; with its own, there is nothing there.
    run_to_completion("peek", peek_thread);

    assert_eq!(
        panda_kernel::syscall::user_bytes_written(),
        before,
        "a user process read an address mapped only in another address space -- \
         processes are not isolated from each other"
    );
}

static ENDPOINT_MADE: AtomicU64 = AtomicU64::new(0);
static MAKER_ID: AtomicUsize = AtomicUsize::new(0);

fn endpoint_maker() {
    let me = sched::current_id().expect("no current thread");
    MAKER_ID.store(me.0, Ordering::Release);
    let endpoint = ipc::create(me, 4).expect("create failed");
    ENDPOINT_MADE.store(endpoint.0, Ordering::Release);
}

#[test_case]
fn capabilities_do_not_outlive_their_thread() {
    ENDPOINT_MADE.store(0, Ordering::Release);
    run_to_completion("endpoint-maker", endpoint_maker);

    let endpoint = EndpointId(ENDPOINT_MADE.load(Ordering::Acquire));
    let maker = ThreadId(MAKER_ID.load(Ordering::Acquire));
    assert_ne!(endpoint.0, 0, "the maker never created an endpoint");

    assert!(
        spin_until(|| ipc::rights_of(maker, endpoint) == Rights::NONE),
        "a dead thread still holds capabilities; the registry is keyed by thread \
         id and grows for the life of the system"
    );
}

static SHARED_BUFFER: AtomicU64 = AtomicU64::new(0);
static HOLDER_READY: AtomicU64 = AtomicU64::new(0);

fn buffer_owner() {
    let me = sched::current_id().expect("no current thread");
    let buffer = gbm::create(me, 64, 64).expect("create failed");
    SHARED_BUFFER.store(buffer.0, Ordering::Release);

    // Share with the boot thread, which outlives this one.
    let boot = ThreadId(0);
    gbm::share(me, boot, buffer).expect("share failed");
    HOLDER_READY.store(1, Ordering::Release);
}

#[test_case]
fn a_shared_buffer_outlives_the_thread_that_made_it() {
    // The natural client shape is: render a frame, hand it over, exit
    // immediately. Freeing on owner exit pulls the surface out from under the
    // consumer before it has drawn -- which showed up as the compositor blitting
    // from an error code and dying.
    HOLDER_READY.store(0, Ordering::Release);
    run_to_completion("buffer-owner", buffer_owner);
    assert_eq!(HOLDER_READY.load(Ordering::Acquire), 1);

    let buffer = gbm::BufferId(SHARED_BUFFER.load(Ordering::Acquire));
    let boot = sched::current_id().expect("no current thread");

    assert!(
        gbm::may_access(boot, buffer),
        "the buffer was destroyed with its creator, even though it was shared"
    );

    let info = gbm::info(boot, buffer).expect("the shared buffer is gone");
    assert_eq!(info.width, 64);
    assert_eq!(info.height, 64);

    // Still usable, not merely present.
    let address = gbm::map(boot, buffer).expect("could not map the shared buffer");
    // SAFETY: just mapped present and writable for the whole buffer.
    unsafe {
        let pixels = address as *mut u32;
        pixels.write_volatile(0x1234_5678);
        assert_eq!(pixels.read_volatile(), 0x1234_5678);
    }
}
