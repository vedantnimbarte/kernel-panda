//! Random bytes: from the processor's generator, through the kernel's, to Ring 3.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(panda_kernel::testing::runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::{entry_point, BootInfo};
use panda_kernel::ipc;
use panda_kernel::sched::{self, ThreadId};
use panda_kernel::{arch::x86_64::halt_loop, random, syscall, testing, userspace, BOOTLOADER_CONFIG};

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

fn me() -> ThreadId {
    sched::current_id().expect("no thread")
}

#[test_case]
fn the_processor_has_a_generator() {
    // xtask asks QEMU for RDRAND and RDSEED; without them every draw below
    // would come from the timing fallback.
    assert!(random::has_hardware_source(), "no RDRAND or RDSEED; is xtask passing +rdrand?");
}

#[test_case]
fn draws_differ_and_are_evenly_spread() {
    let (mut first, mut second) = ([0u8; 64], [0u8; 64]);
    random::fill(&mut first);
    random::fill(&mut second);
    assert_ne!(first, second, "two draws came back the same");
    assert_ne!(first, [0; 64], "a draw came back zero");

    // Over 64 KiB, the share of set bits is within a whisker of a half for
    // anything random, and far outside it for a stuck or broken generator.
    let mut bytes = [0u8; 4096];
    let mut ones = 0u64;
    for _ in 0..16 {
        random::fill(&mut bytes);
        ones += bytes.iter().map(|byte| byte.count_ones() as u64).sum::<u64>();
    }
    let bits = 16 * 4096 * 8;
    assert!(ones.abs_diff(bits / 2) < bits / 100, "{ones} of {bits} bits set");
}

static REPORT: AtomicU64 = AtomicU64::new(0);

fn probe_thread() {
    let image = userspace::load_probe(me(), userspace::probe::RANDOM, REPORT.load(Ordering::Acquire))
        .expect("failed to load the probe");
    // SAFETY: load_probe mapped the entry executable, the stack writable, and
    // filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

#[test_case]
fn ring_3_draws_through_a_system_call() {
    let endpoint = ipc::create(me(), 4).expect("create failed");
    REPORT.store(endpoint.0, Ordering::Release);
    panda_kernel::sync::without_interrupts(|| {
        let id = sched::spawn("random-probe", probe_thread).expect("spawn failed");
        ipc::grant(me(), id, endpoint, ipc::Rights::SEND).expect("grant failed");
    });
    let [first, second, filled, refused] = ipc::receive(me(), endpoint).expect("receive failed").words;

    assert_eq!(filled, 8, "the call did not fill the buffer");
    assert_ne!(first, second, "two draws from Ring 3 came back the same");
    assert_ne!(first, 0);
    assert_eq!(refused, syscall::Error::InvalidArgument as i64 as u64, "an oversized request was not refused");
}
