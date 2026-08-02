//! Kernel Panda boot binary.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use bootloader_api::{entry_point, BootInfo};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use panda_kernel::arch::x86_64::apic;
use panda_kernel::ipc::EndpointId;
use panda_kernel::{
    arch::x86_64::halt_loop, console, ipc, memory, pci, println, sched, sync, syscall, time,
    userspace, BOOTLOADER_CONFIG,
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    let boot_info = panda_kernel::init(boot_info);

    println!();
    println!("Kernel Panda v{}", env!("CARGO_PKG_VERSION"));
    println!("  serial console : COM1 @ 38400 8N1");
    println!(
        "  framebuffer    : {}",
        if console::framebuffer::is_available() {
            "online"
        } else {
            "not provided by bootloader"
        }
    );
    println!("  descriptor tbls: GDT + TSS + IDT loaded");
    println!(
        "  timer          : {}",
        if apic::is_initialised() {
            "Local APIC, periodic"
        } else {
            "unavailable"
        }
    );
    println!();

    memory::log_memory_map(&boot_info.memory_regions);
    println!();
    memory::log_usage();
    println!();

    // Proof that `alloc` is live: this allocates, grows, and reallocates.
    let squares: Vec<u64> = (1..=8u64).map(|n| n * n).collect();
    println!("alloc smoke test: {squares:?}");
    println!();

    // Proof the timer is live: without interrupts these would all read zero.
    // `hlt` parks the CPU until the next one arrives rather than spinning.
    println!("timer at {} Hz, waiting for ticks:", time::frequency_hz());
    for _ in 0..5 {
        let target = time::ticks() + time::frequency_hz() / 5;
        while time::ticks() < target {
            x86_64::instructions::hlt();
        }
        println!("  uptime {:>5} ms  ({} ticks)", time::uptime_ms(), time::ticks());
    }
    println!();

    // Both workers busy-wait rather than sleeping, and neither ever yields.
    // Their output interleaving is therefore entirely the timer's doing.
    println!("scheduler: spawning two workers that never yield");
    sched::spawn("worker-a", worker_a).expect("scheduler not running");
    sched::spawn("worker-b", worker_b).expect("scheduler not running");

    while !(WORKER_A_DONE.load(Ordering::Acquire) && WORKER_B_DONE.load(Ordering::Acquire)) {
        sched::yield_now();
    }

    println!(
        "  both workers finished; {} threads live, running as '{}'",
        sched::live_thread_count(),
        sched::current_name().unwrap_or("?")
    );
    println!();

    println!("ring 3: loading a user program and dropping privilege");
    let user = sched::spawn("user-demo", ring3_demo).expect("scheduler not running");
    while sched::is_alive(user) {
        sched::yield_now();
    }
    println!(
        "  user program exited after writing {} bytes through syscalls",
        syscall::user_bytes_written()
    );
    println!();

    println!("ipc: a blocking logger thread fed over a capability");
    let me = sched::current_id().expect("boot has no thread id");
    let endpoint = ipc::create(me, 8).expect("could not create an endpoint");
    DEMO_ENDPOINT.store(endpoint.0, Ordering::Release);

    // Spawn and grant without a preemption window between them, or the logger
    // could wake first and be turned away for want of a capability.
    let logger = sync::without_interrupts(|| {
        let id = sched::spawn("ipc-logger", ipc_logger).expect("scheduler not running");
        ipc::grant(me, id, endpoint, ipc::Rights::RECEIVE).expect("grant failed");
        id
    });

    for n in 1..=3u64 {
        ipc::send(
            me,
            endpoint,
            ipc::Message {
                tag: 0x100 + n,
                words: [n * 10, 0, 0, 0],
                sender: 0,
            },
        )
        .expect("send failed");
    }

    // A Ring 3 process sends over the same endpoint, holding only SEND.
    let user_sender = sync::without_interrupts(|| {
        let id = sched::spawn("user-ipc", ring3_ipc).expect("scheduler not running");
        ipc::grant(me, id, endpoint, ipc::Rights::SEND).expect("grant failed");
        id
    });
    while sched::is_alive(user_sender) {
        sched::yield_now();
    }

    // Zero tag tells the logger to stop.
    ipc::send(me, endpoint, ipc::Message::default()).expect("send failed");
    while sched::is_alive(logger) {
        sched::yield_now();
    }
    println!("  logger exited; endpoint drained to {}", ipc::queued(endpoint));
    println!();

    println!("shell: a ring 3 daemon reading the serial port");
    let shell = sched::spawn("shell", shell_thread).expect("scheduler not running");
    for line in ["help", "version", "hello", "exit"] {
        type_at_shell(shell, line);
    }
    while sched::is_alive(shell) {
        sched::yield_now();
    }
    println!();

    pci::log_devices();
    if let Some(display) = pci::find_display() {
        println!(
            "  display at {:02x}:{:02x}.{}",
            display.address.bus, display.address.device, display.address.function
        );
        for index in 0..6 {
            if let Some(bar) = pci::read_bar(display.address, index) {
                println!("    bar{index}: {bar:x?}");
            }
        }
    }
    println!();

    halt_loop()
}

static WORKER_A_DONE: AtomicBool = AtomicBool::new(false);
static WORKER_B_DONE: AtomicBool = AtomicBool::new(false);

/// Spin for `n` timer ticks without yielding.
///
/// Deliberately a busy wait rather than a sleep: the point of the demo is that
/// a thread which never gives up the CPU is taken off it anyway.
fn busy_wait_ticks(n: u64) {
    let target = time::ticks() + n;
    while time::ticks() < target {
        core::hint::spin_loop();
    }
}

fn worker_a() {
    for step in 1..=3 {
        println!("  [worker-a] step {step} of 3");
        busy_wait_ticks(15);
    }
    WORKER_A_DONE.store(true, Ordering::Release);
}

fn worker_b() {
    for step in 1..=3 {
        println!("  [worker-b] step {step} of 3");
        busy_wait_ticks(10);
    }
    WORKER_B_DONE.store(true, Ordering::Release);
}

/// Endpoint the demo threads talk over. Set before either is spawned.
static DEMO_ENDPOINT: AtomicU64 = AtomicU64::new(0);

/// Blocks on the endpoint and prints whatever turns up, until a zero tag ends it.
fn ipc_logger() {
    let endpoint = EndpointId(DEMO_ENDPOINT.load(Ordering::Acquire));
    let me = sched::current_id().expect("logger has no thread id");

    loop {
        let message = ipc::receive(me, endpoint).expect("receive failed");
        if message.tag == 0 {
            return;
        }
        println!(
            "  [logger] tag {:#06x} word0 {:>3} from thread {}",
            message.tag, message.words[0], message.sender
        );
    }
}

/// Sends one message from Ring 3 through a capability it was granted.
fn ring3_ipc() {
    let slot = sched::current_id().map_or(0, |id| id.0 as u64);
    let image = userspace::load_program(slot, userspace::ipc_program())
        .expect("failed to map the user image");
    let endpoint = DEMO_ENDPOINT.load(Ordering::Acquire);

    // SAFETY: `load_program` mapped the entry page user-executable and the stack
    // user-writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, endpoint) }
}

fn shell_thread() {
    let slot = sched::current_id().map_or(0, |id| id.0 as u64);
    let image = userspace::load_program(slot, userspace::shell_program())
        .expect("failed to map the shell image");
    // SAFETY: load_program mapped the entry user-executable and the stack
    // user-writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, 0) }
}

/// Type a line at the shell as though it had arrived on the serial port.
///
/// Waits for the shell to be parked in `read` first, so the transcript comes out
/// in order rather than racing the prompt.
fn type_at_shell(shell: sched::ThreadId, line: &str) {
    while sched::is_alive(shell) && !sched::is_blocked(shell) {
        sched::yield_now();
    }
    if !sched::is_alive(shell) {
        return;
    }
    for byte in line.bytes() {
        console::input::inject(byte);
    }
    console::input::inject(b'\n');
}

/// Loads the demo program into its own user slot and drops to Ring 3. Never
/// returns -- the program ends by calling `exit`.
fn ring3_demo() {
    let slot = sched::current_id().map_or(0, |id| id.0 as u64);
    let image = userspace::load_program(slot, userspace::demo_program())
        .expect("failed to map the user image");

    // SAFETY: `load_program` mapped both the entry page and the stack as
    // user-accessible, and the stack as writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, 0) }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!();
    println!("KERNEL PANIC: {info}");
    halt_loop()
}
