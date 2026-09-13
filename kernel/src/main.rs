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
    arch::x86_64::halt_loop, console, device, gbm, ipc, memory, net, pci, println, sched, sync, syscall, time,
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
        "  protections    : NX {}, SMEP {}, SMAP {}",
        if apic::is_initialised() && panda_kernel::arch::x86_64::nx_enabled() {
            "on"
        } else {
            "off"
        },
        if panda_kernel::arch::x86_64::smep_enabled() {
            "on"
        } else {
            "unsupported"
        },
        if panda_kernel::arch::x86_64::smap_enabled() {
            "on"
        } else {
            "unsupported"
        }
    );
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
                sender_user: 0,
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

    println!("compositor: a ring 3 display server");
    let display = ipc::create(me, 16).expect("could not create an endpoint");
    DISPLAY_ENDPOINT.store(display.0, Ordering::Release);

    let compositor = sync::without_interrupts(|| {
        let id = sched::spawn("compositor", compositor_thread).expect("scheduler not running");
        ipc::grant(me, id, display, ipc::Rights::RECEIVE).expect("grant failed");
        // Only this thread may reach the screen. Nothing else spawned below can
        // ask for the framebuffer and be handed it.
        gbm::allow_display_server(id);
        id
    });
    while sched::is_alive(compositor) && !sched::is_blocked(compositor) {
        sched::yield_now();
    }
    println!("  compositor mapped the scanout buffer and is waiting for surfaces");

    // The input daemon is the PS/2 driver. It gets the controller's ports and
    // interrupt lines, and the compositor is told -- by the kernel, which no
    // client can impersonate -- that its key and pointer events are real.
    let input = sync::without_interrupts(|| {
        let id = sched::spawn("input", input_daemon_thread).expect("scheduler not running");
        ipc::grant(me, id, display, ipc::Rights::SEND).expect("grant failed");
        device::grant_ps2_controller(id);
        id
    });
    ipc::notify(
        display,
        ipc::Message {
            tag: INPUT_SOURCE,
            words: [input.0 as u64, 0, 0, 0],
            sender: 0,
            sender_user: 0,
        },
    )
    .expect("could not name the input daemon");

    // Blue, green and red, side by side. The colour is written low byte first
    // and the display is BGR, so 0x0000FF lands as blue.
    for (colour, x, y, name) in [
        (0x0000FFu64, 120u64, 260u64, "blue"),
        (0x00FF00, 260, 260, "green"),
        (0xFF0000, 400, 260, "red"),
    ] {
        *CLIENT_PARAMS.lock() = [
            colour,
            x,
            y,
            display.0,
            120,
            90,
            compositor.0 as u64,
            gbm::bytes_per_pixel() as u64,
        ];
        let client = sync::without_interrupts(|| {
            let id = sched::spawn("client", client_thread).expect("scheduler not running");
            ipc::grant(me, id, display, ipc::Rights::SEND).expect("grant failed");
            id
        });
        while sched::is_alive(client) {
            sched::yield_now();
        }
        println!("  presented a {name} surface at ({x}, {y})");
    }

    // Escape, pressed through the keyboard controller, reaches the input daemon
    // as an interrupt; it forwards a shutdown to the compositor. Nothing in
    // Ring 0 tells either of them to stop.
    while sched::is_alive(input) && !sched::is_blocked(input) {
        sched::yield_now();
    }
    panda_kernel::testing::inject_ps2(false, 0x01);
    while sched::is_alive(input) || sched::is_alive(compositor) {
        sched::yield_now();
    }
    println!("  input daemon sent shutdown; both daemons exited");
    println!();

    println!("net: a ring 3 stack pings the gateway");
    net_demo(me);
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
    let owner = sched::current_id().expect("no current thread");
    let endpoint = DEMO_ENDPOINT.load(Ordering::Acquire);
    let image = userspace::load_probe(owner, userspace::probe::IPC, endpoint)
        .expect("failed to load the probe");

    // SAFETY: `load_probe` mapped the entry user-executable and the stack
    // user-writable, and filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

static DISPLAY_ENDPOINT: AtomicU64 = AtomicU64::new(0);

/// `input::TAG_INPUT_SOURCE` in the user library.
const INPUT_SOURCE: u64 = 5;
static CLIENT_PARAMS: sync::Mutex<[u64; 8]> = sync::Mutex::new([0; 8]);

static NET_CONTROL: AtomicU64 = AtomicU64::new(0);

/// Start the network daemon and have it ping QEMU's gateway.
fn net_demo(me: sched::ThreadId) {
    if net::mac().is_none() {
        println!("  no network card");
        return;
    }

    let control = ipc::create(me, 32).expect("could not create an endpoint");
    NET_CONTROL.store(control.0, Ordering::Release);
    let stack = sync::without_interrupts(|| {
        let id = sched::spawn("net", net_thread).expect("scheduler not running");
        let rights = ipc::Rights::SEND.union(ipc::Rights::RECEIVE);
        ipc::grant(me, id, control, rights).expect("grant failed");
        // The one thread allowed to put frames on the wire and see them arrive.
        net::allow_stack(id);
        id
    });
    while sched::is_alive(stack) && !sched::is_blocked(stack) {
        sched::yield_now();
    }

    let reply = ipc::create(me, 4).expect("could not create an endpoint");
    ipc::grant(me, stack, reply, ipc::Rights::SEND).expect("grant failed");

    const GATEWAY: u64 = 0x0A00_0202;
    let started = time::uptime_ms();
    let ping = ipc::Message {
        tag: 1,
        words: [GATEWAY, reply.0, 1, 0],
        sender: 0,
        sender_user: 0,
    };
    ipc::send(me, control, ping).expect("send failed");

    // Bounded: a machine without a network behind the card should still boot
    // through to the shell.
    while ipc::queued(reply) == 0 && time::uptime_ms() < started + 3000 {
        sched::yield_now();
    }
    if ipc::queued(reply) > 0 {
        let _ = ipc::receive(me, reply);
        println!(
            "  reply from 10.0.2.2 in {} ms, parsed entirely in Ring 3",
            time::uptime_ms() - started
        );
    } else {
        println!("  no reply from 10.0.2.2 within three seconds");
    }
}

fn net_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::NET_ELF).expect("failed to load the network daemon");
    // 10.0.2.15/24 behind 10.0.2.2: QEMU's user-mode network.
    let parameters = [NET_CONTROL.load(Ordering::Acquire), 0x0A00_020F, 0x0A00_0202, 0xFFFF_FF00];
    // SAFETY: the parameter page just mapped for a program not yet running.
    unsafe { userspace::write_parameters(image.data, &parameters) };
    // SAFETY: load_elf mapped the entry user-executable and the stack writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

fn compositor_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::COMPOSITOR_ELF)
        .expect("failed to map the compositor");
    let endpoint = DISPLAY_ENDPOINT.load(Ordering::Acquire);
    // SAFETY: load_program mapped the entry user-executable and the stack
    // user-writable.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, endpoint) }
}

fn input_daemon_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::INPUT_ELF)
        .expect("failed to map the input daemon");
    let endpoint = DISPLAY_ENDPOINT.load(Ordering::Acquire);
    // SAFETY: as above.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, endpoint) }
}

fn client_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::CLIENT_ELF)
        .expect("failed to map the client");

    let params = *CLIENT_PARAMS.lock();
    // SAFETY: `image.data` is the writable data page just mapped for this
    // program, which is not running yet.
    unsafe { userspace::write_parameters(image.data, &params) };
    // SAFETY: as above.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

fn shell_thread() {
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_elf(owner, userspace::SHELL_ELF)
        .expect("failed to load the shell");
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
    let owner = sched::current_id().expect("no current thread");
    let image = userspace::load_probe(owner, userspace::probe::DEMO, 0)
        .expect("failed to load the probe");

    // SAFETY: `load_probe` mapped the entry user-executable and the stack
    // user-writable, and filled in the parameter page.
    unsafe { userspace::enter_ring3(image.entry, image.stack_top, image.data.as_u64()) }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    panda_kernel::crash::panic(info)
}
