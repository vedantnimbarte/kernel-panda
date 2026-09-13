//! Host-side build driver for Kernel Panda.
//!
//! ```text
//! cargo xtask build [--release]           compile the kernel, emit boot images
//! cargo xtask run   [--release] [--uefi]  compile, then boot in QEMU with a display
//! cargo xtask test  [--release]           boot every kernel/tests/*.rs and assert on the exit code
//! cargo xtask runner <elf> [--uefi]       wrap one kernel ELF in an image, boot it headless
//! ```
//!
//! `runner` is the subcommand cargo itself invokes, via the `runner` key in
//! kernel/.cargo/config.toml. That key points at this *already-compiled binary*
//! rather than at `cargo run -p xtask`, because a nested cargo launched from
//! kernel/ would inherit kernel/.cargo/config.toml and try to build xtask for
//! `x86_64-unknown-none` with `build-std` -- which fails in confusing ways.

use std::{
    env,
    ffi::OsString,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

/// QEMU maps a write of `v` to the isa-debug-exit port onto process exit code
/// `(v << 1) | 1`. The kernel writes 0x10 for success and 0x11 for failure.
const QEMU_EXIT_SUCCESS: i32 = (0x10 << 1) | 1; // 33
const QEMU_EXIT_FAILED: i32 = (0x11 << 1) | 1; // 35
/// "Boot me again": the runner starts the same kernel once more, with the same
/// crash disk, so a test can see what one boot leaves for the next.
const QEMU_EXIT_REBOOT: i32 = (0x12 << 1) | 1; // 37

/// Generous enough for a debug build under a cold QEMU, short enough that a
/// hung or triple-faulting kernel doesn't wedge CI.
const TEST_TIMEOUT: Duration = Duration::from_secs(90);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            eprintln!("usage: cargo xtask <build|run|test|runner> [options]");
            return ExitCode::FAILURE;
        }
    };

    let result = match cmd {
        "build" => cmd_build(rest),
        "run" => cmd_run(rest),
        "test" => cmd_test(rest),
        "runner" => cmd_runner(rest),
        other => Err(format!(
            "unknown subcommand {other:?}; expected build, run, test or runner"
        )),
    };

    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("xtask: {msg}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn cmd_build(args: &[String]) -> Result<ExitCode, String> {
    let kernel = build_kernel(has_flag(args, "--release"))?;
    let images = make_images(&kernel, has_flag(args, "--verbose-boot"))?;
    println!("kernel: {}", kernel.display());
    println!("bios:   {}", images.bios.display());
    println!("uefi:   {}", images.uefi.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_run(args: &[String]) -> Result<ExitCode, String> {
    let uefi = has_flag(args, "--uefi");
    // `--headless` plus `--timeout=N` makes the boot log capturable from a
    // script: no window, and the VM is killed once it has had long enough to
    // print everything. A kernel that ends in a halt loop never exits on its own.
    let headless = has_flag(args, "--headless");
    let timeout = flag_value(args, "--timeout")
        .map(|v| {
            v.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|_| format!("--timeout expects a number of seconds, got {v:?}"))
        })
        .transpose()?;

    let kernel = build_kernel(has_flag(args, "--release"))?;
    let images = make_images(&kernel, has_flag(args, "--verbose-boot"))?;
    let image = if uefi { &images.uefi } else { &images.bios };

    // Kept between runs, so a panic is still there to read on the next boot.
    let crash = crash_disk("crash.img", false)?;
    start_host_services();
    let code = match run_qemu(qemu_command(image, uefi, headless, &crash)?, timeout) {
        Ok(code) => code,
        // A timeout is the expected outcome when one was requested: the kernel
        // halts rather than exiting.
        Err(_) if timeout.is_some() => return Ok(ExitCode::SUCCESS),
        Err(e) => return Err(e),
    };
    // A normal window close, or a kernel that halts and is killed by the user,
    // is not a failure -- only report the debug-exit failure code as one.
    if code == QEMU_EXIT_FAILED {
        eprintln!("xtask: kernel signalled failure via isa-debug-exit");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_test(args: &[String]) -> Result<ExitCode, String> {
    let release = has_flag(args, "--release");

    // cargo will invoke `../target/release/xtask.exe runner <elf>` for each test
    // kernel, so that binary has to exist before we hand control over. When we
    // were launched through the `cargo xtask` alias it already does; this check
    // gives a clear error instead of a cryptic one when it doesn't.
    // The kernel embeds the user binaries, so they must exist before any test
    // kernel compiles.
    build_userland()?;

    let runner = runner_binary_path();
    if !runner.exists() {
        return Err(format!(
            "test runner not built at {}\nrun `cargo build -p xtask --release` first",
            runner.display()
        ));
    }

    let mut cmd = cargo_in_kernel();
    cmd.arg("test");
    if release {
        cmd.arg("--release");
    }
    let status = cmd
        .status()
        .map_err(|e| format!("failed to launch cargo test: {e}"))?;
    if status.success() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn cmd_runner(args: &[String]) -> Result<ExitCode, String> {
    let uefi = has_flag(args, "--uefi");
    let elf = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("runner requires a path to a kernel ELF")?;

    let images = make_images(Path::new(elf), has_flag(args, "--verbose-boot"))?;
    let image = if uefi { &images.uefi } else { &images.bios };

    let crash = crash_disk("crash-test.img", true)?;
    start_host_services();
    let mut code = run_qemu(qemu_command(image, uefi, true, &crash)?, Some(TEST_TIMEOUT))?;
    if code == QEMU_EXIT_REBOOT {
        println!("xtask: rebooting");
        code = run_qemu(qemu_command(image, uefi, true, &crash)?, Some(TEST_TIMEOUT))?;
    }

    match code {
        QEMU_EXIT_SUCCESS => Ok(ExitCode::SUCCESS),
        QEMU_EXIT_REBOOT => {
            eprintln!("xtask: test kernel asked for a second reboot; it gets one");
            Ok(ExitCode::FAILURE)
        }
        QEMU_EXIT_FAILED => {
            eprintln!("xtask: test kernel reported a failure");
            Ok(ExitCode::FAILURE)
        }
        // Anything else means the kernel never reached the debug-exit port:
        // a triple fault (QEMU dies on reset because of -no-reboot), a hang, or
        // a bootloader-level failure.
        other => {
            eprintln!(
                "xtask: qemu exited with {other}; the kernel never wrote to isa-debug-exit \
                 (expected {QEMU_EXIT_SUCCESS} for pass or {QEMU_EXIT_FAILED} for fail)"
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

/// Build the Ring 3 programs.
///
/// Must run before the kernel: the kernel embeds these binaries with
/// `include_bytes!`, so they have to exist on disk when it compiles. Always
/// release -- a debug user binary is several times larger for no benefit, and it
/// is carried inside the kernel image.
fn build_userland() -> Result<(), String> {
    let mut cmd = cargo_in(workspace_root().join("userland"));
    cmd.args(["build", "--release"]);
    let status = cmd
        .status()
        .map_err(|e| format!("failed to launch cargo for userland: {e}"))?;
    if !status.success() {
        return Err("userland build failed".into());
    }
    Ok(())
}

fn build_kernel(release: bool) -> Result<PathBuf, String> {
    build_userland()?;
    let mut cmd = cargo_in_kernel();
    cmd.arg("build");
    if release {
        cmd.arg("--release");
    }
    let status = cmd
        .status()
        .map_err(|e| format!("failed to launch cargo: {e}"))?;
    if !status.success() {
        return Err("kernel build failed".into());
    }

    let profile = if release { "release" } else { "debug" };
    let bin = kernel_dir()
        .join("target")
        .join("x86_64-unknown-none")
        .join(profile)
        .join("panda");
    if !bin.exists() {
        return Err(format!("kernel binary missing at {}", bin.display()));
    }
    Ok(bin)
}

/// A cargo invocation rooted *inside* kernel/.
///
/// The working directory matters more than it looks: cargo discovers
/// `.cargo/config.toml` by walking up from the cwd, not from `--manifest-path`.
/// Running this from the workspace root would silently skip the kernel's
/// build-std and target settings.
fn cargo_in_kernel() -> Command {
    cargo_in(kernel_dir())
}

fn cargo_in(directory: PathBuf) -> Command {
    let mut cmd = Command::new(env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")));
    cmd.current_dir(directory);
    // Don't leak the outer cargo's state into the inner one.
    cmd.env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTUP_TOOLCHAIN");
    cmd
}

struct Images {
    bios: PathBuf,
    uefi: PathBuf,
}

fn make_images(kernel: &Path, verbose_boot: bool) -> Result<Images, String> {
    if !kernel.exists() {
        return Err(format!("no kernel ELF at {}", kernel.display()));
    }

    // The bootloader has its own logger and by default narrates every ELF
    // segment it maps onto the same serial line the kernel uses. Silence it so
    // the console belongs to the kernel -- but keep it one flag away, because
    // when a boot fails before `kernel_main` this chatter is the only evidence
    // there is.
    // `BootConfig` is #[non_exhaustive], so it has to be built by mutation
    // rather than with a struct literal.
    #[allow(clippy::field_reassign_with_default)]
    let boot_config = {
        let mut c = bootloader::BootConfig::default();
        c.frame_buffer_logging = verbose_boot;
        c.serial_logging = verbose_boot;
        c
    };
    let out_dir = workspace_root().join("target").join("images");
    fs::create_dir_all(&out_dir).map_err(|e| format!("creating {}: {e}", out_dir.display()))?;

    // Test kernels carry a cargo-assigned hash in their filename, so distinct
    // test binaries never collide here.
    let stem = kernel
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "kernel".into());

    let bios = out_dir.join(format!("{stem}-bios.img"));
    let uefi = out_dir.join(format!("{stem}-uefi.img"));

    bootloader::BiosBoot::new(kernel)
        .set_boot_config(&boot_config)
        .create_disk_image(&bios)
        .map_err(|e| format!("building BIOS image: {e:#}"))?;
    bootloader::UefiBoot::new(kernel)
        .set_boot_config(&boot_config)
        .create_disk_image(&uefi)
        .map_err(|e| format!("building UEFI image: {e:#}"))?;

    Ok(Images { bios, uefi })
}

// ---------------------------------------------------------------------------
// QEMU
// ---------------------------------------------------------------------------

/// Bytes of each scratch disk handed to the guest.
///
/// Small on purpose: they are created fresh for every QEMU launch, and every
/// test kernel launches its own. Different sizes, because size is how a test
/// tells the SATA, NVMe and virtio disks apart without trusting enumeration
/// order.
const SCRATCH_DISK_BYTES: u64 = 16 * 1024 * 1024;
const NVME_DISK_BYTES: u64 = 32 * 1024 * 1024;
const VIRTIO_DISK_BYTES: u64 = 24 * 1024 * 1024;
const CRASH_DISK_BYTES: u64 = 2 * 1024 * 1024;

/// GPT type of the partition the kernel leaves crash records in. Must match
/// `crash::PARTITION_TYPE`.
const CRASH_PARTITION_TYPE: &[u8; 16] = b"KernelPandaCrash";

/// Contents of the file the TFTP server hands out. A network test compares
/// against this, so it is fixed here rather than generated.
const TFTP_FILE_CONTENTS: &str = "hello from the host, over TFTP\n";

/// A TCP service on the host, which the guest reaches at 10.0.2.2. Must match
/// `kernel/tests/net.rs`.
const HOST_TCP_PORT: u16 = 47110;
/// A host port QEMU forwards to the guest's port 80.
const FORWARDED_PORT: u16 = 47111;
/// A DNS server on the host, which the guest reaches at 10.0.2.2. Knows one
/// name. Must match `kernel/tests/net.rs`.
const HOST_DNS_PORT: u16 = 47153;

/// What network tests talk to on the host, for as long as this process lives:
///
/// * a TCP server that greets, answers one line with "you said: " and that
///   line, and closes;
/// * a client that keeps connecting to the guest's port 80 until something
///   there answers "hello from the host" with "hello from panda";
/// * a DNS server that says `panda.test` is 10.1.2.3 and that nothing else
///   exists.
///
/// Neither matters to a kernel that does not use the network. A port already
/// taken is left alone, and the test that needs it fails saying so.
fn start_host_services() {
    thread::spawn(|| {
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, HOST_TCP_PORT)) else {
            return;
        };
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let _ = stream.write_all(b"hello from the host, over TCP\n");
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_ok() {
                    let _ = stream.write_all(format!("you said: {line}").as_bytes());
                }
            });
        }
    });

    thread::spawn(|| {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, HOST_DNS_PORT)) else {
            return;
        };
        let mut query = [0u8; 512];
        while let Ok((length, client)) = socket.recv_from(&mut query) {
            if let Some(answer) = dns_answer(&query[..length]) {
                let _ = socket.send_to(&answer, client);
            }
        }
    });

    thread::spawn(|| {
        let guest = SocketAddr::from((Ipv4Addr::LOCALHOST, FORWARDED_PORT));
        loop {
            thread::sleep(Duration::from_millis(500));
            let Ok(mut stream) = TcpStream::connect_timeout(&guest, Duration::from_secs(1)) else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut answer = Vec::new();
            if stream.write_all(b"hello from the host\n").is_ok()
                && stream.read_to_end(&mut answer).is_ok()
                && answer == b"hello from panda\n"
            {
                return;
            }
        }
    });
}

/// The directory QEMU's TFTP server serves, holding `hello.txt`.
fn tftp_root() -> Result<PathBuf, String> {
    let directory = workspace_root().join("target").join("images").join("tftp");
    fs::create_dir_all(&directory).map_err(|e| format!("could not create {directory:?}: {e}"))?;
    let file = directory.join("hello.txt");
    fs::write(&file, TFTP_FILE_CONTENTS).map_err(|e| format!("could not write {file:?}: {e}"))?;
    Ok(directory)
}

/// Create an empty raw disk image for the guest to write to.
///
/// Zero-filled rather than left as whatever was on disk, so a test reading a
/// sector it never wrote sees a defined value.
fn scratch_disk(name: &str, bytes: u64) -> Result<PathBuf, String> {
    let path = workspace_root().join("target").join("images").join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create {parent:?}: {e}"))?;
    }

    let file = fs::File::create(&path).map_err(|e| format!("could not create {path:?}: {e}"))?;
    file.set_len(bytes)
        .map_err(|e| format!("could not size {path:?}: {e}"))?;
    Ok(path)
}

/// A disk holding one crash partition, the way the kernel's own
/// `write_single_partition_gpt` lays it out. Reused if it exists, unless `fresh`.
fn crash_disk(name: &str, fresh: bool) -> Result<PathBuf, String> {
    const SECTOR: usize = 512;
    const ENTRIES: usize = 128;
    const ENTRY_SIZE: usize = 128;
    const ENTRY_SECTORS: u64 = 32;

    let path = workspace_root().join("target").join("images").join(name);
    if !fresh && path.exists() {
        return Ok(path);
    }

    let total = CRASH_DISK_BYTES / SECTOR as u64;
    let (first_usable, last_usable) = (2 + ENTRY_SECTORS, total - ENTRY_SECTORS - 2);
    let mut disk = vec![0u8; CRASH_DISK_BYTES as usize];
    let mut put = |at: u64, bytes: &[u8]| {
        let at = at as usize * SECTOR;
        disk[at..at + bytes.len()].copy_from_slice(bytes);
    };

    // Protective MBR.
    let mut mbr = [0u8; SECTOR];
    mbr[446 + 4] = 0xEE;
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&((total - 1) as u32).to_le_bytes());
    mbr[510..512].copy_from_slice(&[0x55, 0xAA]);
    put(0, &mbr);

    let mut entries = vec![0u8; ENTRY_SECTORS as usize * SECTOR];
    entries[0..16].copy_from_slice(CRASH_PARTITION_TYPE);
    entries[16..32].copy_from_slice(b"panda-crash-disk");
    entries[32..40].copy_from_slice(&first_usable.to_le_bytes());
    entries[40..48].copy_from_slice(&last_usable.to_le_bytes());
    for (index, ch) in "crash".encode_utf16().enumerate() {
        entries[56 + index * 2..58 + index * 2].copy_from_slice(&ch.to_le_bytes());
    }
    let entries_crc = crc32(&entries[..ENTRIES * ENTRY_SIZE]);
    let backup_entries = total - 1 - ENTRY_SECTORS;
    put(2, &entries);
    put(backup_entries, &entries);

    for (at, other, entries_lba) in [(1, total - 1, 2), (total - 1, 1, backup_entries)] {
        let mut header = [0u8; SECTOR];
        header[0..8].copy_from_slice(b"EFI PART");
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&92u32.to_le_bytes());
        header[24..32].copy_from_slice(&at.to_le_bytes());
        header[32..40].copy_from_slice(&other.to_le_bytes());
        header[40..48].copy_from_slice(&first_usable.to_le_bytes());
        header[48..56].copy_from_slice(&last_usable.to_le_bytes());
        header[56..72].copy_from_slice(b"panda-crash-gpt!");
        header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        header[80..84].copy_from_slice(&(ENTRIES as u32).to_le_bytes());
        header[84..88].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let checksum = crc32(&header[..92]);
        header[16..20].copy_from_slice(&checksum.to_le_bytes());
        put(at, &header);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create {parent:?}: {e}"))?;
    }
    fs::write(&path, &disk).map_err(|e| format!("could not write {path:?}: {e}"))?;
    Ok(path)
}

/// The answer to one DNS question: `panda.test` A is 10.1.2.3; everything else
/// is no such name.
fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    while *query.get(at)? != 0 {
        let length = query[at] as usize;
        labels.push(String::from_utf8_lossy(query.get(at + 1..at + 1 + length)?).to_ascii_lowercase());
        at += 1 + length;
    }
    let question = query.get(12..at + 5)?;
    let kind = u16::from_be_bytes([query[at + 1], query[at + 2]]);
    let known = labels.join(".") == "panda.test" && kind == 1;

    let mut answer = Vec::from(&query[0..2]);
    answer.extend_from_slice(if known { &[0x81, 0x80] } else { &[0x81, 0x83] });
    answer.extend_from_slice(&[0, 1, 0, known as u8, 0, 0, 0, 0]);
    answer.extend_from_slice(question);
    if known {
        // A pointer to the question's name, then A, IN, a minute, four bytes.
        answer.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 1, 2, 3]);
    }
    Some(answer)
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, byte| {
        (0..8).fold(crc ^ *byte as u32, |crc, _| (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg()))
    })
}

fn qemu_command(image: &Path, uefi: bool, headless: bool, crash: &Path) -> Result<Command, String> {
    let mut cmd = Command::new(find_qemu()?);

    if uefi {
        let (code, vars) = ovmf_pflash()?;
        cmd.arg("-drive")
            .arg(format!("if=pflash,format=raw,readonly=on,file={}", qpath(&code)));
        cmd.arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", qpath(&vars)));
    }

    cmd.arg("-drive")
        .arg(format!("format=raw,file={}", qpath(image)));
    // q35 rather than the default i440FX. The older model is a 1996 chipset
    // with no PCI Express at all, so the firmware describes no memory-mapped
    // configuration window and every extended-config path goes untested. It
    // also gives a more representative interrupt topology to route.
    cmd.args(["-machine", "q35"]);
    cmd.args(["-m", "256M"]);
    // Four cores by default. The kernel targets multi-processor hardware, so
    // running the tests on one core would leave every SMP path untested -- and
    // the races it would hide are exactly the ones worth finding early.
    cmd.args(["-smp", "4"]);
    // The default `qemu64` model advertises neither SMEP nor SMAP, so the kernel
    // detects them as absent and skips them -- which means every protection they
    // provide goes untested, and a missing `stac` reads as working code. Asking
    // for them explicitly is what makes those paths real here.
    cmd.args(["-cpu", "qemu64,+smep,+smap"]);
    // A scratch SATA disk for the block driver to talk to.
    //
    // Attached through q35's own ICH9 AHCI controller, which is the same
    // interface most x86 machines expose for SATA -- so the driver exercised
    // here is the driver a real machine would need, not a QEMU-only shim.
    //
    // A fresh image per run: the tests write to it, and a disk carrying over
    // state from a previous run would make failures depend on what ran before.
    // q35 already has an ICH9 AHCI controller, and the boot drive above lands on
    // its first port. Adding a second controller instead of using the one that
    // is there gives the firmware two things to boot from and it picks the empty
    // one. This hangs on the second port of the existing controller.
    let disk = scratch_disk("scratch.img", SCRATCH_DISK_BYTES)?;
    cmd.arg("-drive")
        .arg(format!("id=panda-disk,if=none,format=raw,file={}", qpath(&disk)));
    cmd.args(["-device", "ide-hd,drive=panda-disk,bus=ide.1"]);
    // Where a panic leaves its record, on the next port along.
    cmd.arg("-drive")
        .arg(format!("id=panda-crash,if=none,format=raw,file={}", qpath(crash)));
    cmd.args(["-device", "ide-hd,drive=panda-crash,bus=ide.2"]);

    // The same again behind the two other interfaces a disk is likely to have:
    // an NVMe controller, as on nearly any machine built this decade, and
    // virtio-blk, as under nearly any hypervisor.
    let nvme = scratch_disk("nvme.img", NVME_DISK_BYTES)?;
    cmd.arg("-drive")
        .arg(format!("id=panda-nvme,if=none,format=raw,file={}", qpath(&nvme)));
    cmd.args(["-device", "nvme,drive=panda-nvme,serial=panda-nvme"]);
    let virtio = scratch_disk("virtio.img", VIRTIO_DISK_BYTES)?;
    cmd.arg("-drive")
        .arg(format!("id=panda-virtio,if=none,format=raw,file={}", qpath(&virtio)));
    cmd.args(["-device", "virtio-blk-pci,drive=panda-virtio"]);

    // A network card on QEMU's user-mode network: the guest is 10.0.2.15, the
    // gateway 10.0.2.2 answers pings, and a TFTP server on it serves one known
    // file. Everything a network test needs, with no host networking involved
    // and nothing to set up outside this process.
    let tftp = tftp_root()?;
    cmd.arg("-netdev")
        .arg(format!("user,id=panda-net,tftp={},hostfwd=tcp:127.0.0.1:{FORWARDED_PORT}-:80", qpath(&tftp)));
    cmd.args(["-device", "virtio-net-pci,netdev=panda-net"]);

    cmd.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    // Turn a triple fault into a dead VM instead of an invisible reboot loop.
    cmd.arg("-no-reboot");
    cmd.args(["-serial", "stdio"]);
    if headless {
        cmd.args(["-display", "none"]);
    }
    Ok(cmd)
}

fn run_qemu(mut cmd: Command, timeout: Option<Duration>) -> Result<i32, String> {
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to launch qemu: {e}"))?;

    let Some(timeout) = timeout else {
        let status = child.wait().map_err(|e| format!("waiting on qemu: {e}"))?;
        return Ok(status.code().unwrap_or(-1));
    };

    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|e| format!("polling qemu: {e}"))? {
            Some(status) => return Ok(status.code().unwrap_or(-1)),
            None if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "qemu did not exit within {}s -- the kernel is probably hung",
                    timeout.as_secs()
                ));
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn find_qemu() -> Result<PathBuf, String> {
    if let Some(p) = env::var_os("QEMU") {
        return Ok(PathBuf::from(p));
    }
    if let Some(dir) = qemu_install_dir() {
        return Ok(dir.join(qemu_exe_name()));
    }
    // Last resort: hope it is on PATH.
    if Command::new("qemu-system-x86_64")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
    {
        return Ok(PathBuf::from("qemu-system-x86_64"));
    }
    Err("could not find qemu-system-x86_64; install QEMU or set the QEMU env var".into())
}

fn qemu_install_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = env::var_os("QEMU_DIR") {
        candidates.push(PathBuf::from(p));
    }
    candidates.push(PathBuf::from(r"C:\Program Files\qemu"));
    candidates.push(PathBuf::from(r"C:\Program Files (x86)\qemu"));
    candidates.push(PathBuf::from("/usr/bin"));
    candidates
        .into_iter()
        .find(|d| d.join(qemu_exe_name()).exists())
}

fn qemu_exe_name() -> &'static str {
    if cfg!(windows) {
        "qemu-system-x86_64.exe"
    } else {
        "qemu-system-x86_64"
    }
}

/// Locate the OVMF code image and produce a writable copy of the variable store.
///
/// QEMU ships no `edk2-x86_64-vars.fd`; the x86_64 firmware pairs with the i386
/// varstore, which is the same format. The vars pflash drive must be writable,
/// so it is copied out of the read-only install directory.
fn ovmf_pflash() -> Result<(PathBuf, PathBuf), String> {
    let share = qemu_install_dir()
        .map(|d| d.join("share"))
        .filter(|d| d.exists())
        .ok_or("could not locate the QEMU share directory holding OVMF firmware")?;

    let code = share.join("edk2-x86_64-code.fd");
    if !code.exists() {
        return Err(format!(
            "OVMF firmware not found at {}; use the BIOS image instead (drop --uefi)",
            code.display()
        ));
    }

    let vars_src = share.join("edk2-i386-vars.fd");
    if !vars_src.exists() {
        return Err(format!("OVMF variable store not found at {}", vars_src.display()));
    }

    let vars_dst = workspace_root().join("target").join("images").join("ovmf-vars.fd");
    if let Some(parent) = vars_dst.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    if !vars_dst.exists() {
        fs::copy(&vars_src, &vars_dst)
            .map_err(|e| format!("copying OVMF vars to {}: {e}", vars_dst.display()))?;
    }
    Ok((code, vars_dst))
}

/// QEMU parses `key=value` option strings, so hand it forward slashes rather
/// than Windows backslashes.
fn qpath(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Paths and flags
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is baked in at compile time and points at xtask/, which
    // stays correct even when cargo invokes this binary directly as a runner.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ always has a parent")
        .to_path_buf()
}

fn kernel_dir() -> PathBuf {
    workspace_root().join("kernel")
}

/// Must stay in sync with the `runner` key in kernel/.cargo/config.toml.
fn runner_binary_path() -> PathBuf {
    workspace_root().join("target").join("release").join(if cfg!(windows) {
        "xtask.exe"
    } else {
        "xtask"
    })
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Read `--name=value` or `--name value`.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let prefix = format!("{flag}=");
    for (i, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value);
        }
        if arg == flag {
            return args.get(i + 1).map(String::as_str);
        }
    }
    None
}
