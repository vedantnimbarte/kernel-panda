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
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

/// QEMU maps a write of `v` to the isa-debug-exit port onto process exit code
/// `(v << 1) | 1`. The kernel writes 0x10 for success and 0x11 for failure.
const QEMU_EXIT_SUCCESS: i32 = (0x10 << 1) | 1; // 33
const QEMU_EXIT_FAILED: i32 = (0x11 << 1) | 1; // 35

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

    let code = match run_qemu(qemu_command(image, uefi, headless)?, timeout) {
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

    match run_qemu(qemu_command(image, uefi, true)?, Some(TEST_TIMEOUT))? {
        QEMU_EXIT_SUCCESS => Ok(ExitCode::SUCCESS),
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

fn qemu_command(image: &Path, uefi: bool, headless: bool) -> Result<Command, String> {
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
