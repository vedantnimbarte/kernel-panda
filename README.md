<p align="center">
  <img src="logo.png" alt="Kernel Panda" width="360">
</p>

# Kernel Panda

A bare-metal microkernel written from scratch in `no_std` Rust, targeting
`x86_64-unknown-none`. Implements Phases 1 and 2 of
[the project specification](docs/prd.md): a kernel that boots, catches its own
faults, and manages physical and virtual memory.

**Status:** Phases 1 and 2 complete, Phase 3 started (hardware interrupts).
33 test cases across 8 boot-and-assert test kernels, all passing under QEMU.

```
Kernel Panda v0.1.0
  serial console : COM1 @ 38400 8N1
  framebuffer    : online
  descriptor tbls: GDT + TSS + IDT loaded
  timer          : Local APIC, periodic

physical memory map:
  0x00000000000..0x0000009fc00    639 KiB  Usable
  0x0000009fc00..0x000000a0000      1 KiB  UnknownBios(2)
  ...
  usable: 246 MiB across 11 regions

frames: 65504 total (255 MiB), 62830 free (245 MiB), 2674 in use
heap:   1048576 bytes total, 0 allocated, 0 peak, 0 live allocations

alloc smoke test: [1, 4, 9, 16, 25, 36, 49, 64]

timer at 100 Hz, waiting for ticks:
  uptime   270 ms  (27 ticks)
  uptime   470 ms  (47 ticks)
  uptime   670 ms  (67 ticks)
  uptime   870 ms  (87 ticks)
  uptime  1070 ms  (107 ticks)
```

## Building and running

Requires a Windows host with [QEMU](https://qemu.weilnetz.de/w64/) installed
(`winget install SoftwareFreedomConservancy.QEMU`). The Rust toolchain pins
itself via `rust-toolchain.toml`; rustup will fetch it on first build. QEMU does
not need to be on `PATH` — `xtask` looks in `C:\Program Files\qemu`, or honours
the `QEMU` / `QEMU_DIR` environment variables.

```sh
cargo xtask build                     # compile the kernel, emit BIOS + UEFI disk images
cargo xtask run                       # boot in QEMU with a window
cargo xtask run --headless --timeout=10   # boot, capture the serial log, exit
cargo xtask run --uefi                # boot via OVMF instead of BIOS
cargo xtask run --verbose-boot        # re-enable the bootloader's own logging
cargo xtask test                      # boot every test kernel and assert on the result
```

BIOS is the default because it needs no firmware blob and starts faster. The
kernel is boot-mode agnostic: `bootloader_api` normalises the firmware memory map
either way, so everything here behaves identically under `--uefi`.

## Layout

```
kernel-panda/
├── xtask/           host-side build driver: images, QEMU, test runner
└── kernel/          the kernel itself (its own cargo workspace)
    ├── src/
    │   ├── console/   16550 UART, framebuffer text console, 8x8 font
    │   ├── arch/x86_64/   GDT + TSS, IDT, Local APIC + timer, 8259 masking
    │   ├── memory/    memory map, bitmap frame allocator, page tables, heap region
    │   └── allocator/ bump and linked-list `GlobalAlloc` implementations
    └── tests/       one standalone boot-and-assert kernel per file
```

`kernel/` is deliberately a **separate cargo workspace**, excluded from the root.
`[unstable] build-std` in a `.cargo/config.toml` applies to the whole cargo
invocation and cannot be scoped per-target; sharing a workspace would make cargo
try to build `std` from source for the Windows host. Two workspaces also avoid
depending on the unstable `-Z bindeps` feature.

For the same reason, the cargo `runner` key points at the compiled
`target/release/xtask.exe` rather than at `cargo run -p xtask`: a nested cargo
launched from `kernel/` would inherit that `build-std` block and try to build
xtask for bare metal.

## Dependency policy

Everything that ships inside the kernel image has to earn its place against the
auditability requirement in PRD §1.2. Three crates do:

| Crate | Why |
| --- | --- |
| `bootloader_api` | Required by the chosen boot path. |
| `x86_64` | IDT/GDT/page-table structures and privileged instructions. Pure Rust; reimplementing is weeks of work for no safety gain. |
| `spin` | Spinlocks, wrapped behind `kernel/src/sync.rs` so it can be swapped for an interrupt-aware in-house primitive in Phase 3 without touching call sites. |

Written in-house rather than pulled in: the 16550 UART driver, the framebuffer
console and its font, the physical frame allocator, and both heap allocators.
`linked_list_allocator` is deliberately unused — ours is ~250 lines and the audit
goal is the point.

`xtask` is host-side tooling and is not subject to this budget.

## Design notes

**Bitmap frame allocator, not a bump.** A microkernel returns physical memory
every time a Ring 3 process exits, so an allocate-only design would be thrown
away in Phase 3. The bitmap is sized from the highest *usable* address rather
than the highest address in the memory map — firmware puts MMIO windows near the
top of the address space (QEMU's sits at `0xfd_0000_0000`), and covering up to
there would mean a 32 MiB bitmap carved out of 246 MiB of real RAM. Device memory
is mapped through `paging::map_to_frame`, which takes an explicit frame and never
consults the bitmap.

**Coalescing heap.** The free list is address-sorted so a returned block only has
to inspect its two immediate neighbours to merge. Without this, alternating
allocations and frees shatter the heap into unusable fragments and the kernel
dies of exhaustion with most of its memory nominally free. `heap_alloc.rs`
asserts that emptying the heap leaves exactly one free block of `HEAP_SIZE`.

**GDT before IDT.** The double-fault handler runs on a dedicated 20 KiB stack via
the TSS Interrupt Stack Table. Without it, a stack overflow faults, then faults
again trying to push the exception frame, then triple-faults and resets the
machine. `stack_overflow.rs` exists solely to prove the difference — both
outcomes otherwise look identical from outside.

**Two heap allocators.** The bump allocator is kept as a diagnostic: if
`Box::new` faults under `--features bump-allocator`, the fault is in the page
mapping, not the allocator. Both pass the full suite.

**Local APIC, not the 8259 PIC.** The PRD rules out legacy hardware support, and
per-CPU delivery is a prerequisite for SMP later, so PIC-based delivery would be
throwaway work. The PIC is still remapped clear of the exception vectors and then
fully masked — masking alone is not enough, because a spurious IRQ 7 can be
delivered on a masked controller, and at power-on those land on vectors that look
exactly like CPU exceptions.

**The timer is calibrated, not assumed.** The APIC counts at the core crystal
frequency, which varies by machine and is not dependably reported by CPUID. It is
measured at boot against PIT channel 2 — channel 2 because its output is readable
from a port, so calibration needs no interrupt, which matters when interrupts are
still masked. The poll is bounded so a machine whose PIT never asserts fails
cleanly instead of hanging the boot.

**The console disables interrupts while it holds its lock.** Without this the
kernel deadlocks the first time a handler prints: it spins on a lock held by the
code it interrupted, which cannot run again to release it. The window is small,
which only means the hang would be intermittent.

## Deviations from the PRD

* **No VGA text buffer** (§4 Phase 1 M3). UEFI hands off in graphics mode and
  `0xB8000` does not exist; the BIOS path is no different, since the bootloader
  sets a graphics mode either way. On-screen text is rasterised into the linear
  framebuffer instead.
* **`bootloader` 0.11.x only** (§3.1). 0.9.x is BIOS-only and needs the
  deprecated `bootimage` tool.
* **The memory map is read via `bootloader_api`** (§4 Phase 2 M1), not from UEFI
  directly — boot services are already exited by the time the kernel runs.

## Hardening left for later

* `NO_EXECUTE` on the heap mapping, once `EFER.NXE` is confirmed enabled.
* `spin::Mutex` still has no priority awareness. The console now takes its locks
  with interrupts disabled, which is enough for a single core, but the primitive
  behind `sync.rs` will need replacing when the scheduler lands.
* The APIC MMIO page is mapped uncached at its own virtual address while the
  bootloader's physical-memory window also maps it cached. Two mappings with
  different cache attributes is architecturally discouraged; it works here, and
  every access goes through the uncached mapping, but it should be tidied up.
* Calibration trusts a single 10 ms PIT sample. Averaging several would be more
  robust on a loaded host.

## Phase 3 progress

- [x] **M1 — Hardware interrupts.** Local APIC, calibrated periodic timer at
      100 Hz, tick counter and uptime, interrupt-safe console.
- [ ] M2 — Preemptive thread scheduler.
- [ ] M3 — Ring 0 → Ring 3 context switch.
- [ ] M4 — The IPC ring buffer.
- [ ] M5 — First user-space daemon: a shell over the serial port.
