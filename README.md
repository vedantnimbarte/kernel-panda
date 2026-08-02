<p align="center">
  <img src="logo.png" alt="Kernel Panda" width="360">
</p>

# Kernel Panda

A bare-metal microkernel written from scratch in `no_std` Rust, targeting
`x86_64-unknown-none`. Implements Phases 1 and 2 of
[the project specification](docs/prd.md): a kernel that boots, catches its own
faults, and manages physical and virtual memory.

**Status:** all 17 milestones of the PRD roadmap are implemented — from a
freestanding binary through a preemptive scheduler, Ring 3 user space,
capability-mediated IPC, PCIe enumeration, and a display server that composites
client buffers onto the screen from Ring 3 — plus a hardening pass covering
per-process address spaces, W^X, resource quotas and multiprocessing.
**108 test cases across 17 boot-and-assert test kernels, all passing on four
cores under QEMU.**

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

scheduler: spawning two workers that never yield
  [worker-b] step 1 of 3
  [worker-a] step 1 of 3
  [worker-b] step 2 of 3
  [worker-a] step 2 of 3
  [worker-b] step 3 of 3
  [worker-a] step 3 of 3
  both workers finished; 3 threads live, running as 'boot'

ring 3: loading a user program and dropping privilege
  [ring 3] hello from user space
  [ring 3] still running after a yield
  user program exited after writing 72 bytes through syscalls

ipc: a blocking logger thread fed over a capability
  [logger] tag 0x0101 word0  10 from thread 0
  [logger] tag 0x0102 word0  20 from thread 0
  [logger] tag 0x0103 word0  30 from thread 0
  [logger] tag 0xcafe word0 48879 from thread 6
  logger exited; endpoint drained to 0

compositor: a ring 3 display server
  compositor mapped the scanout buffer and is waiting for surfaces
  presented a blue surface at (120, 260)
  presented a green surface at (260, 260)
  presented a red surface at (400, 260)
  input daemon sent shutdown; both daemons exited

shell: a ring 3 daemon reading the serial port
panda> help
commands: help version hello exit
panda> version
Kernel Panda, ring 3 shell
panda> exit
shell exiting

pci: 6 devices
  00:00.0  8086:1237  class 06.00  host bridge
  00:02.0  1234:1111  class 03.00  display controller
  ...
    bar0: Memory { address: fd000000, size: 1000000, prefetchable: true }
```

Neither worker yields — the interleaving is entirely the timer taking the CPU
away from them. Thread 6 is a Ring 3 process sending through a SEND-only
capability; the kernel stamped its identity into the message, overwriting the
value the program had put there.

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
├── userland/        Ring 3 programs in Rust (its own cargo workspace)
│   ├── src/lib.rs   syscall wrappers, entry macro, panic handler
│   └── src/bin/     shell, compositor, input daemon, client, test probe
└── kernel/          the kernel itself (its own cargo workspace)
    ├── src/
    │   ├── console/   16550 UART, framebuffer text console, 8x8 font
    │   ├── arch/x86_64/   GDT + TSS, IDT, Local APIC + timer, 8259 masking
    │   ├── memory/    memory map, bitmap frame allocator, page tables, heap region
    │   ├── allocator/ bump and linked-list `GlobalAlloc` implementations
    │   ├── sched/  threads, context switch, round-robin scheduler
    │   ├── userspace.rs  user regions, program loading, the drop to Ring 3
    │   ├── syscall.rs    the entire Ring 3 surface
    │   ├── ipc.rs        endpoints, capabilities, blocking receive
    │   ├── pci.rs        bus enumeration and BAR decoding
    │   └── gbm.rs        shared graphics buffers and the scanout
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

**The context switch exchanges only callee-saved registers.** `context_switch` is
called like an ordinary C function, so the compiler has already spilled anything
caller-saved at the call site; saving it again would be wasted work. Between the
two halves the whole register file is covered.

**The boot thread cannot double as the idle thread.** Idle is by definition the
last choice, so any CPU-bound worker would starve it permanently — and with it,
whatever the kernel booted into. There is a separate idle thread that only runs
when the ready queue is empty.

**The scheduler lock is released before the switch.** Holding a spinlock across a
context switch leaves it locked by a thread that is no longer running. This is
safe only because the whole scheduler runs with interrupts disabled on a single
core, so nothing can observe the gap. It is the first thing that will need
rethinking for SMP.

**Entry to the kernel is an interrupt gate, not `SYSCALL`.** An interrupt gate
switches to the stack in `TSS.privilege_stack_table[0]` automatically, where
`SYSCALL` does not switch stacks at all and needs `swapgs` plus a per-CPU block
to find one. The gate costs more cycles and buys a great deal less that can go
quietly wrong. The ABI does not depend on the mechanism, so it can be swapped
later.

**A user fault kills the thread, not the kernel.** PRD 1.2 asks that a fault in
unprivileged code never take the system down, so the page-fault and GP handlers
check the saved CS and, if the fault came from Ring 3, destroy that thread and
carry on. `ring3.rs` proves it by running a program that dereferences the kernel
heap: the fault reports `PROTECTION_VIOLATION | USER_MODE`, meaning the page is
mapped and the `USER_ACCESSIBLE` bit is what stopped it — not a lucky unmapped
address.

**Every pointer from Ring 3 is walked before it is believed.** A user pointer is
an attacker-controlled integer. Validation checks both that the range lies inside
the user region *and* that every page it spans is present with the permissions
the access needs. Checking only the base is the classic confused-deputy hole, so
there are tests for a range that runs off the end and for a length that wraps the
address space.

**The kernel runs on every core.** Application processors come out of reset in
16-bit real mode, so they are started through a trampoline that walks them back
up to long mode — copied into low memory and *identity mapped*, because the
instant it enables paging it keeps executing at the address it is already at.
Every address inside that page is a compile-time constant offset, so nothing is
patched at runtime.

Each CPU has its own GDT, TSS and double-fault stack. `privilege_stack_table[0]`
names the stack *that* processor traps onto; sharing one would have two cores
landing on the same stack and destroying each other's frames — corruption rather
than a fault.

**The scheduler does not enqueue an outgoing thread until its registers are
saved.** Releasing the lock before a context switch was safe with one core
because nothing could observe the gap. With more, another CPU could pick the
outgoing thread off the ready queue and resume a context that is still live in
our registers. The incoming context performs the enqueue instead, once the
switch has completed.

**Each process has its own page tables.** A new address space is a clone of the
kernel's level 4 table with one slot — the 512 GiB entry covering the whole user
region — replaced by a private subtree. Kernel mappings are therefore shared *by
pointer*, so a later kernel mapping is visible everywhere at once, and only the
user region diverges. That holds while no kernel mapping needs a brand-new level
4 entry after the first process exists; every kernel region has its slot
populated during boot.

The page-table mapper is rebuilt from CR3 on every call rather than cached. A
cached mapper always describes the boot tables, so once processes have spaces of
their own it answers questions about the wrong one — silently, and only for user
addresses.

`one_process_cannot_read_another_address_space` is the proof: a process handed an
address that is mapped only in another space faults with `USER_MODE` and no
`PROTECTION_VIOLATION`, meaning the page is not present rather than merely
forbidden. The kernel-trespass test shows the opposite pair.

**Authority narrows, never widens.** A grant is intersected with what the granter
already holds, and requires the `GRANT` right to perform at all. Naming an
endpoint conveys nothing on its own.

**The display's pixel format is read, not assumed.** QEMU's framebuffer is 24-bit,
and a client rendering 32-bit pixels into it produces an image sheared a little
further right on every row. Buffers take their depth from the display so the two
always agree.

**The compositor never touches the hardware.** It reaches the screen only through
a shared buffer handle and learns what to draw only through IPC. The scanout
buffer is a singleton — two handles to one screen would let two compositors fight
over the same pixels with neither aware of the other — and it refuses to be
destroyed, because returning MMIO to the frame allocator would be a catastrophic
double free.

**The compositor tests assert on real pixels.** They read the display's memory
back and check the colour at the requested coordinates, and that just past the
surface's edge nothing was touched. A blit that runs one row long, or lands at
the wrong offset, passes every structural check and fails these.

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

* No SMAP. The kernel legitimately reads and writes user buffers during
  syscalls, so enabling it means bracketing every such access with `stac`/`clac`.
* Quotas are fixed constants, identical for every process. Real ones would be
  per-process policy set by whoever spawned it.
* The ACPI IOAPIC address is read but never used — nothing routes a device
  interrupt yet, so console input is still polled.
* Only ever run under QEMU. Firmware variance in ACPI layout and AP start-up
  timing is exactly where this class of code breaks.
* Intermediate page tables are reclaimed for a process's user region when it
  exits, but not for kernel mappings — an unmapped kernel range leaves its
  P3/P2/P1 standing.
* `spin::Mutex` still has no priority awareness and no fairness — a contended
  lock is won by whichever core asks at the right moment.
* The scheduler is one shared ready queue behind one lock. Correct, but every
  core contends for it on every switch; per-CPU queues with work stealing would
  scale further.
* TLB shootdown flushes the whole TLB rather than one page, and does not wait for
  the other cores to acknowledge. Sufficient here because shootdowns only follow
  an unmap the sender has already completed, but a finer implementation would
  invalidate a single address and confirm receipt.
* The APIC MMIO page is mapped uncached at its own virtual address while the
  bootloader's physical-memory window also maps it cached. Two mappings with
  different cache attributes is architecturally discouraged; it works here, and
  every access goes through the uncached mapping, but it should be tidied up.
* Calibration trusts a single 10 ms PIT sample. Averaging several would be more
  robust on a loaded host.
* Kernel stacks come from the heap, so they have no guard page. A thread that
  overflows its 32 KiB corrupts whatever the allocator put beneath it, silently.
  They should move to guard-paged mappings of their own.
* The scheduler is strict round-robin with no priorities. Threads can now block
  on IPC, but there is still no sleep and no wait-for-thread, so polling with
  `yield_now` is the only way to await anything else.
* One user program is still hand-written assembly: the W^X test, which plants
  two bytes of machine code on its own stack and jumps to them. That is not
  something Rust will express, and it is the right tool for that one job.
* The compositor has no damage tracking, no double buffering and no z-order. It
  blits each surface once, as it arrives.
* PCI uses the port-based config mechanism, so extended config space above
  offset 0xFF is unreachable. Getting there means parsing the ACPI MCFG table.
* Input is polled from the timer rather than driven by an interrupt, which caps
  throughput at the tick rate. Routing IRQ 4 needs the IOAPIC, and finding the
  IOAPIC properly needs ACPI.
* Syscalls run with interrupts disabled, because the gate is an interrupt gate.
  Long-running calls are therefore not preemptible; only `write` is bounded
  today, and every future call has to stay short or the quantum is a fiction.

## Phase 3 progress

- [x] **M1 — Hardware interrupts.** Local APIC, calibrated periodic timer at
      100 Hz, tick counter and uptime, interrupt-safe console.
- [x] **M2 — Preemptive thread scheduler.** Kernel threads with their own
      stacks, round-robin over a 10 ms quantum, timer-driven preemption,
      `yield_now`, and reaping of finished threads.
- [x] **M3 — Ring 0 → Ring 3.** User code and data segments, a per-thread Ring 0
      stack in the TSS, an `int 0x80` syscall gate, user page mapping with
      validated pointers, and user faults that kill only the faulting thread.
- [x] **M4 — IPC.** Bounded endpoint queues, unforgeable sender identity,
      capabilities with `SEND`/`RECEIVE`/`GRANT`, and a blocking receive that
      parks the thread rather than spinning.
- [x] **M5 — First user-space daemon.** A line-editing shell over the serial
      port, running in Ring 3 and parking in the kernel between keystrokes.

## Phase 4 progress

- [x] **M1 — PCIe enumeration.** Full bus sweep, class decoding, BAR sizing.
- [x] **M2 — Generic buffer management.** Shared graphics buffers with
      capability-checked handles, plus a scanout buffer wrapping display memory.
- [x] **M3 — Input daemon.** A Ring 3 process that owns console input, drops
      control codes, and forwards the rest over IPC.
- [x] **M4 — Sovereign compositor.** A Ring 3 display server that maps the
      scanout buffer and blits client surfaces into it.
