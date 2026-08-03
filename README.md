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

**No thread is runnable, or freeable, while a processor is still standing on its
stack.** Releasing the scheduler lock before a context switch was safe with one
core because nothing could observe the gap. With more, the window between "stops
being this CPU's `current`" and "the `mov rsp` inside `context_switch`" is a
window in which the thread looks idle and is not. Another core resuming it there
loads a saved stack pointer that has not been written yet; another core *freeing*
it there unmaps a live stack.

Each thread therefore carries an `on_cpu` flag, set when a CPU commits to
switching to it and cleared by the incoming context once the switch has actually
happened. The ready queue, `unblock` and `reap` all respect it. `unblock` is the
one that is easy to miss — a wake arrives from another core at a moment of the
waker's choosing, including while the thread it is waking is halfway off its
processor. It sets the state and leaves the enqueue to the handshake.

Symptom when this was wrong: an intermittent double fault with `rsp` of zero, one
run in ten, from a blocking IPC receive.

**The compositor keeps a surface table, composes back to front, and only
redraws what changed.** It was a blitter: each message painted straight into the
scanout as it arrived, so what ended up on top was decided by which client sent
last. Surfaces now carry a depth and are composed in that order, into an
off-screen buffer that reaches the display in one copy per frame — drawing
directly into the scanout lets the display controller read a half-composed
frame, which with overlapping surfaces is a visible flicker of whatever was
underneath.

Composition has to clear before it draws, or a surface that moved leaves its old
pixels behind; and having cleared, it has to redraw *every* surface intersecting
the cleared region, not just the newest. Both directions are tested, because
each one alone passes a plausible-looking wrong implementation.

Damage is accumulated as a single rectangle covering both a surface's old and
new bounds. One rectangle cannot grow without bound and is cheap to intersect
against; the cost is redrawing some pixels that did not need it.

`depth_decides_what_is_on_top_not_arrival_order` sends the nearer surface
*first*, so a compositor painting in arrival order fails it — which the previous
one does, checked rather than assumed.

**PCI configuration space is reached by memory when the firmware describes a
window.** The port mechanism latches an address in `0xCF8` and reads `0xCFC`,
which works everywhere and reaches only the first 256 bytes of each function —
its selector has nowhere to put a wider offset. Everything PCI Express added
lives above that: MSI-X, AER, link control. ECAM makes bus, device and function
into address bits of a window named by the ACPI MCFG table, so there is no
latch, no pair of accesses to keep together, no lock, and 4 KiB per function.

The two are views of the same registers, so they must agree about the low 256
bytes. `both_views_of_configuration_space_agree` checks that rather than
assuming it — if MCFG describes a window somewhere other than where the firmware
actually put it, every extended read afterwards lands on unrelated physical
memory, which is far worse than having no ECAM at all.

The test harness runs QEMU as `-machine q35`. The default i440FX is a 1996
chipset with no PCI Express, so it publishes no MCFG and every extended-config
path would go untested.

**Serial input arrives by interrupt, not by polling.** It was drained from the
timer handler before, which capped throughput at the tick rate and made a
keystroke wait up to a full quantum to be noticed. That was not laziness:
routing IRQ 4 needs an I/O APIC, and finding one needs ACPI, so it had to wait
for both.

The MADT's interrupt source overrides are honoured rather than assumed away.
Firmware is allowed to wire an ISA IRQ to a pin other than the one its number
suggests — the timer usually arrives on pin 2, not pin 0 — and programming the
obvious pin instead is the classic way to configure a redirection entry nothing
is connected to, then wait forever.

Order matters at both ends. The redirection entry's high half is written before
its low half, because the low half carries the mask bit and the entry must never
be briefly live with no destination set — on a multiprocessor that is an
interrupt delivered to whichever core happens to be APIC id zero. And the UART
is told to raise the line only *after* something is listening: a level-triggered
input asserted with the entry still masked stays asserted.

The timer handler still polls the console when routing did not happen — no ACPI,
no chip, a firmware layout this does not understand. A machine whose only
interface is the serial port should be slow rather than deaf.

**The lock is a ticket lock, so waiters are served in the order they arrived.**
A test-and-set spinlock has no queue: every waiter races for the same word on
release, and the core whose cache already holds the line tends to win again.
Under sustained contention on the heap or the frame allocator — which every core
touches — that leaves a processor waiting for reasons nothing in the code
explains. Each caller now takes a number and waits for it, so the longest waiter
is always next. The cost is one extra atomic per acquisition, against a single
contended cache line bouncing between four cores.

**A TLB shootdown names one page and waits for an answer.** It used to flush
everything and return immediately. The old comment argued the gap was harmless
because the sender had already finished its unmap — true only if nothing reuses
the frame in the meantime, and freeing it is exactly what happens next.

Waiting introduces a deadlock that has to be designed out rather than hoped
away: two processors can each be waiting on the other, and callers arrive with
interrupts already masked, so neither would ever take the other's IPI. The
request lives in a per-CPU slot, and a processor waiting for acknowledgements
services *its own* slot inline on every pass of the wait loop. That breaks the
cycle without relying on interrupt delivery at all. Requests merge rather than
overwrite — two different pages become "everything", because dropping one would
leave a stale translation alive with nothing left to report it.

Freeing an intermediate page table still flushes wholesale: what the processors
cached is the structure, not one leaf, and a single-address invalidation does not
reach it.

**`cpu_index` takes no lock.** It is called from the timer handler, from every
scheduler operation and from every wake, and it used to lock a `Vec` and search
it — a contended shared lock on the hottest path in the kernel, which is what the
scheduler had just been restructured to avoid. The IPI fan-out *cloned* that
`Vec`, so a page unmap could end up inside the heap allocator. Both now read a
fixed table of atomics written once during boot.

**System calls are preemptible.** The gate is a trap gate, not an interrupt gate,
so `IF` survives the transition. As an interrupt gate a syscall ran to completion
however long it took, the calling thread's quantum meant nothing, and every
future call had to stay short — a constraint a microkernel cannot keep, since the
point is that calls do real work. What it demands in return is that the
dispatcher tolerate preemption: every lock it touches masks interrupts for the
window it holds them, the user-memory windows are bracketed by a guard that does
the same, and the frame it edits lives on the calling thread's own kernel stack.

**Run queues are per-CPU, and an idle core steals rather than idling.** A thread
goes back on the queue of the processor that last ran it, so it tends to return
to a core whose caches still know about it. Left there, that would be four
independent schedulers with wildly different amounts of work — a core that
emptied its own queue would run its idle thread next to another core's backlog —
so a core with nothing of its own takes from the busiest queue instead.

**The timer tick does not take the scheduler lock.** It runs on every core on
every tick and asks two questions, both of which are almost always answered "no":
has this slice expired, and is a sleeper due. Both now live in atomics outside
the lock, so four cores no longer queue on one spinlock a hundred times a second
for the privilege of subtracting one. The slice is advisory — the authoritative
reset happens under the lock at the switch — so a lost race costs at most one
early or late preemption, which round-robin cannot distinguish from a normal one.

Reaping used to walk the entire thread table on every context switch, looking for
the rare thread that had died. An exiting thread now records itself, so the walk
is proportional to the number of threads that actually finished.

**Three priorities, and a guard against the obvious consequence.** Strict
priority starves: a `High` thread that never blocks means nothing below it runs
again. Every eighth switch is therefore taken from somewhere other than the top.
Three levels rather than thirty-two, because scheduling policy belongs in Ring 3;
what the kernel owes is enough separation for an input daemon to preempt a
compute loop.

The first version of that guard served the *lowest* occupied queue, which reads
as reasonable and quietly skips the middle: with `High` and `Low` both busy,
every guarded turn went to `Low` and a `Normal` thread never ran again. The boot
thread is `Normal`, so the kernel hung outright the moment anything saturated the
other two levels — it woke from a sleep and was simply never picked. The guard
alternates between `Low` and `Normal` instead, which bounds any level's wait at
two guard intervals. `the_middle_priority_is_not_squeezed_out` saturates the
outer two deliberately and requires an ordinary thread to still get in.

The priority test spawns six threads at each level rather than one. With four
cores and one thread of each, both simply get a core and the choice never
happens — the queues have to be contended for the result to mean anything.

**A thread can sleep, and a thread can be waited for.** Both had been missing, so
polling with `yield_now` was the only way to await anything that was not an IPC
message. Sleepers sit in an unsorted list next to the earliest deadline in it, so
the timer handler — which runs on every core on every tick — compares two
integers in the common case and walks the list only when something is actually
due.

`join` registers the waiter and blocks under a single acquisition of the
scheduler lock, and `exit_current` takes the waiter list under that same lock.
That is what makes the race unrepresentable: a join either gets in before the
thread finishes and is woken, or sees `Finished` and does not park at all. The
list lives on the thread being waited *for*, so finishing is one look-up rather
than a scan.

**One processor keeps the clock.** Every core has its own APIC timer and all of
them reach the same handler, so counting the clock on each made uptime run at
four times real speed on a four-core machine — and any duration measured in ticks
come out short by the same factor. Invisible from inside, because everything was
measured against the same wrong clock. Per-CPU interrupt counts are kept
separately, which is both the honest diagnostic and what makes the property
testable.

**An unmap gives back the page tables it emptied, except at level 4.** Removing a
mapping clears one level 1 entry; the P1 that held it and the P2 above it used to
stay allocated forever, so a range that is mapped and released repeatedly leaked
a frame per level per region. Each unmap now walks back up and frees whatever it
left empty.

Level 4 is deliberately excluded. Every entry there outside the user slot is
shared *by pointer* with every process's cloned table, so clearing one would
unmap a whole kernel region from every address space at once and hand a live
table to the allocator. The user slot has its own path — `AddressSpace::release`
frees that subtree wholesale when the process exits. Everything below level 4 is
the same physical table in every space, so freeing one there is right rather than
merely tolerable: the mapping really has gone everywhere.

Freeing a table means invalidating more than one address. Processors cache
*paging structures* as well as translations, so a P2 that still remembers a P1
just handed back would walk into whatever gets allocated next — the local TLB is
flushed wholesale and the other cores are told to do the same.

**The kernel has to ask before it may touch user memory.** With SMAP on, every
supervisor read or write of a user-accessible page faults unless `EFLAGS.AC` is
set. The handful of places that legitimately do it — copying a syscall's buffer,
filling a program's image before it starts — hold a `UserAccess` guard, which
sets `AC` and clears it again on drop. Everywhere else, a stray dereference of an
attacker-supplied pointer now faults instead of quietly succeeding.

The guard also masks interrupts. Nothing clears `AC` on the way into a handler,
so an interrupt landing inside the window would run the entire handler with SMAP
disabled, and a context switch there would carry the relaxation into an unrelated
thread. Every window is a bounded copy, so the cost is small and the alternative
is a protection that lapses at moments an attacker can choose.

`ring0_cannot_touch_user_memory_without_asking` is the proof, and it needed a
small piece of machinery to write: a kernel-mode page fault normally panics, so
the test arms a one-shot flag that turns the expected fault into a thread death
instead. Its partner case performs the same access through the guard and requires
it to succeed, so the pair cannot both pass for a trivial reason.

The test harness runs QEMU as `-cpu qemu64,+smep,+smap`. The default model
advertises neither, the kernel would detect them as absent and skip them, and a
missing `stac` would read as working code.

**Kernel stacks are mapped, not allocated, with an unmapped guard page beneath
each.** A stack on the heap has nothing below it but more heap, so overflowing it
writes into another allocation and surfaces later as corruption somewhere
unrelated. An unmapped page turns that into a fault on the first byte past the
end — and on a kernel thread that fault escalates to a double fault, which lands
on the IST stack and prints. Slots are spaced twice the stack size apart, so an
overflow cannot skip the guard and land in the neighbour.

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

**Any lock the timer handler can reach masks interrupts.** The console, the heap,
the scheduler, the page tables and the frame allocator all do. The rule is not
about multi-core exclusion — the spin still provides that — it is about a CPU
deadlocking against itself: a tick that lands on the very core holding a lock,
and then needs it, spins forever, because the holder cannot run again to release
it.

Which locks qualify changes as the kernel grows, and that is the trap. The frame
allocator did not qualify until kernel stacks moved off the heap: after that, a
tick could schedule, scheduling could drop a finished thread, and dropping one
unmaps a stack and returns its frames. It hung about one run in thirty, in
whichever test allocated the most physical memory.

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

* Quotas are fixed constants, identical for every process. Real ones would be
  per-process policy set by whoever spawned it.
* Only ever run under QEMU. Firmware variance in ACPI layout and AP start-up
  timing is exactly where this class of code breaks.
* The ticket lock is fair but not priority-aware: a `High` thread queues behind
  a `Low` one that asked first. Fixing that means priority inheritance, which
  needs the lock to know who holds it and the scheduler to be reachable from the
  locking primitive.
* The thread table is still one lock. The timer tick no longer takes it and the
  run queues are per-CPU, but a context *switch* does. Removing that means each
  thread being owned by exactly one processor's queue, with migration
  transferring ownership under both locks in index order — a real ownership model
  rather than a data-structure change.
* The APIC MMIO page is mapped uncached at its own virtual address while the
  bootloader's physical-memory window also maps it cached. Two mappings with
  different cache attributes is architecturally discouraged; it works here, and
  every access goes through the uncached mapping, but it should be tidied up.
* Calibration trusts a single 10 ms PIT sample. Averaging several would be more
  robust on a loaded host.
* One user program is still hand-written assembly: the W^X test, which plants
  two bytes of machine code on its own stack and jumps to them. That is not
  something Rust will express, and it is the right tool for that one job.
* The compositor's damage is one rectangle rather than a region list, so two
  small changes at opposite corners recompose everything between them. A region
  list is the answer, and it needs an allocator the userland does not have.
* Nothing catches tearing from inside the machine. The back buffer's existence
  is checked; that the display never sees a half-composed frame is argued from
  the structure, not observed.
* The ECAM window is clamped to the first 64 buses. Firmware routinely describes
  all 256 whether or not anything is on them, and mapping that eagerly is 65,536
  page-table entries at boot for buses that will never answer. A device beyond
  the cap still works through the port mechanism; only its extended
  configuration space is out of reach.
* The I/O APIC decides which pin owns a global interrupt by base address alone;
  it does not read each chip's redirection-entry count. Exact with one I/O APIC,
  which is every machine this has run on, and wrong on a machine with two whose
  interrupt ranges are not contiguous.

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
