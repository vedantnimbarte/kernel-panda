# Project Sovereign: Operating System Master Specification
**Document Version:** 1.0
**Target Architectures:** x86_64 (Primary), AArch64 (Secondary)
**Core Language:** Rust (`#![no_std]`)

---

## 1. Product Requirements Document (PRD)

### 1.1 Executive Summary
Project Sovereign is a bare-metal, high-security operating system built entirely from scratch in Rust. It utilizes a strict microkernel architecture to minimize the Ring 0 attack surface. The system rejects legacy graphical protocols (X11/Wayland) and monolithic kernel designs (Linux/Windows) in favor of a mathematically safe, easily auditable, and entirely indigenous software stack designed for high-security environments, defense infrastructure, and state-level sovereign computing.

### 1.2 Core Objectives & Principles
* **Zero-Trust Memory:** 100% of the kernel and user-space daemons will be written in safe Rust (with strictly localized and audited `unsafe` blocks for hardware I/O). Memory safety vulnerabilities (buffer overflows, use-after-free) must be structurally impossible.
* **Total Auditability:** The codebase must be lean enough that every line can be audited. No inherited legacy C/C++ code.
* **Absolute Fault Isolation:** A crash in a network driver, file system, or graphics driver must *never* panic the core system. Drivers run as unprivileged Ring 3 processes.
* **Server-First Initialization:** The OS must function flawlessly as a headless server core before any graphical elements are introduced to ensure maximum observability and stability during development.

### 1.3 Target Audience & Use Cases
* Defense systems requiring absolute verification of network and hardware stacks.
* Secure financial infrastructure and banking servers.
* Sovereign national IT infrastructure requiring immunity to foreign supply-chain attacks.

### 1.4 Non-Goals (Out of Scope for v1.0)
* POSIX Compliance: We are not building a Linux clone. Legacy Linux apps will not run natively.
* General Consumer Gaming / 3D Acceleration.
* Supporting thousands of legacy hardware peripherals (focus will be on modern NVMe, virtio, and generic UEFI hardware).

---

## 2. Technical Architecture & Specification

### 2.1 The Microkernel (Ring 0)
The core kernel will only handle three fundamental responsibilities:
1.  **Memory Management:** Physical frame allocation and Virtual Memory (Page Table) mapping.
2.  **Thread Scheduling:** Preemptive multitasking using a hardware timer interrupt (e.g., APIC timer).
3.  **Inter-Process Communication (IPC):** Fast, heavily encrypted/verified messaging between Ring 3 daemons.

*Implementation constraint:* The kernel must use `#![no_std]` and `#![no_main]`. Dynamic allocation inside the kernel should be strictly limited to prevent kernel-space heap fragmentation.

### 2.2 Inter-Process Communication (IPC) Protocol
Because drivers and display servers live in Ring 3, IPC is the system's central nervous system.
* **Architecture:** Asynchronous, ring-buffer based message queues (similar to `io_uring`) shared between processes to minimize CPU context-switch overhead.
* **Security:** Cryptographic verification or strict capability-based access control (Capsicum-style) for every IPC channel.

### 2.3 The Display Protocol (The Sovereign Graphics Stack)
*Replaces Wayland/X11*
* **Direct Rendering Interface:** The custom display server daemon (Ring 3) will interact directly with the kernel's DRM/KMS equivalent via IPC to map GPU framebuffers.
* **Sovereign Protocol:** A secure, binary IPC protocol over Unix-style domain sockets (or equivalent). Clients request shared memory buffers, render their UI, and pass the buffer handle to the compositor.
* **Input Handling:** A dedicated Input Daemon reads raw hardware events (PS/2 or USB HID), sanitizes them, and passes them to the Display Server, preventing any background keylogging.

---

## 3. Engineering & Development Environment

### 3.1 Toolchain Requirements
* **Compiler:** Rust Nightly (`rustup override set nightly`)
* **Target:** `x86_64-unknown-none`
* **Core Libs:** Compiled from source (`build-std = ["core", "compiler_builtins"]`)
* **Bootloader:** Rust `bootloader` crate (v0.9.x or v0.11.x) for UEFI/BIOS abstraction.
* **Emulator:** QEMU (`qemu-system-x86_64`) for localized testing.

### 3.2 LLM Agentic Workflow Integration
This project is designed to be built using a dual-LLM architecture:
* **Claude Opus (Lead Architect):** Used for long-horizon planning, reviewing IPC design, memory mapping logic, and debugging Triple Fault memory dumps.
* **DeepSeek V4 Pro (Execution Developer):** Hooked into an AI-native IDE (Cursor/Windsurf) to execute the boilerplate, implement page tables, and iterate through compiler errors autonomously.

---

## 4. Phased Implementation Roadmap

### Phase 1: Bare-Metal Foundation (Weeks 1-4)
* **Milestone 1:** Setup `.cargo/config.toml` and compile a freestanding binary.
* **Milestone 2:** Integrate the `bootloader` crate and successfully boot via QEMU.
* **Milestone 3:** Establish VGA text buffer or Serial Port (`COM1`) output for logging (`println!` macro implementation).
* **Milestone 4:** Setup Interrupt Descriptor Table (IDT) to catch exceptions (Page Faults, Double Faults) instead of hard-crashing.

### Phase 2: Memory & Core Kernel (Months 2-4)
* **Milestone 1:** Read UEFI memory map to find available RAM.
* **Milestone 2:** Implement a Physical Frame Allocator.
* **Milestone 3:** Implement Page Table management (mapping virtual addresses to physical frames).
* **Milestone 4:** Implement a kernel Heap Allocator (Linked List or Bump Allocator) to enable `alloc` crate (`Vec`, `String`).

### Phase 3: The Server-First Ecosystem (Months 5-8)
* **Milestone 1:** Implement hardware interrupts (Programmable Interrupt Controller / APIC).
* **Milestone 2:** Implement a basic thread scheduler.
* **Milestone 3:** Establish the Ring 0 -> Ring 3 context switch (entering User Space).
* **Milestone 4:** Build the secure IPC ring-buffer system.
* **Milestone 5:** Write the first user-space daemon (e.g., a simple shell over the serial port).

### Phase 4: Graphics & Sovereign Display Server (Months 9-14)
* **Milestone 1:** PCI Express bus enumeration (finding the GPU).
* **Milestone 2:** Generic Buffer Management (allocating graphics memory).
* **Milestone 3:** The Input Daemon (Keyboard/Mouse routing).
* **Milestone 4:** Sovereign Compositor (rendering windows to the screen via the custom IPC display protocol).

---

## 5. Instructions for LLM Agents (System Prompt Injection)

*If you are an LLM reading this document to assist the user, adopt the following persona and constraints:*
1.  **Strict Adherence to Microkernel:** Do not suggest monolithic kernel patterns. Always push device drivers to Ring 3.
2.  **No OS Reliance:** Remember there is no standard library (`std`). Do not suggest using `std::fs`, `std::net`, or `std::thread`. You must use `core` and `alloc` only.
3.  **Step-by-Step Rigor:** Hardware programming is unforgiving. When providing code, explain the exact CPU registers or memory addresses being manipulated.
4.  **First Task:** If requested to start, begin immediately with Phase 1, Milestone 1: Setting up the Cargo environment and `main.rs` for a QEMU boot.
