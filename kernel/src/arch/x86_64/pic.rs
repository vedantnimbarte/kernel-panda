//! The legacy 8259 Programmable Interrupt Controller.
//!
//! Nothing here delivers interrupts. The Local APIC does that. This module
//! exists purely to put the PIC into a state where it cannot interfere.
//!
//! At power-on the master PIC raises its IRQs on vectors 0x08-0x0F, which
//! collide head-on with the CPU's own exception vectors -- a timer IRQ would
//! arrive looking exactly like a double fault. Masking alone is not enough
//! either: a spurious IRQ 7 can still be delivered on a masked controller. So
//! the vectors are remapped clear of the exception range *first*, and only then
//! is every line masked off.

use x86_64::instructions::port::Port;

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// Where the master PIC's IRQ 0 lands after remapping. Just past the 32
/// architecturally reserved exception vectors.
const PIC1_VECTOR_BASE: u8 = 0x20;
/// The slave follows immediately after the master's eight lines.
const PIC2_VECTOR_BASE: u8 = 0x28;

/// ICW1: begin initialisation, expect ICW4.
const ICW1_INIT: u8 = 0x11;
/// ICW4: 8086/88 mode.
const ICW4_8086: u8 = 0x01;

/// Remap both PICs out of the exception range, then mask every line.
///
/// # Safety
///
/// Must run before interrupts are enabled, and only once.
pub unsafe fn remap_and_mask() {
    let mut pic1_command = Port::<u8>::new(PIC1_COMMAND);
    let mut pic1_data = Port::<u8>::new(PIC1_DATA);
    let mut pic2_command = Port::<u8>::new(PIC2_COMMAND);
    let mut pic2_data = Port::<u8>::new(PIC2_DATA);

    // SAFETY: these are the architecturally fixed 8259 ports, present on every
    // PC-compatible machine and on QEMU's default machine model. The sequence
    // below is the standard initialisation word order; interrupts are still off,
    // so no IRQ can arrive part-way through it.
    unsafe {
        // ICW1: start the initialisation sequence on both chips.
        pic1_command.write(ICW1_INIT);
        io_wait();
        pic2_command.write(ICW1_INIT);
        io_wait();

        // ICW2: the new vector base for each chip.
        pic1_data.write(PIC1_VECTOR_BASE);
        io_wait();
        pic2_data.write(PIC2_VECTOR_BASE);
        io_wait();

        // ICW3: tell the master a slave hangs off IRQ 2, and tell the slave it
        // is the one hanging there.
        pic1_data.write(1 << 2);
        io_wait();
        pic2_data.write(2);
        io_wait();

        // ICW4: 8086 mode rather than the ancient 8080 mode.
        pic1_data.write(ICW4_8086);
        io_wait();
        pic2_data.write(ICW4_8086);
        io_wait();

        // Mask everything. From here the PIC is inert and the APIC owns
        // interrupt delivery.
        pic1_data.write(0xFF);
        pic2_data.write(0xFF);
    }
}

/// Burn a bus cycle on a port nothing uses.
///
/// The 8259 needs a short settling delay between initialisation words, and on
/// old hardware it is slower than back-to-back `out` instructions allow. Port
/// 0x80 is the POST diagnostic port -- unclaimed on every machine that matters,
/// so writing junk to it is a safe way to spend the time.
unsafe fn io_wait() {
    // SAFETY: port 0x80 is the POST code port; a write is discarded everywhere.
    unsafe { Port::<u8>::new(0x80).write(0u8) }
}
