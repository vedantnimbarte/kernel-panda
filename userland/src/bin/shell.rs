//! A line-editing shell over the serial port.
//!
//! The same program that used to be a hand-written assembly blob. Written in
//! Rust it gained the things assembly made impractical: a command table, a
//! prompt that reports the thread it is running as, and room to grow.

#![no_std]
#![no_main]

use panda_user as user;

user::entry!(main);

const MAX_LINE: usize = 128;

extern "C" fn main(_argument: u64) {
    user::write("panda shell -- type 'help'\n");

    let mut line = [0u8; MAX_LINE];

    loop {
        user::write("panda> ");
        let length = read_line(&mut line);
        let command = core::str::from_utf8(&line[..length]).unwrap_or("");

        match command.trim() {
            "" => {}
            "help" => {
                user::write("commands: help version tid echo exit\n");
            }
            "version" => {
                user::write("Kernel Panda, ring 3 shell (rust)\n");
            }
            "tid" => {
                user::write("thread ");
                user::write_number(user::thread_id() as u64);
                user::write("\n");
            }
            "exit" => {
                user::write("shell exiting\n");
                user::exit(0);
            }
            other if other.starts_with("echo ") => {
                user::write(&other[5..]);
                user::write("\n");
            }
            _ => {
                user::write("unknown command\n");
            }
        }
    }
}

/// Read one line, echoing as it goes. Returns its length in bytes.
fn read_line(line: &mut [u8]) -> usize {
    let mut length = 0;

    loop {
        let mut byte = [0u8; 1];
        if user::read(&mut byte) != 1 {
            continue;
        }
        let byte = byte[0];

        if byte == b'\r' || byte == b'\n' {
            user::write("\n");
            return length;
        }

        // Backspace, so a typo is recoverable.
        if byte == 0x08 || byte == 0x7F {
            if length > 0 {
                length -= 1;
                user::write("\x08 \x08");
            }
            continue;
        }

        if length < line.len() {
            line[length] = byte;
            length += 1;
            // SAFETY: a single byte that is not a control code, so valid UTF-8.
            user::write(unsafe { core::str::from_utf8_unchecked(&line[length - 1..length]) });
        }
    }
}
