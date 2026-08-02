//! The input daemon.
//!
//! Owns console input and forwards what it approves of to a single endpoint.
//! It is the only process holding a read capability on the console, which is
//! what stops anything else from watching the keyboard.

#![no_std]
#![no_main]

use panda_user as user;

user::entry!(main);

/// Ends the session, and tells the consumer to shut down too.
const ESCAPE: u8 = 0x1B;

extern "C" fn main(endpoint: u64) {
    loop {
        let mut byte = [0u8; 1];
        if user::read(&mut byte) != 1 {
            continue;
        }
        let byte = byte[0];

        if byte == ESCAPE {
            // Tag zero is the agreed shutdown.
            user::ipc_send(endpoint, &user::Message::default());
            user::exit(0);
        }

        // Sanitise: printable ASCII and the two line endings, nothing else. A
        // consumer should never see a byte it did not ask for.
        let acceptable = (0x20..=0x7E).contains(&byte) || byte == b'\n' || byte == b'\r';
        if !acceptable {
            continue;
        }

        let message = user::Message {
            tag: 1,
            words: [byte as u64, 0, 0, 0],
            sender: 0,
        };
        user::ipc_send(endpoint, &message);
    }
}
