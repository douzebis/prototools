// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The server's request callback (spec 0377 S2, S5, S8): read each request's
//! tags into a bit field, write its bytes to stdout, and — when the tags
//! smuggle a message (S3a) — log it to stderr. The reading itself is
//! `life::tags`; this is just the server's wiring.

use std::io::Write;

/// Installed on the codec by `main`, called once per request before it is
/// decoded, with the request's raw bytes.
pub fn report(request: &[u8]) {
    let bits = life::tags::read_tags(request);

    // The raw bit field to stdout (S5), one line per request.
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(bits.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();

    // The smuggled message, if any, to stderr (S8). Empty means none.
    let message = bits.recover_message();
    if !message.is_empty() {
        match std::str::from_utf8(&message) {
            Ok(text) => eprintln!("  smuggled: {text}"),
            Err(_) => eprintln!("  smuggled: {message:02x?}"),
        }
    }
}
