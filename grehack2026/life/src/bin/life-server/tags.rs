// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The server's half of the tag channel: it reads each request's tags
//! (spec 0377 S2, S5, S8) and, for the echo handshake (spec 0379), smuggles
//! a fresh `"hello client <N>"` into every response and checks the echo the
//! next request carries. The tag work itself is `life::tags`; this is the
//! server's wiring and its state.

use std::io::Write;
use std::sync::atomic::{AtomicU16, Ordering};

/// The N the server last smuggled into a response (spec 0379 S2, S4), to
/// check the next request's echo against. `NONE` before the first response.
/// One value, for the single client of the demo (spec 0379 N1).
static LAST_SENT: AtomicU16 = AtomicU16::new(NONE);
const NONE: u16 = 0x100; // 256: outside a u8, so it means "nothing sent yet"

/// Decode callback (spec 0377 S2): read a request's tags, write the raw bit
/// field to stdout (S5), and check the echo it carries (spec 0379 S4).
pub fn on_request(request: &[u8]) {
    let bits = life::tags::read_tags(request, life::tags::REQUEST);

    // The raw bit field to stdout (spec 0377 S5), one line per request.
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(bits.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();

    // The echo (spec 0379 S4): compare "hi server <N>" with the N we sent.
    if let Some(got) = life::tags::parse_hi(&bits.recover_message()) {
        match LAST_SENT.load(Ordering::Relaxed) {
            NONE => eprintln!("  echo: got {got}, but nothing was sent yet"),
            sent if sent == u16::from(got) => eprintln!("  echo ok ({got})"),
            sent => eprintln!("  echo mismatch (sent {sent}, got {got})"),
        }
    }
}

/// Encode callback (spec 0379 S2): smuggle a fresh `"hello client <N>"` into
/// the response's tags, and record N for the echo check.
pub fn on_response(response: &[u8]) -> Vec<u8> {
    let n = life::tags::random_u8();
    LAST_SENT.store(u16::from(n), Ordering::Relaxed);
    let bits = life::tags::BitField::frame_message(life::tags::hello_client(n).as_bytes());
    life::tags::encode_tags(response, &bits, life::tags::RESPONSE)
}
