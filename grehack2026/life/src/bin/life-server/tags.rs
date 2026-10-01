// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The server's half of the tag channel: it reads each request's tags
//! (spec 0377 S2, S5, S8) and, for the echo handshake (spec 0379), smuggles
//! the number the operator typed on stdin into the next response as
//! `"hello client <N>"`, then checks the echo the following request carries.
//! With `--self-echo-percentage`, it also sends random numbers on its own
//! (spec 0379 S8). The tag work itself is `life::tags`; this is the server's
//! wiring and its state.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};

/// A one-number slot shared between callbacks and the stdin reader, `NONE`
/// when empty. The callbacks are capture-less `fn` pointers (spec 0379 S1),
/// so the state lives in statics of this type.
struct Slot(AtomicU16);

const NONE: u16 = 0x100; // 256: outside a u8, so it means "empty"

impl Slot {
    const fn new() -> Self {
        Slot(AtomicU16::new(NONE))
    }

    fn store(&self, n: u8) {
        self.0.store(u16::from(n), Ordering::Relaxed);
    }

    fn get(&self) -> Option<u8> {
        u8::try_from(self.0.load(Ordering::Relaxed)).ok()
    }

    /// Empty the slot, returning what it held.
    fn take(&self) -> Option<u8> {
        u8::try_from(self.0.swap(NONE, Ordering::Relaxed)).ok()
    }
}

/// The N the operator entered and the server has not sent yet (spec 0379
/// S2). The latest entry wins: there is no queue.
static PENDING: Slot = Slot::new();

/// The N the server last smuggled into a response (spec 0379 S2, S4), to
/// check the next request's echo against. Empty before the first one.
/// One value, for the single client of the demo (spec 0379 N1).
static LAST_SENT: Slot = Slot::new();

/// `--verbose` (spec 0379 S7): print the per-request output.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// `--self-echo-percentage` (spec 0379 S8), 0..=100.
static SELF_ECHO_PERCENTAGE: AtomicU8 = AtomicU8::new(0);

/// The xorshift state of the spontaneous echoes (spec 0379 S8), one stream
/// for all tokio workers. Seeded by `configure`; never zero after that.
static RNG: AtomicU64 = AtomicU64::new(0);

/// Record the flags the capture-less callbacks read (spec 0379 S7, S8), and
/// seed the generator from the clock (as the client's grid fill, 0375 S5).
/// Called once, before serving.
pub fn configure(verbose: bool, self_echo_percentage: u8) {
    use std::time::{SystemTime, UNIX_EPOCH};
    VERBOSE.store(verbose, Ordering::Relaxed);
    SELF_ECHO_PERCENTAGE.store(self_echo_percentage, Ordering::Relaxed);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0x9e37_79b9, |d| d.as_nanos() as u64)
        | 1;
    RNG.store(seed, Ordering::Relaxed);
}

/// Whether to print the per-request output (spec 0379 S7).
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

fn xorshift(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// The next draw of the shared generator.
fn random_u64() -> u64 {
    let old = RNG
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| Some(xorshift(x)))
        .unwrap_or_else(|x| x);
    xorshift(old)
}

/// Whether a draw fires at `percentage` % (spec 0379 S8): a uniform draw in
/// 0..100 below the percentage. 0 never fires, 100 always does.
fn fires(draw: u64, percentage: u8) -> bool {
    draw % 100 < u64::from(percentage)
}

/// The spontaneous N for this response, if the roll fires (spec 0379 S8).
fn self_echo() -> Option<u8> {
    if !fires(random_u64(), SELF_ECHO_PERCENTAGE.load(Ordering::Relaxed)) {
        return None;
    }
    let n = (random_u64() >> 56) as u8;
    if verbose() {
        eprintln!("  N={n} sent spontaneously");
    }
    Some(n)
}

/// Decode callback (spec 0377 S2): read a request's tags, write the raw bit
/// field to stdout (S5), and check the echo it carries (spec 0379 S4).
pub fn on_request(request: &[u8]) {
    let bits = life::tags::read_tags(request, life::tags::REQUEST);

    // The raw bit field to stdout (spec 0377 S5), one line per request, only
    // under --verbose (spec 0379 S7). The tags are read regardless: the echo
    // check below needs them.
    if verbose() {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(bits.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }

    // The echo (spec 0379 S4): compare "hi server <N>" with the N we sent.
    if let Some(got) = life::tags::parse_hi(&bits.recover_message()) {
        match LAST_SENT.get() {
            None => eprintln!("  echo: got {got}, but nothing was sent yet"),
            Some(sent) if sent == got => eprintln!("  echo ok ({got})"),
            Some(sent) => eprintln!("  echo mismatch (sent {sent}, got {got})"),
        }
    }
}

/// Encode callback (spec 0379 S2, S8): smuggle the operator's pending N, or
/// else maybe a spontaneous one, into the response's tags.
pub fn on_response(response: &[u8]) -> Vec<u8> {
    let bits = response_message(&PENDING, &LAST_SENT, self_echo);
    life::tags::encode_tags(response, &bits, life::tags::RESPONSE)
}

/// The bit field a response carries (spec 0379 S2, S8): `"hello client <N>"`
/// for the operator's pending N — taken, so it is sent once — or, with none
/// pending, for the N `roll` returns; the N sent is recorded as the last
/// sent. With neither, the empty message, leaving the last sent unchanged
/// for the echo still to come. `roll` is not called when the operator's N
/// is sent.
fn response_message(
    pending: &Slot,
    last_sent: &Slot,
    roll: impl FnOnce() -> Option<u8>,
) -> life::tags::BitField {
    match pending.take().or_else(roll) {
        Some(n) => {
            last_sent.store(n);
            life::tags::BitField::frame_message(life::tags::hello_client(n).as_bytes())
        }
        None => life::tags::BitField::new(),
    }
}

/// The operator's number on a stdin line (spec 0379 S6): one to three ASCII
/// digits, value 0..=255, surrounding whitespace ignored. Anything else —
/// a sign, a non-digit, a larger value, the empty line — is `None`.
fn parse_operator_n(line: &str) -> Option<u8> {
    let digits = line.trim();
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u8>().ok()
}

/// Act on one stdin line (spec 0379 S6): store an accepted N into `pending`.
/// Returns the stderr note to print, or `None` for an empty line, which is
/// ignored silently.
fn on_operator_line(line: &str, pending: &Slot) -> Option<String> {
    if line.trim().is_empty() {
        return None;
    }
    Some(match parse_operator_n(line) {
        Some(n) => {
            pending.store(n);
            format!("  N={n} queued for the next response")
        }
        None => format!("  rejected {:?}: want an integer 0..=255", line.trim()),
    })
}

/// Read the operator's numbers from stdin on a thread of their own (spec
/// 0379 S6), beside the RPCs. End of file ends the thread quietly; a read
/// error ends it after one note. Either way the server keeps serving.
pub fn spawn_stdin_reader() {
    std::thread::spawn(|| {
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(line) => {
                    if let Some(note) = on_operator_line(&line, &PENDING) {
                        eprintln!("{note}");
                    }
                }
                Err(e) => {
                    eprintln!("  stdin: {e}; no more numbers will be read");
                    return;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_n_accepts_0_to_255() {
        for (line, n) in [("0", 0), ("255", 255), ("007", 7), (" 42 ", 42), ("9\r", 9)] {
            assert_eq!(parse_operator_n(line), Some(n), "{line:?}");
        }
    }

    #[test]
    fn operator_n_rejects_the_rest() {
        for line in [
            "", "256", "-1", "+5", "4 2", "0x10", "1000", "0255", "abc", "٣",
        ] {
            assert_eq!(parse_operator_n(line), None, "{line:?}");
        }
    }

    #[test]
    fn an_empty_line_is_ignored_not_rejected() {
        let pending = Slot::new();
        assert_eq!(on_operator_line("   ", &pending), None);
        assert!(on_operator_line("abc", &pending)
            .unwrap()
            .contains("rejected"));
        assert_eq!(pending.get(), None);
        assert!(on_operator_line("42", &pending).unwrap().contains("queued"));
        assert_eq!(pending.get(), Some(42));
    }

    #[test]
    fn a_number_is_sent_once() {
        let (pending, last_sent) = (Slot::new(), Slot::new());

        // Nothing pending: the empty message, nothing recorded.
        assert_eq!(
            response_message(&pending, &last_sent, || None),
            life::tags::BitField::new()
        );
        assert_eq!(last_sent.get(), None);

        // One entry: the next response carries it, the one after nothing,
        // and the last sent survives for the echo check.
        pending.store(7);
        let bits = response_message(&pending, &last_sent, || None);
        assert_eq!(life::tags::parse_hello(&bits.recover_message()), Some(7));
        assert_eq!(
            response_message(&pending, &last_sent, || None),
            life::tags::BitField::new()
        );
        assert_eq!(last_sent.get(), Some(7));

        // Two entries before a response: only the latter is sent.
        pending.store(1);
        pending.store(2);
        let bits = response_message(&pending, &last_sent, || None);
        assert_eq!(life::tags::parse_hello(&bits.recover_message()), Some(2));
        assert_eq!(last_sent.get(), Some(2));
    }

    #[test]
    fn the_operator_wins_over_the_roll() {
        let (pending, last_sent) = (Slot::new(), Slot::new());
        pending.store(5);
        let bits = response_message(&pending, &last_sent, || panic!("rolled"));
        assert_eq!(life::tags::parse_hello(&bits.recover_message()), Some(5));
        assert_eq!(last_sent.get(), Some(5));
    }

    #[test]
    fn a_roll_is_sent_like_an_operator_number() {
        let (pending, last_sent) = (Slot::new(), Slot::new());
        let bits = response_message(&pending, &last_sent, || Some(200));
        assert_eq!(life::tags::parse_hello(&bits.recover_message()), Some(200));
        assert_eq!(last_sent.get(), Some(200));
    }

    #[test]
    fn zero_never_fires_and_a_hundred_always_does() {
        configure(false, 0);
        for _ in 0..1000 {
            let draw = random_u64();
            assert!(!fires(draw, 0));
            assert!(fires(draw, 100));
        }
    }

    #[test]
    fn the_draws_vary() {
        configure(false, 0);
        let a: Vec<u64> = (0..8).map(|_| random_u64()).collect();
        assert!(a.iter().any(|&x| x != a[0]), "not all identical: {a:?}");
    }
}
