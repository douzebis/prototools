// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The server's half of the tag channel: it reads each request's tags
//! (spec 0377 S2, S5, S8) and, for the factoring exchange (spec 0382), sends
//! the number the operator typed on stdin in the next response as
//! `"factor <N>"`, then checks the factors a later request brings back and
//! prints them on stdout. With `--self-echo-percentage`, it also sends random
//! numbers on its own (spec 0379 S8, 0382 S3). The tag work itself is
//! `life::tags`; this is the server's wiring and its state.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

/// A one-number slot shared between callbacks and the stdin reader. The
/// callbacks are capture-less `fn` pointers (spec 0379 S1), so the state
/// lives in statics of this type; a `Mutex`, as there is no stable
/// `AtomicU128` (spec 0382 S3).
struct Slot(Mutex<Option<u128>>);

impl Slot {
    const fn new() -> Self {
        Slot(Mutex::new(None))
    }

    fn store(&self, n: u128) {
        *self.0.lock().unwrap() = Some(n);
    }

    fn get(&self) -> Option<u128> {
        *self.0.lock().unwrap()
    }

    /// Empty the slot, returning what it held.
    fn take(&self) -> Option<u128> {
        self.0.lock().unwrap().take()
    }
}

/// The N the operator entered and the server has not sent yet (spec 0379
/// S2). The latest entry wins: there is no queue.
static PENDING: Slot = Slot::new();

/// The N the server last sent and whose factors it has not received yet
/// (spec 0382 S3, S4). Empty before the first one, and once answered. One
/// value, for the single client of the demo (spec 0382 N4).
static AWAITED: Slot = Slot::new();

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

/// The spontaneous N for this response, if the roll fires (spec 0379 S8): a
/// random `u64`, at least 2 (spec 0382 S3).
fn self_echo() -> Option<u128> {
    if !fires(random_u64(), SELF_ECHO_PERCENTAGE.load(Ordering::Relaxed)) {
        return None;
    }
    let n = u128::from(random_u64().max(2));
    if verbose() {
        eprintln!("  N={n} sent spontaneously");
    }
    Some(n)
}

/// Decode callback (spec 0377 S2): read a request's tags, write the raw bit
/// field to stdout (S5), and check the factors it carries (spec 0382 S4).
pub fn on_request(request: &[u8]) {
    let bits = life::tags::read_tags(request, life::tags::REQUEST);

    // The raw bit field to stdout (spec 0377 S5), one line per request, only
    // under --verbose (spec 0379 S7). The tags are read regardless: the factors
    // check below needs them.
    if verbose() {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(bits.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }

    // The factors (spec 0382 S4): check them against the N we await.
    let message = bits.recover_message();
    if let Some(factors) = life::tags::parse_factors_reply(&message) {
        let shown = String::from_utf8_lossy(&message);
        match AWAITED.take() {
            None => eprintln!("  got {shown:?}, but nothing was awaited"),
            Some(n) if factors_are_right(n, &factors) => {
                let mut out = std::io::stdout().lock();
                let display = life::tags::render_factors(&factors, " * ");
                let _ = writeln!(out, "{n} = {display}");
                let _ = out.flush();
            }
            Some(n) => eprintln!("  factors wrong for {n}: got {shown:?}"),
        }
    }
}

/// Whether `factors` is the prime factorization of `n` (spec 0382 S4):
/// primes, strictly ascending, multiplying to `n` without overflow.
fn factors_are_right(n: u128, factors: &[(u128, u32)]) -> bool {
    let ascending = factors.windows(2).all(|w| w[0].0 < w[1].0);
    let primes = factors.iter().all(|&(p, _)| life::factor::is_prime(p));
    let product = factors
        .iter()
        .try_fold(1u128, |acc, &(p, e)| acc.checked_mul(p.checked_pow(e)?));
    ascending && primes && product == Some(n)
}

/// Encode callback (spec 0382 S3): send the operator's pending N, or a
/// spontaneous one, in the response's tags.
pub fn on_response(response: &[u8]) -> Vec<u8> {
    let bits = response_message(&PENDING, &AWAITED, self_echo);
    life::tags::encode_tags(response, &bits, life::tags::RESPONSE)
}

/// The bit field a response carries (spec 0382 S3): `"factor <N>"` for the
/// operator's pending N — taken, so it is sent once — or, with none pending
/// and nothing awaited, for the N `roll` returns. The N sent becomes the
/// awaited one, replacing any older. With neither, the empty message.
/// `roll` is called only when nothing is pending or awaited.
fn response_message(
    pending: &Slot,
    awaited: &Slot,
    roll: impl FnOnce() -> Option<u128>,
) -> life::tags::BitField {
    let n = pending
        .take()
        .or_else(|| awaited.get().is_none().then(roll).flatten());
    match n {
        Some(n) => {
            awaited.store(n);
            life::tags::BitField::frame_message(life::tags::factor_request(n).as_bytes())
        }
        None => life::tags::BitField::new(),
    }
}

/// The operator's number on a stdin line (spec 0382 S2): ASCII digits,
/// value 2..=`u128::MAX`, leading zeros and surrounding whitespace ignored.
/// Anything else — a sign, a non-digit, 0 or 1, a larger value, the empty
/// line — is `None`.
fn parse_operator_n(line: &str) -> Option<u128> {
    let digits = line.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u128>().ok().filter(|&n| n >= 2)
}

/// Act on one stdin line (spec 0379 S6, 0382 S2): store an accepted N into `pending`.
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
        None => format!(
            "  rejected {:?}: want an integer 2..={}",
            line.trim(),
            u128::MAX
        ),
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

    fn sent(bits: &life::tags::BitField) -> Option<u128> {
        life::tags::parse_factor_request(&bits.recover_message())
    }

    #[test]
    fn operator_n_accepts_2_to_u128_max() {
        let max = u128::MAX.to_string();
        for (line, n) in [
            ("2", 2),
            ("007", 7),
            (" 42 ", 42),
            ("9\r", 9),
            (max.as_str(), u128::MAX),
        ] {
            assert_eq!(parse_operator_n(line), Some(n), "{line:?}");
        }
    }

    #[test]
    fn operator_n_rejects_the_rest() {
        for line in [
            "",
            "0",
            "1",
            "340282366920938463463374607431768211456", // u128::MAX + 1
            "-1",
            "+5",
            "4 2",
            "0x10",
            "abc",
            "٣",
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
    fn a_number_is_sent_once_and_awaited() {
        let (pending, awaited) = (Slot::new(), Slot::new());

        // Nothing pending: the empty message, nothing awaited.
        assert_eq!(
            response_message(&pending, &awaited, || None),
            life::tags::BitField::new()
        );
        assert_eq!(awaited.get(), None);

        // One entry: the next response carries it, the one after nothing,
        // and it stays awaited for the factors still to come.
        pending.store(360);
        assert_eq!(
            sent(&response_message(&pending, &awaited, || None)),
            Some(360)
        );
        assert_eq!(
            response_message(&pending, &awaited, || None),
            life::tags::BitField::new()
        );
        assert_eq!(awaited.get(), Some(360));

        // Two entries before a response: only the latter is sent, and it
        // replaces the awaited one (spec 0382 G4).
        pending.store(1000);
        pending.store(1001);
        assert_eq!(
            sent(&response_message(&pending, &awaited, || None)),
            Some(1001)
        );
        assert_eq!(awaited.get(), Some(1001));
    }

    #[test]
    fn the_operator_wins_over_the_roll() {
        let (pending, awaited) = (Slot::new(), Slot::new());
        pending.store(5);
        let bits = response_message(&pending, &awaited, || panic!("rolled"));
        assert_eq!(sent(&bits), Some(5));
        assert_eq!(awaited.get(), Some(5));
    }

    #[test]
    fn a_roll_is_sent_like_an_operator_number_but_only_when_idle() {
        let (pending, awaited) = (Slot::new(), Slot::new());
        let bits = response_message(&pending, &awaited, || Some(200));
        assert_eq!(sent(&bits), Some(200));
        assert_eq!(awaited.get(), Some(200));
        // 200 is awaited: no roll until it is answered (spec 0382 S3).
        let bits = response_message(&pending, &awaited, || panic!("rolled"));
        assert_eq!(bits, life::tags::BitField::new());
    }

    #[test]
    fn the_factors_are_checked() {
        assert!(factors_are_right(360, &[(2, 3), (3, 2), (5, 1)]));
        assert!(factors_are_right(97, &[(97, 1)]));
        let m127 = (1u128 << 127) - 1;
        assert!(factors_are_right(m127, &[(m127, 1)]));
        assert!(
            !factors_are_right(360, &[(2, 3), (3, 2), (7, 1)]),
            "product"
        );
        assert!(
            !factors_are_right(360, &[(4, 1), (2, 1), (3, 2), (5, 1)]),
            "order"
        );
        assert!(!factors_are_right(360, &[(5, 1), (2, 3), (3, 2)]), "order");
        assert!(!factors_are_right(36, &[(4, 1), (9, 1)]), "composite");
        assert!(!factors_are_right(5, &[(2, 128)]), "overflow");
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
