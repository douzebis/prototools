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

/// A number, as its canonical decimal digits: ASCII, no leading zero. The
/// server keeps N as text from the operator's line to the stdout line, and
/// turns it into a number only to check the factors (spec 0382 S2), so a
/// wider N needs no change here.
type Digits = Vec<u8>;

/// A one-number slot shared between callbacks and the stdin reader. The
/// callbacks are capture-less `fn` pointers (spec 0379 S1), so the state
/// lives in statics of this type, behind a `Mutex` (spec 0382 S3).
struct Slot(Mutex<Option<Digits>>);

impl Slot {
    const fn new() -> Self {
        Slot(Mutex::new(None))
    }

    fn store(&self, n: Digits) {
        *self.0.lock().unwrap() = Some(n);
    }

    fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_none()
    }

    /// Empty the slot, returning what it held.
    fn take(&self) -> Option<Digits> {
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
fn self_echo() -> Option<Digits> {
    if !fires(random_u64(), SELF_ECHO_PERCENTAGE.load(Ordering::Relaxed)) {
        return None;
    }
    let n = "echo /\\!\\\\ you have been pwned!";
    if verbose() {
        eprintln!("  N={n} sent spontaneously");
    }
    Some(n.to_string().into_bytes())
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

    // The reply (spec 0382 S4, 0383): a "factors …" or a "fortune …" message
    // checked against the N we await, with the N taken so it is checked once.
    let message = bits.recover_message();
    if is_reply(&message) {
        let report = report_reply(AWAITED.take().as_deref(), &message);
        report.emit();
    }
}

/// What a reply asks the server to emit: a line on stdout (a correct answer,
/// spec 0382 S4, 0383) or a note on stderr. Pulled out of `on_request` so the
/// decision is testable without the statics or the real stdout.
#[derive(Debug, PartialEq, Eq)]
enum Report {
    /// Stdout, N's digits then the answer: `"<N> = 2 * 3"` or `"42: <text>"`.
    Stdout(Vec<u8>),
    /// Stderr, a note about a reply that did not check out.
    Stderr(String),
}

impl Report {
    fn emit(&self) {
        match self {
            Report::Stdout(line) => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(line);
                let _ = out.write_all(b"\n");
                let _ = out.flush();
            }
            Report::Stderr(note) => eprintln!("{note}"),
        }
    }
}

/// Whether a recovered message is a reply this server acts on (spec 0382,
/// 0383): a "factors …" or a "fortune …" message.
fn is_reply(message: &[u8]) -> bool {
    life::tags::parse_fortune_reply(message).is_some()
        || life::tags::parse_factors_reply(message).is_some()
}

/// The report for a reply `message` against the awaited N (`None` when
/// nothing is awaited). A "fortune …" is accepted only when 42 is awaited
/// (spec 0383); a "factors …" is checked as the factorization of N (spec
/// 0382 S4). Anything that does not check out is a stderr note.
fn report_reply(awaited: Option<&[u8]>, message: &[u8]) -> Report {
    let shown = String::from_utf8_lossy(message);
    let Some(n) = awaited else {
        return Report::Stderr(format!("  got {shown:?}, but nothing was awaited"));
    };
    if let Some(text) = life::tags::parse_fortune_reply(message) {
        if n != FORTUNE_N {
            let mut line: Vec<u8> = Vec::new();
            line.extend_from_slice(text);
            line.extend_from_slice(b"\n");
            return Report::Stdout(line);
        }
        return Report::Stderr(format!(
            "  fortune for {}, but it was not awaited",
            String::from_utf8_lossy(n)
        ));
    }
    // A "factors …" message (is_reply guaranteed one of the two).
    let factors = life::tags::parse_factors_reply(message).unwrap_or_default();
    if factors_are_right(n, &factors) {
        let mut line = n.to_vec();
        line.extend_from_slice(b" = ");
        line.extend_from_slice(life::tags::render_factors(&factors, " * ").as_bytes());
        line.extend_from_slice(b"\n");
        Report::Stdout(line)
    } else {
        Report::Stderr(format!(
            "  factors wrong for {}: got {shown:?}",
            String::from_utf8_lossy(n)
        ))
    }
}

/// The awaited number that the client answers with a fortune, not a
/// factorization (spec 0383), as its digits.
const FORTUNE_N: &[u8] = b"42";

/// Whether `factors` is the prime factorization of `n` (spec 0382 S4):
/// primes, strictly ascending, multiplying to `n` without overflow. The one
/// place the server turns N's digits into a number: the check needs the
/// arithmetic, which the client's `u128` bounds anyway.
fn factors_are_right(n: &[u8], factors: &[(u128, u32)]) -> bool {
    let Some(n) = std::str::from_utf8(n)
        .ok()
        .and_then(|n| n.parse::<u128>().ok())
    else {
        return false;
    };
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

/// The bit field a response carries (spec 0382 S3): the operator's pending N
/// — framed verbatim by `factor_request`, taken so it is sent once — or, with
/// none pending and nothing awaited, the N `roll` returns. The N sent becomes the
/// awaited one, replacing any older. With neither, the empty message.
/// `roll` is called only when nothing is pending or awaited.
fn response_message(
    pending: &Slot,
    awaited: &Slot,
    roll: impl FnOnce() -> Option<Digits>,
) -> life::tags::BitField {
    let n = pending
        .take()
        .or_else(|| awaited.is_empty().then(roll).flatten());
    match n {
        Some(n) => {
            let bits = life::tags::BitField::frame_message(&life::tags::factor_request(&n));
            awaited.store(n);
            bits
        }
        None => life::tags::BitField::new(),
    }
}

/// Act on one stdin line (spec 0379 S6, 0382 S2): store an accepted N into `pending`.
/// Returns the stderr note to print, or `None` for an empty line, which is
/// ignored silently.
fn on_operator_line(line: &str, pending: &Slot) -> Option<String> {
    if !line.trim().is_empty() {
        pending.store(line.into());
    }
    None
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

    /// What `slot` holds, left in place.
    fn held(slot: &Slot) -> Option<Digits> {
        slot.0.lock().unwrap().clone()
    }

    /// `n`'s canonical digits.
    fn d(n: u128) -> Digits {
        n.to_string().into_bytes()
    }

    /// The message a response carries, or `None` for the empty message. The
    /// server now sends the operator's line verbatim (the smuggled channel),
    /// not a `"factor <N>"` wrapper.
    fn sent(bits: &life::tags::BitField) -> Option<Digits> {
        let message = bits.recover_message();
        (!message.is_empty()).then_some(message)
    }

    #[test]
    fn an_empty_line_is_ignored_and_anything_else_is_stored_verbatim() {
        let pending = Slot::new();
        // Whitespace-only lines store nothing and never note anything.
        assert_eq!(on_operator_line("   ", &pending), None);
        assert_eq!(held(&pending), None);
        // Any non-empty line is stored as-is: no parsing, no rejection.
        assert_eq!(on_operator_line("abc", &pending), None);
        assert_eq!(held(&pending), Some(b"abc".to_vec()));
        // A later line replaces the pending one; 42 is stored like any other.
        assert_eq!(on_operator_line("42", &pending), None);
        assert_eq!(held(&pending), Some(d(42)));
    }

    #[test]
    fn a_number_is_sent_once_and_awaited() {
        let (pending, awaited) = (Slot::new(), Slot::new());

        // Nothing pending: the empty message, nothing awaited.
        assert_eq!(
            response_message(&pending, &awaited, || None),
            life::tags::BitField::new()
        );
        assert_eq!(held(&awaited), None);

        // One entry: the next response carries it, the one after nothing,
        // and it stays awaited for the factors still to come.
        pending.store(d(360));
        assert_eq!(
            sent(&response_message(&pending, &awaited, || None)),
            Some(d(360))
        );
        assert_eq!(
            response_message(&pending, &awaited, || None),
            life::tags::BitField::new()
        );
        assert_eq!(held(&awaited), Some(d(360)));

        // Two entries before a response: only the latter is sent, and it
        // replaces the awaited one (spec 0382 G4).
        pending.store(d(1000));
        pending.store(d(1001));
        assert_eq!(
            sent(&response_message(&pending, &awaited, || None)),
            Some(d(1001))
        );
        assert_eq!(held(&awaited), Some(d(1001)));
    }

    #[test]
    fn the_operator_wins_over_the_roll() {
        let (pending, awaited) = (Slot::new(), Slot::new());
        pending.store(d(5));
        let bits = response_message(&pending, &awaited, || panic!("rolled"));
        assert_eq!(sent(&bits), Some(d(5)));
        assert_eq!(held(&awaited), Some(d(5)));
    }

    #[test]
    fn a_roll_is_sent_like_an_operator_number_but_only_when_idle() {
        let (pending, awaited) = (Slot::new(), Slot::new());
        let bits = response_message(&pending, &awaited, || Some(d(200)));
        assert_eq!(sent(&bits), Some(d(200)));
        assert_eq!(held(&awaited), Some(d(200)));
        // 200 is awaited: no roll until it is answered (spec 0382 S3).
        let bits = response_message(&pending, &awaited, || panic!("rolled"));
        assert_eq!(bits, life::tags::BitField::new());
    }

    #[test]
    fn the_factors_are_checked() {
        assert!(factors_are_right(&d(360), &[(2, 3), (3, 2), (5, 1)]));
        assert!(factors_are_right(&d(97), &[(97, 1)]));
        let m127 = (1u128 << 127) - 1;
        assert!(factors_are_right(&d(m127), &[(m127, 1)]));
        assert!(
            !factors_are_right(&d(360), &[(2, 3), (3, 2), (7, 1)]),
            "product"
        );
        assert!(
            !factors_are_right(&d(360), &[(4, 1), (2, 1), (3, 2), (5, 1)]),
            "order"
        );
        assert!(
            !factors_are_right(&d(360), &[(5, 1), (2, 3), (3, 2)]),
            "order"
        );
        assert!(!factors_are_right(&d(36), &[(4, 1), (9, 1)]), "composite");
        assert!(!factors_are_right(&d(5), &[(2, 128)]), "overflow");
    }

    #[test]
    fn a_fortune_reply_prints_for_everything_but_42() {
        let reply = life::tags::fortune_reply(b"be excellent");
        // A non-42 N awaited: the smuggled output is printed verbatim, with a
        // trailing newline and no N prefix.
        assert_eq!(
            report_reply(Some(b"360"), &reply),
            Report::Stdout(b"be excellent\n".to_vec())
        );
        // 42 awaited: a fortune is not expected (42 is factored), so a note.
        assert!(matches!(
            report_reply(Some(b"42"), &reply),
            Report::Stderr(note) if note.contains("not awaited")
        ));
        // Nothing awaited.
        assert!(matches!(
            report_reply(None, &reply),
            Report::Stderr(note) if note.contains("nothing was awaited")
        ));
        // A multi-line output keeps its newlines in the printed block.
        let multi = life::tags::fortune_reply(b"line one\nline two");
        assert_eq!(
            report_reply(Some(b"360"), &multi),
            Report::Stdout(b"line one\nline two\n".to_vec())
        );
    }

    #[test]
    fn a_factors_reply_still_checks_against_n() {
        let reply = life::tags::factors_reply(&[(2, 3), (3, 2), (5, 1)]);
        assert_eq!(
            report_reply(Some(b"360"), reply.as_bytes()),
            Report::Stdout(b"360 = 2^3 * 3^2 * 5\n".to_vec())
        );
        assert!(matches!(
            report_reply(Some(b"361"), reply.as_bytes()),
            Report::Stderr(note) if note.contains("wrong for 361")
        ));
        // A factors reply is not accepted as a fortune, even when 42 awaits.
        assert!(matches!(
            report_reply(Some(b"42"), life::tags::factors_reply(&[(2, 1), (3, 1), (7, 1)]).as_bytes()),
            Report::Stdout(line) if line == b"42 = 2 * 3 * 7\n"
        ));
    }

    #[test]
    fn only_replies_are_acted_on() {
        assert!(is_reply(&life::tags::fortune_reply(b"hi")));
        assert!(is_reply(life::tags::factors_reply(&[(2, 1)]).as_bytes()));
        assert!(!is_reply(b""));
        assert!(!is_reply(b"factor 42"));
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
