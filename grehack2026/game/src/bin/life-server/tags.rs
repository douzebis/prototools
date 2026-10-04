// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The server's half of the value channel (specs 0384, 0385): it reads each
//! request's values (spec 0377 S2, S5, S8) and smuggles the command the
//! operator typed on stdin in the next response's values, then prints the
//! command's output that a later request brings back on stdout. With
//! `--self-echo-percentage`, it also sends a command on its own (spec 0379 S8,
//! 0382 S3). No number is special-cased and nothing is factored (spec 0385):
//! every reply is command output, printed exactly. The value work itself is
//! `life::tags`; this is the server's wiring and its state.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

/// A command, as the operator's raw bytes (spec 0385): sent verbatim, run
/// verbatim. The server never parses it — no number is special-cased — so the
/// bytes pass through from the operator's line to the client unchanged.
type Command = Vec<u8>;

/// A one-command slot shared between callbacks and the stdin reader. The
/// callbacks are capture-less `fn` pointers (spec 0379 S1), so the state
/// lives in statics of this type, behind a `Mutex` (spec 0382 S3).
struct Slot(Mutex<Option<Command>>);

impl Slot {
    const fn new() -> Self {
        Slot(Mutex::new(None))
    }

    fn store(&self, n: Command) {
        *self.0.lock().unwrap() = Some(n);
    }

    fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_none()
    }

    /// Empty the slot, returning what it held.
    fn take(&self) -> Option<Command> {
        self.0.lock().unwrap().take()
    }
}

/// The command the operator entered and the server has not sent yet (spec
/// 0379 S2). The latest entry wins: there is no queue.
static PENDING: Slot = Slot::new();

/// The command the server last sent and whose output it has not received yet
/// (spec 0382 S3, 0385). Empty before the first one, and once answered. One
/// value, for the single client of the demo (spec 0382 N4).
static AWAITED: Slot = Slot::new();

/// The command the latest response smuggled, and the output the latest
/// request brought back — each empty when that message hid nothing. Kept for
/// the traffic log's `Capture.contraband` (spec 0391 S2). Not part of the
/// channel protocol; purely what the log reads.
static LAST_COMMAND: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static LAST_OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// The command the latest response smuggled, or empty (spec 0391 S2).
pub fn last_command() -> Vec<u8> {
    LAST_COMMAND.lock().unwrap().clone()
}

/// The command output the latest request brought back, or empty (spec 0391
/// S2).
pub fn last_output() -> Vec<u8> {
    LAST_OUTPUT.lock().unwrap().clone()
}

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

/// The spontaneous command for this response, if the roll fires (spec 0379 S8,
/// 0382 S3): a fixed `echo` the client runs, so the demo shows traffic even
/// with no operator typing.
fn self_echo() -> Option<Command> {
    if !fires(random_u64(), SELF_ECHO_PERCENTAGE.load(Ordering::Relaxed)) {
        return None;
    }
    let command = "echo /\\!\\\\ you have been pwned!";
    if verbose() {
        eprintln!("  command {command:?} sent spontaneously");
    }
    Some(command.to_string().into_bytes())
}

/// Decode callback (spec 0377 S2): read a request's values, write the raw bit
/// field to stdout (S5), and print the command output it carries (spec 0385).
pub fn on_request(request: &[u8]) {
    let bits = life::tags::read_values(request, life::tags::REQUEST);

    // The raw bit field to stdout (spec 0377 S5), one line per request, only
    // under --verbose (spec 0379 S7). The values are read regardless: the
    // reply handling below needs them.
    if verbose() {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(bits.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }

    // The reply (spec 0385): command output, printed as-is. A non-empty
    // recovered message is a reply; the empty message means the client had
    // nothing to send. The awaited command is taken so a reply is reported
    // once.
    let message = bits.recover_message();
    // Spec 0391 S2: every request resets it, so a request that hid nothing
    // logs no contraband rather than the last reply again.
    *LAST_OUTPUT.lock().unwrap() = life::tags::parse_command_output(&message).to_vec();
    if !message.is_empty() {
        let report = report_reply(AWAITED.take().is_some(), &message);
        report.emit();
    }
}

/// What a reply asks the server to emit: command output on stdout (spec 0385
/// S3) or a note on stderr. Pulled out of `on_request` so the decision is
/// testable without the statics or the real stdout.
#[derive(Debug, PartialEq, Eq)]
enum Report {
    /// Stdout, the command's output bytes exactly, plus a trailing newline.
    Stdout(Vec<u8>),
    /// Stderr, a note about a reply with nothing outstanding.
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

/// The report for a reply `message` (spec 0385 S3): the command's output,
/// printed on stdout exactly as it came back (no prefix, no label), when a
/// command was awaited. A reply with nothing outstanding is a stderr note.
fn report_reply(awaited: bool, message: &[u8]) -> Report {
    if !awaited {
        let shown = String::from_utf8_lossy(message);
        return Report::Stderr(format!("  got {shown:?}, but nothing was awaited"));
    }
    let mut line = life::tags::parse_command_output(message).to_vec();
    line.push(b'\n');
    Report::Stdout(line)
}

/// Encode callback (spec 0385): smuggle the operator's pending command, or a
/// spontaneous one, in the response's values.
pub fn on_response(response: &[u8]) -> Vec<u8> {
    let bits = response_message(&PENDING, &AWAITED, self_echo);
    *LAST_COMMAND.lock().unwrap() = bits.recover_message();
    life::tags::encode_values(response, &bits, life::tags::RESPONSE)
}

/// The bit field a response carries (spec 0385): the operator's pending
/// command — framed verbatim by `command_message`, taken so it is sent once —
/// or, with none pending and nothing awaited, the command `roll` returns. The
/// command sent becomes the awaited one, replacing any older. With neither, the
/// empty message. `roll` is called only when nothing is pending or awaited.
fn response_message(
    pending: &Slot,
    awaited: &Slot,
    roll: impl FnOnce() -> Option<Command>,
) -> life::tags::BitField {
    let n = pending
        .take()
        .or_else(|| awaited.is_empty().then(roll).flatten());
    match n {
        Some(n) => {
            let bits = life::tags::BitField::frame_message(&life::tags::command_message(&n));
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

/// Read the operator's commands from stdin on a thread of their own (spec
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
                    eprintln!("  stdin: {e}; no more commands will be read");
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
    fn held(slot: &Slot) -> Option<Command> {
        slot.0.lock().unwrap().clone()
    }

    /// `n`'s decimal digits, used as a command whose exact bytes are easy to
    /// assert on.
    fn d(n: u128) -> Command {
        n.to_string().into_bytes()
    }

    /// The message a response carries, or `None` for the empty message. The
    /// server sends the operator's command verbatim (the smuggled channel),
    /// with no wrapper.
    fn sent(bits: &life::tags::BitField) -> Option<Command> {
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
        // and it stays awaited for the output still to come back.
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
    fn a_reply_prints_the_command_output_exactly() {
        // A command awaited: the output is printed verbatim, with a trailing
        // newline and no prefix or label (spec 0385 S3, G1).
        let reply = life::tags::command_output(b"experiment");
        assert_eq!(
            report_reply(true, &reply),
            Report::Stdout(b"experiment\n".to_vec())
        );
        // No number is special-cased: "42" output prints like any other.
        assert_eq!(
            report_reply(true, &life::tags::command_output(b"42")),
            Report::Stdout(b"42\n".to_vec())
        );
        // A multi-line output keeps its newlines in the printed block.
        let multi = life::tags::command_output(b"line one\nline two");
        assert_eq!(
            report_reply(true, &multi),
            Report::Stdout(b"line one\nline two\n".to_vec())
        );
        // Nothing awaited: a note, not output.
        assert!(matches!(
            report_reply(false, &reply),
            Report::Stderr(note) if note.contains("nothing was awaited")
        ));
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
