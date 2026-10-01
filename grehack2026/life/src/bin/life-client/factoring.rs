// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The client's half of the factoring exchange (spec 0382 S5). A response's
//! `"factor <N>"` starts a worker thread that factors N while the game keeps
//! stepping; the worker leaves its `"factors …"` reply in an outbox, which
//! the next request carries. A newer N abandons the older one.
//!
//! The number 42 is a special case (spec 0383): instead of factoring, the
//! worker runs the `fortune` program and sends its output back as
//! `"fortune <text>"`.

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
    pub fn start(&'static self, n: u128) -> std::thread::JoinHandle<()> {
        let job = {
            let mut outbox = self.outbox.lock().unwrap();
            *outbox = None;
            self.job.fetch_add(1, Ordering::Relaxed) + 1
        };
        std::thread::spawn(move || {
            let current = || self.job.load(Ordering::Relaxed) == job;
            let Some(reply) = work(n, &current) else {
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
fn work(n: u128, keep_going: &dyn Fn() -> bool) -> Option<Vec<u8>> {
    if n == FORTUNE_N {
        return Some(life::tags::fortune_reply(&run_fortune()));
    }
    let factors = life::factor::factorize(n, keep_going)?;
    Some(life::tags::factors_reply(&factors).into_bytes())
}

/// The number that runs `fortune` rather than being factored (spec 0383).
const FORTUNE_N: u128 = 42;

/// Run `fortune` and return its stdout (spec 0383). `fortune` is on the
/// client's PATH, wrapped into the binary by Nix, so this does not depend on
/// the shell. On a non-zero exit or a spawn failure, the stderr or the error
/// stands in, so the server always has something to show.
fn run_fortune() -> Vec<u8> {
    let result = crate::command::run_command("fortune".to_string());
    if result.status == "exit 0" && !result.stdout.is_empty() {
        result.stdout
    } else if !result.stderr.is_empty() {
        result.stderr
    } else {
        format!("fortune: {}", result.status).into_bytes()
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
        f.start(360).join().unwrap();
        assert_eq!(f.message(), b"factors 2^3*3^2*5");
        // A retry, before settle, carries it again.
        assert_eq!(f.message(), b"factors 2^3*3^2*5");
        f.settle();
        assert_eq!(f.message(), b"");
    }

    #[test]
    fn a_reply_stored_after_the_encode_survives_settle() {
        let f = fresh();
        assert_eq!(f.message(), b""); // the request goes out empty
        f.start(97).join().unwrap(); // a worker finishes during the step
        f.settle();
        assert_eq!(f.message(), b"factors 97");
    }

    #[test]
    fn forty_two_runs_fortune_not_a_factorization() {
        let f = fresh();
        f.start(42).join().unwrap();
        let message = f.message();
        // Always a "fortune ..." reply, factored or not: with fortune on
        // PATH it is its output, otherwise the error stands in, but never the
        // factorization 2*3*7.
        assert!(
            life::tags::parse_fortune_reply(&message).is_some(),
            "want a fortune reply, got {:?}",
            String::from_utf8_lossy(&message)
        );
        assert!(!message.windows(5).any(|w| w == b"2*3*7"));
    }

    #[test]
    fn a_newer_number_abandons_the_older_one() {
        let f = fresh();
        // Two primes near 2^61 and 2^64: rho would take about 2^30 steps,
        // so this worker is still polling when 12 replaces it.
        let slow = f.start(((1u128 << 61) - 1) * 18_446_744_073_709_551_557);
        f.start(12).join().unwrap();
        slow.join().unwrap();
        assert_eq!(f.message(), b"factors 2^2*3");
    }
}
