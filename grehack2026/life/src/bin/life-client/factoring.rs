// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The client's half of the factoring exchange (spec 0382 S5). A response's
//! `"factor <N>"` starts a worker thread that factors N while the game keeps
//! stepping; the worker leaves its `"factors …"` reply in an outbox, which
//! the next request carries. A newer N abandons the older one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A finished reply, and whether a request has carried it yet.
struct Outbox {
    reply: String,
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

    /// Abandon the job in progress and any reply not yet settled, and
    /// factor `n` on a thread of its own.
    pub fn start(&'static self, n: u128) -> std::thread::JoinHandle<()> {
        let job = {
            let mut outbox = self.outbox.lock().unwrap();
            *outbox = None;
            self.job.fetch_add(1, Ordering::Relaxed) + 1
        };
        std::thread::spawn(move || {
            let current = || self.job.load(Ordering::Relaxed) == job;
            if let Some(factors) = life::factor::factorize(n, &current) {
                // Checked under the lock `start` takes, so a reply to an
                // abandoned N cannot slip in after the newer N cleared it.
                let mut outbox = self.outbox.lock().unwrap();
                if current() {
                    *outbox = Some(Outbox {
                        reply: life::tags::factors_reply(&factors),
                        sent: false,
                    });
                }
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
                outbox.reply.clone().into_bytes()
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
