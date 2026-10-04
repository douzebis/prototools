// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The client's half of the smuggled command channel (specs 0384, 0385). The
//! command bytes a response carries start a worker thread while the game keeps
//! stepping; the worker leaves the command's output in an outbox, which the
//! next request carries. A newer command abandons the older one.
//!
//! Every non-empty command is run (`sh -c <command>`, spec 0380's
//! `run_command`) and its output rides back exactly (spec 0385): no number is
//! special-cased, nothing is factored, and no prefix is added.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A finished reply (the framed output bytes), and whether a request has
/// carried it yet.
struct Outbox {
    reply: Vec<u8>,
    sent: bool,
}

/// The current job and its outbox. The codec callbacks are capture-less
/// `fn` pointers (spec 0379 S1), so the client keeps one in a static.
pub struct CommandChannel {
    /// Bumped by every new command; a worker whose command is no longer
    /// current stores nothing (spec 0382 G4).
    job: AtomicU64,
    outbox: Mutex<Option<Outbox>>,
}

impl CommandChannel {
    pub const fn new() -> Self {
        CommandChannel {
            job: AtomicU64::new(0),
            outbox: Mutex::new(None),
        }
    }

    /// Run `command` on a thread of its own, abandoning the job in progress and
    /// any reply not yet settled, and leave its output for the next request
    /// (spec 0385 S2). Returns the worker's handle, or `None` when there is
    /// nothing to do.
    ///
    /// An **empty** command — what the server sends every step when it has no
    /// new command (spec 0385, the empty message) — is a no-op: it must *not*
    /// abandon the in-flight worker or clear a reply waiting to be carried back,
    /// or the output of the one real command would be wiped by the stream of
    /// empties that follows it before a request can carry it. So only a
    /// non-empty command starts (and abandons) a job.
    pub fn start(&'static self, command: Vec<u8>) -> Option<std::thread::JoinHandle<()>> {
        if command.is_empty() {
            return None;
        }
        let job = {
            let mut outbox = self.outbox.lock().unwrap();
            *outbox = None;
            self.job.fetch_add(1, Ordering::Relaxed) + 1
        };
        Some(std::thread::spawn(move || {
            let current = || self.job.load(Ordering::Relaxed) == job;
            let Some(reply) = work(&command, &current) else {
                return;
            };
            // Checked under the lock `start` takes, so a reply to an
            // abandoned command cannot slip in after the newer one cleared it.
            let mut outbox = self.outbox.lock().unwrap();
            if current() {
                *outbox = Some(Outbox { reply, sent: false });
            }
        }))
    }

    /// The message for the next request: the finished output, marked sent
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

/// The reply for `command`: its output bytes, exactly (spec 0385 S1, G1), or
/// `None` for the empty command (nothing to run). The command is run even when
/// the job is abandoned mid-run — `run_command` does not poll — but the caller
/// drops the reply if the job is no longer current, so `keep_going` is unused
/// here and kept only for the abandon check the caller still performs.
fn work(command: &[u8], _keep_going: &dyn Fn() -> bool) -> Option<Vec<u8>> {
    if command.is_empty() {
        return None;
    }
    Some(life::tags::command_output(&run(command)))
}

/// Run `command` and return its stdout (spec 0380, 0385 S2). `run_command`
/// already runs its argument as `sh -c <command>`, so the command bytes are
/// passed straight through, not wrapped again. On a non-zero exit or a spawn
/// failure, the stderr or the rendered status stands in, so the server always
/// has something to show.
fn run(command: &[u8]) -> Vec<u8> {
    let result = crate::command::run_command(String::from_utf8_lossy(command).into_owned());
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

    fn fresh() -> &'static CommandChannel {
        Box::leak(Box::new(CommandChannel::new()))
    }

    #[test]
    fn a_reply_is_carried_until_the_step_succeeds() {
        let c = fresh();
        assert_eq!(c.message(), b"");
        // A command runs as a shell command; its output rides back exactly,
        // with no prefix (spec 0385).
        c.start(b"echo hi".to_vec()).unwrap().join().unwrap();
        assert_eq!(c.message(), b"hi");
        // A retry, before settle, carries it again.
        assert_eq!(c.message(), b"hi");
        c.settle();
        assert_eq!(c.message(), b"");
    }

    #[test]
    fn a_reply_stored_after_the_encode_survives_settle() {
        let c = fresh();
        assert_eq!(c.message(), b""); // the request goes out empty
        c.start(b"echo kept".to_vec()).unwrap().join().unwrap(); // a worker finishes during the step
        c.settle();
        assert_eq!(c.message(), b"kept");
    }

    #[test]
    fn an_empty_command_is_a_no_op() {
        let c = fresh();
        // An empty command starts no worker (returns None) and leaves state
        // untouched: nothing is stored.
        assert!(c.start(b"".to_vec()).is_none());
        assert_eq!(c.message(), b"");
    }

    #[test]
    fn a_stream_of_empties_does_not_wipe_a_pending_reply() {
        // The real bug this guards (specs 0384/0385): the server sends the one
        // command, then an empty message every step after. Those empties must
        // not abandon the in-flight worker or clear the reply before a request
        // carries it back.
        let c = fresh();
        c.start(b"echo kept".to_vec()).unwrap().join().unwrap();
        // Empties arrive before the reply is carried: they are no-ops.
        assert!(c.start(b"".to_vec()).is_none());
        assert!(c.start(b"".to_vec()).is_none());
        // The reply is still there to carry.
        assert_eq!(c.message(), b"kept");
    }

    #[test]
    fn every_command_runs_including_numbers() {
        let c = fresh();
        // No number is special-cased (spec 0385 G2): "42" runs as a command
        // like any other, it is not factored. `echo` makes the output visible.
        c.start(b"echo 42".to_vec()).unwrap().join().unwrap();
        assert_eq!(c.message(), b"42");
    }

    #[test]
    fn a_newer_message_abandons_the_older_one() {
        let c = fresh();
        // A slow command still running when the next one replaces it; its
        // reply is dropped because the job is no longer current.
        let slow = c.start(b"sleep 1".to_vec()).unwrap();
        c.start(b"echo quick".to_vec()).unwrap().join().unwrap();
        slow.join().unwrap();
        assert_eq!(c.message(), b"quick");
    }
}
