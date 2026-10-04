// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The `s`-key shell runner (spec 0380): a one-line prompt, a background
//! child, and a log file for its output. Kept apart from `main.rs` so the
//! mode state machine (S1, S2, S5) and the spawn/collect worker (S3) are
//! unit-testable without a terminal.

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

/// What the TUI is doing with the keyboard (S1): playing the game, or
/// collecting a command line.
pub enum Mode {
    Game,
    Prompt { line: String },
}

/// What a keypress in `Prompt` mode asks the caller to do (S2), split out
/// so the state machine is testable without crossterm.
pub enum PromptAction {
    /// Keep collecting; the line was edited (or the key was ignored).
    Edit,
    /// Escape: drop the line, return to `Game`.
    Cancel,
    /// Enter on a non-empty line: run it, return to `Game`.
    Submit(String),
    /// Enter on an empty line: return to `Game`, run nothing.
    SubmitEmpty,
}

/// Apply one editing key to the prompt line (S2). `Char` appends,
/// `Backspace` pops, `Enter` submits (empty or not), `Esc` cancels; any
/// other key is ignored. Returns the action for the caller to carry out.
pub fn on_prompt_key(line: &mut String, key: PromptKey) -> PromptAction {
    match key {
        PromptKey::Char(c) => {
            line.push(c);
            PromptAction::Edit
        }
        PromptKey::Backspace => {
            line.pop();
            PromptAction::Edit
        }
        PromptKey::Enter if line.is_empty() => PromptAction::SubmitEmpty,
        PromptKey::Enter => PromptAction::Submit(std::mem::take(line)),
        PromptKey::Escape => PromptAction::Cancel,
        PromptKey::Ignore => PromptAction::Edit,
    }
}

/// The subset of key events the prompt reacts to (S2) — a crossterm-free
/// shape so `on_prompt_key` tests without a terminal.
pub enum PromptKey {
    Char(char),
    Backspace,
    Enter,
    Escape,
    Ignore,
}

/// A finished command, as the worker thread sends it back (S3).
pub struct CommandResult {
    pub line: String,
    /// The child's exit status, rendered (`exit 0`, or the signal) — kept as
    /// a string so the result crosses the channel without a platform type.
    pub status: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run `sh -c <line>` to completion, capturing stdout and stderr (S3). The
/// pipes are drained by `wait_with_output`, which reads both concurrently
/// with the child, so a child writing past a pipe buffer does not deadlock.
pub fn run_command(line: String) -> CommandResult {
    let child = Command::new("sh")
        .arg("-c")
        .arg(&line)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    match child.and_then(|c| c.wait_with_output()) {
        Ok(out) => CommandResult {
            line,
            status: render_status(out.status),
            stdout: out.stdout,
            stderr: out.stderr,
        },
        Err(e) => CommandResult {
            line,
            status: format!("could not run: {e}"),
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
    }
}

/// `exit N`, or the terminating signal when there was no exit code.
fn render_status(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit {code}"),
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt as _;
                if let Some(sig) = status.signal() {
                    return format!("killed by signal {sig}");
                }
            }
            format!("{status}")
        }
    }
}

/// Spawn the command on its own thread (S3), returning the channel the UI
/// loop polls (S4). The thread owns the `Sender` and ends when it has sent
/// the one result; the UI holds the `Receiver`.
pub fn spawn_command(line: String) -> Receiver<CommandResult> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(run_command(line));
    });
    rx
}

/// The pending command: the channel a running child will report on (S4,
/// S5). `None` means no command is running, so `s` may open the prompt.
pub struct Pending(Option<Receiver<CommandResult>>);

impl Pending {
    pub fn idle() -> Self {
        Pending(None)
    }

    pub fn is_running(&self) -> bool {
        self.0.is_some()
    }

    /// Start a child for `line` and hold its channel (S3, S5).
    pub fn start(&mut self, line: String) {
        self.0 = Some(spawn_command(line));
    }

    /// Non-blocking poll (S4): `Some(result)` when the child has finished
    /// (the slot is cleared); `None` while it still runs or when idle. A
    /// disconnected channel with nothing pending also clears the slot.
    pub fn poll(&mut self) -> Option<CommandResult> {
        match self.0.as_ref()?.try_recv() {
            Ok(result) => {
                self.0 = None;
                Some(result)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.0 = None;
                None
            }
        }
    }
}

/// The log block for one result (S6): the command line, the status, then
/// stdout and (if non-empty) stderr, each labeled, with a trailing blank
/// line so blocks are distinguishable. Non-UTF-8 output is summarized by
/// byte count and rendered lossily, so a binary spew cannot corrupt the log.
pub fn format_result(result: &CommandResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "$ {}", result.line);
    let _ = writeln!(out, "{}", result.status);
    append_stream(&mut out, "stdout", &result.stdout);
    if !result.stderr.is_empty() {
        append_stream(&mut out, "stderr", &result.stderr);
    }
    out.push('\n');
    out
}

fn append_stream(out: &mut String, label: &str, bytes: &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            let _ = writeln!(out, "--- {label} ---");
            out.push_str(text);
            if !text.is_empty() && !text.ends_with('\n') {
                out.push('\n');
            }
        }
        Err(_) => {
            let _ = writeln!(out, "--- {label} ({} bytes, not UTF-8) ---", bytes.len());
            out.push_str(&String::from_utf8_lossy(bytes));
            out.push('\n');
        }
    }
}

/// Append a result's block to the log file and flush, so a `tail -f` sees
/// it as the command finishes (S6).
pub fn log_result(file: &mut std::fs::File, result: &CommandResult) {
    let block = format_result(result);
    let _ = file.write_all(block.as_bytes());
    let _ = file.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_captures_stdout_stderr_and_code() {
        let r = run_command("printf 'out'; printf 'err' 1>&2; exit 3".to_string());
        assert_eq!(r.stdout, b"out");
        assert_eq!(r.stderr, b"err");
        assert_eq!(r.status, "exit 3");
    }

    #[test]
    fn worker_does_not_deadlock_on_large_output() {
        // More than a 64 KiB pipe buffer: wait_with_output must drain both
        // pipes concurrently or this would hang (S3).
        let r = run_command("yes x | head -c 200000".to_string());
        assert_eq!(r.stdout.len(), 200_000);
        assert_eq!(r.status, "exit 0");
    }

    #[test]
    fn pending_polls_to_completion() {
        let mut pending = Pending::idle();
        assert!(!pending.is_running());
        pending.start("printf hi".to_string());
        assert!(pending.is_running());
        // Block until the child reports, without a sleep loop in the test.
        let result = loop {
            if let Some(r) = pending.poll() {
                break r;
            }
        };
        assert_eq!(result.stdout, b"hi");
        assert!(!pending.is_running());
    }

    #[test]
    fn format_result_blocks_are_labeled() {
        let block = format_result(&CommandResult {
            line: "id".to_string(),
            status: "exit 0".to_string(),
            stdout: b"uid=0(root)\n".to_vec(),
            stderr: Vec::new(),
        });
        assert!(block.starts_with("$ id\nexit 0\n"));
        assert!(block.contains("--- stdout ---\nuid=0(root)\n"));
        assert!(!block.contains("stderr"));
        assert!(block.ends_with("\n\n"));
    }

    #[test]
    fn format_result_includes_stderr_when_present() {
        let block = format_result(&CommandResult {
            line: "x".to_string(),
            status: "exit 1".to_string(),
            stdout: Vec::new(),
            stderr: b"boom".to_vec(),
        });
        assert!(block.contains("--- stderr ---\nboom\n"));
    }

    #[test]
    fn prompt_key_machine() {
        let mut line = String::new();
        assert!(matches!(
            on_prompt_key(&mut line, PromptKey::Char('l')),
            PromptAction::Edit
        ));
        assert!(matches!(
            on_prompt_key(&mut line, PromptKey::Char('s')),
            PromptAction::Edit
        ));
        assert_eq!(line, "ls");
        assert!(matches!(
            on_prompt_key(&mut line, PromptKey::Backspace),
            PromptAction::Edit
        ));
        assert_eq!(line, "l");
        // Enter on a non-empty line submits the line and empties it.
        match on_prompt_key(&mut line, PromptKey::Enter) {
            PromptAction::Submit(cmd) => assert_eq!(cmd, "l"),
            _ => panic!("expected Submit"),
        }
        assert_eq!(line, "");
        // Enter on an empty line submits nothing.
        assert!(matches!(
            on_prompt_key(&mut line, PromptKey::Enter),
            PromptAction::SubmitEmpty
        ));
        // Escape cancels.
        line.push('x');
        assert!(matches!(
            on_prompt_key(&mut line, PromptKey::Escape),
            PromptAction::Cancel
        ));
    }

    #[test]
    fn format_result_handles_non_utf8() {
        let block = format_result(&CommandResult {
            line: "x".to_string(),
            status: "exit 0".to_string(),
            stdout: vec![0xff, 0xfe, 0x00],
            stderr: Vec::new(),
        });
        assert!(block.contains("3 bytes, not UTF-8"));
    }
}
