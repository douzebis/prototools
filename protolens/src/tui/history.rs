// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Prompt histories (spec 0246 S11–S16, spec 0392): the walk through a
//! history that `Up`/`Down` and `Ctrl-P`/`Ctrl-N` share between the search
//! prompts and the `:` command line, and the command line's own history.
//!
//! The two histories are separate (spec 0392 G3); only the walk is shared.

use super::*;

/// How many entries a history keeps (spec 0246 S13, spec 0392 S3). vim's
/// default `'history'`; the entries are short strings and no measurement
/// stands behind the number.
pub(super) const HISTORY_MAX: usize = 50;

/// An open prompt's walk through a history (spec 0246 S14, spec 0392
/// S4–S5).
#[derive(Debug, Clone)]
pub(super) struct HistoryBrowse {
    /// Which entry the prompt is showing.
    pub(super) index: usize,
    /// What the user had typed before the first `Up`: restored by `Down`
    /// past the newest entry, and the prefix `Up`/`Down` filter on. It
    /// stays fixed for the whole walk (spec 0392 S5).
    pub(super) draft: String,
    /// The text the walk last put in the prompt. If the prompt no longer
    /// holds it, the user has edited since, which ends the walk (spec 0246
    /// S16, spec 0392 S4) — detected here rather than on every editing
    /// path, so typing, pasting and Tab completion all count alike.
    pub(super) shown: String,
}

/// One step of a walk: what the prompt should do.
#[derive(Debug, PartialEq)]
pub(super) enum HistoryStep {
    /// Nothing to move to: the prompt and the walk stay as they are.
    Stay,
    /// Show `history[index]`.
    Show(usize),
    /// Back past the newest entry: put the draft back and end the walk.
    Restore,
}

/// The next step of a walk through `history`, from `from` (the entry being
/// shown, or `None` before the first step).
///
/// `back` is `Up`/`Ctrl-P`. With `filtered` (`Up`/`Down`), only entries
/// starting with `prefix` count; without it (`Ctrl-P`/`Ctrl-N`), every
/// entry does (spec 0392 S5). Neither end wraps.
pub(super) fn history_step(
    history: &[String],
    from: Option<usize>,
    back: bool,
    prefix: &str,
    filtered: bool,
) -> HistoryStep {
    let counts = |i: &usize| !filtered || history[*i].starts_with(prefix);
    if back {
        let below = from.unwrap_or(history.len());
        match (0..below).rev().find(counts) {
            Some(i) => HistoryStep::Show(i),
            None => HistoryStep::Stay,
        }
    } else {
        match from {
            None => HistoryStep::Stay,
            Some(f) => match (f + 1..history.len()).find(counts) {
                Some(i) => HistoryStep::Show(i),
                None => HistoryStep::Restore,
            },
        }
    }
}

/// `browse`, unless the prompt was edited since it last showed something
/// (spec 0392 S4): then the walk is over, and the next one starts from
/// what the prompt now holds.
pub(super) fn live_browse(browse: Option<HistoryBrowse>, current: &str) -> Option<HistoryBrowse> {
    browse.filter(|b| b.shown == current)
}

impl App {
    /// Spec 0392 S1/S3: remember a command line that was run. Stored
    /// trimmed; a line empty once trimmed is not stored; a repeat moves to
    /// the end rather than being stored twice.
    pub(super) fn push_command_history(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        if let Some(i) = self.command_history.iter().position(|l| l == line) {
            self.command_history.remove(i);
        }
        self.command_history.push(line.to_string());
        if self.command_history.len() > HISTORY_MAX {
            self.command_history.remove(0);
        }
    }

    /// Spec 0392 S4/S5: `Up`/`Ctrl-P` (`back`) and `Down`/`Ctrl-N` at the
    /// `:` prompt. `filtered` is `Up`/`Down`: only entries starting with
    /// the walk's draft count.
    pub(super) fn browse_command_history(&mut self, back: bool, filtered: bool) {
        let current = self.command_buffer.clone().unwrap_or_default();
        let browse = live_browse(self.command_browse.take(), &current);
        let (from, draft) = match &browse {
            Some(b) => (Some(b.index), b.draft.clone()),
            None => (None, current),
        };
        match history_step(&self.command_history, from, back, &draft, filtered) {
            HistoryStep::Stay => self.command_browse = browse,
            HistoryStep::Show(index) => {
                let shown = self.command_history[index].clone();
                self.command_cursor = shown.chars().count();
                self.command_buffer = Some(shown.clone());
                self.command_browse = Some(HistoryBrowse {
                    index,
                    draft,
                    shown,
                });
            }
            HistoryStep::Restore => {
                self.command_cursor = draft.chars().count();
                self.command_buffer = Some(draft);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn back_without_a_filter_visits_every_entry_and_stops_at_the_oldest() {
        let history = h(&["a", "b", "c"]);
        assert_eq!(
            history_step(&history, None, true, "x", false),
            HistoryStep::Show(2)
        );
        assert_eq!(
            history_step(&history, Some(2), true, "x", false),
            HistoryStep::Show(1)
        );
        assert_eq!(
            history_step(&history, Some(0), true, "x", false),
            HistoryStep::Stay
        );
    }

    #[test]
    fn a_filter_skips_entries_without_the_prefix() {
        let history = h(&["override /1", "export x", "override /2", "help"]);
        assert_eq!(
            history_step(&history, None, true, "ov", true),
            HistoryStep::Show(2)
        );
        assert_eq!(
            history_step(&history, Some(2), true, "ov", true),
            HistoryStep::Show(0)
        );
        assert_eq!(
            history_step(&history, Some(0), true, "ov", true),
            HistoryStep::Stay
        );
        assert_eq!(
            history_step(&history, Some(0), false, "ov", true),
            HistoryStep::Show(2)
        );
        assert_eq!(
            history_step(&history, Some(2), false, "ov", true),
            HistoryStep::Restore
        );
    }

    #[test]
    fn a_prefix_nothing_starts_with_moves_nowhere() {
        let history = h(&["a", "b"]);
        assert_eq!(
            history_step(&history, None, true, "zz", true),
            HistoryStep::Stay
        );
    }

    #[test]
    fn forward_before_any_back_moves_nowhere() {
        let history = h(&["a"]);
        assert_eq!(
            history_step(&history, None, false, "", true),
            HistoryStep::Stay
        );
    }

    #[test]
    fn an_edited_prompt_ends_the_walk() {
        let browse = HistoryBrowse {
            index: 0,
            draft: String::new(),
            shown: "abc".to_string(),
        };
        assert!(live_browse(Some(browse.clone()), "abc").is_some());
        assert!(live_browse(Some(browse), "abd").is_none());
    }
}
