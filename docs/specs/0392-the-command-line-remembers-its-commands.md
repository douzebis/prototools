<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0392 — the command line remembers its commands

Status: implemented
Implemented in: 2026-10-04
App: protolens
Refs: docs/specs/0246-the-search-prompt-browses-history-and-rotates-matches.md
      (the search history this mirrors: S12–S16; and N1, which left the
      `:` prompt without history, lifted here; S14, whose browsing gains
      the prefix filter);
      docs/specs/0113-protolens-tui-refinements.md (D26: any key but Tab ends a completion
      cycle);
      docs/specs/0236-an-override-is-edited-as-one-command.md (the
      `:override` line, and `o`'s pre-fill of it)

## Background

The search prompts (`/`, `?`, `F`, `B`) keep a history of committed
patterns, browsed with `Up`/`Down` or `Ctrl-P`/`Ctrl-N` (spec 0246
S12–S16). The `:` command line has none: spec 0246 N1 left it out to
keep that spec small, citing the `:` prompt's Tab completion. Re-running
or adjusting an earlier `:override …` or `:export …` means typing it
again.

How commands reach the command line today:

- Typed after `:`, then Enter. `run_command` has exactly one caller:
  Enter at the `:` prompt (`command_line.rs`).
- Pre-filled by a shortcut, then Enter: `o` (`:override`), `s`/`r` in
  the main view (`:save-overrides`/`:restore-overrides`), and the `x…`
  export chords (`:export`). These also run through Enter at the
  prompt.
- Not at all: Enter in the override selection pane commits an override
  directly (`overrides.activate_with_name`), although an equivalent
  `:override` line exists. The management pane's `a`, `d`, `D`, `z`/`Z`
  and `r`/`R` edit entries with no `:` command equivalent.

The concern behind spec 0246 N1 does not arise: Tab completion's state
is already cleared by any key other than Tab (spec 0113 D26), so
`Up`/`Down` cannot meet a half-finished completion.

## Goals

- **G1.** The `:` command line keeps a history of the commands run from
  it, browsable as the search history is.
- **G2.** An action taken by a shortcut that has an equivalent command
  line is added to that history as that command line, as if it had been
  typed.
- **G3.** The `:` history and the search history stay separate, as in
  vim.
- **G4.** Both histories filter by the typed prefix, as vim does: what
  was typed before browsing selects which entries `Up`/`Down` visit.

## Non-goals

- **N1.** No persistence across runs, for the reason spec 0246 N2 gives
  for the search history: protolens writes no state file.
- **N2.** Shortcuts with no `:` equivalent add nothing: the management
  pane's `a`, `d`, `D`, `z`/`Z`, `r`/`R`. Giving them commands is a
  separate feature.
- **N3.** `q` and `?` add nothing, although `:quit` and `:help` exist:
  recalling either is never useful.

## Specification

- **S1. What is recorded.** Every line run with Enter at the `:` prompt,
  whether typed, pre-filled (by a shortcut such as `o`, or by a
  `--script` beat's `command:`, which only opens the prompt pre-filled),
  or recalled from history. It
  is recorded whether the command succeeds or fails, as vim does, so a
  line with a typo can be recalled and fixed (decided with the user,
  2026-10-04). A line that is empty once trimmed is not recorded.

- **S2. Shortcuts with an equivalent (G2).** Enter in the override
  selection pane, when it commits an override, records the `:override`
  line for the entry it committed: the line the management pane's `o`
  would pre-fill for that entry (origin, `--as` unless raw,
  `--cardinality` when explicit, `--field-name`). Running that line
  reproduces the same entry, and on the same document is a no-op (spec
  0236 S6). If the commit fails, nothing is recorded.

- **S3. Storage.** `App::command_history: Vec<String>`, beside
  `search_history`, with the same rules (spec 0246 S12–S13): at most 50
  entries; a line already present moves to the end instead of being
  stored twice; the oldest entry drops first. Lines are stored, and so
  compared, with their ends trimmed.

- **S4. Browsing.** At the `:` prompt, `Up`/`Ctrl-P` step back and
  `Down`/`Ctrl-N` step forward, as at a search prompt (spec 0246 S14):
  - the first `Up` keeps what was typed as the draft, and `Down` past
    the newest entry restores it;
  - neither end wraps, and reaching one shows no message;
  - the cursor goes to the end of the recalled line;
  - any editing key ends the browse, so the next `Up` starts again from
    the newest entry.

  The search prompts keep their own history. S5's prefix filter is
  their only change.

- **S5. Prefix filtering, at every prompt (G4).** Applies to the `:`
  prompt and to the search prompts, whose browsing (spec 0246 S14) gains
  the same filter.
  - **The prefix.** The first `Up` or `Ctrl-P` of a browse saves the
    line as typed. That is the draft spec 0246 S14 already keeps, and it
    is also the prefix. It stays fixed for the whole browse: recalling
    an entry does not make that entry the prefix.
  - **`Up`/`Down`** move from the current position to the nearest older
    (newer) entry that starts with the prefix, skipping the others.
    With no older match, `Up` does nothing; if that is the first `Up`,
    no browse starts and the line is left as typed. `Down` past the
    newest match restores the draft and ends the browse.
  - **`Ctrl-P`/`Ctrl-N`** make the same move with an empty prefix, so
    every entry counts. Both pairs share one position in the history, so
    they can be mixed within a browse.
  - **Matching** is a plain, case-sensitive "starts with", as in vim.
    For search patterns, smartcase still governs how a pattern matches
    the document, not which history entries are recalled.
  - **Display** is unchanged: the prompt line shows one recalled entry,
    with the cursor at its end. No list or popup is drawn.
  - With an empty draft, the prefix is empty, and `Up`/`Ctrl-P` behave
    the same: a plain `Up` browses everything, as today.

  Because a repeated line moves to the end instead of being stored
  twice (S3), a filtered browse never shows the same line twice.

- **S6. Help.** The help pane documents `Up`/`Down` and
  `Ctrl-P`/`Ctrl-N` at the `:` prompt, and updates the search-prompt
  line, both with S5's prefix filter.

## Alternatives considered

### Record every shortcut as some command

The management pane's edits have no `:` command (N2). Recording them
would mean inventing command lines that cannot be run, which would turn
the history into an action log rather than something to recall and
re-run.

### Prefix filtering at `:` only

Commands share long prefixes (`override …`), and searches less so, so
the filter matters more at `:`. But one browsing rule at every prompt is
easier to learn, and vim applies it to both. Decided with the user
(2026-10-04).

### Record only commands that succeed

Keeps the history clean, but loses the line one most wants back: the one
with the typo. Decided against with the user (2026-10-04).

### One history for `:` and the search prompts

Recalling a search pattern at `:` is never what is wanted, and the
reverse neither. vim keeps them apart for the same reason.

## Test plan

1. `a_run_command_is_recorded` and `an_empty_line_is_not_recorded`.
2. `a_failed_command_is_recorded` (S1).
3. `a_repeated_command_moves_to_the_end` and
   `the_history_keeps_fifty_entries` (S3).
4. `up_recalls_the_newest_command_and_down_restores_the_draft`, and
   `ctrl_p_and_ctrl_n_browse_like_up_and_down` (S4). These replace spec
   0246's `up_at_a_colon_prompt_is_still_inert`, which asserts the
   opposite.
5. `an_edit_ends_the_browse` (S4).
6. `up_filters_by_the_typed_prefix_and_ctrl_p_does_not` (S5), at the
   `:` prompt and at a search prompt;
   `the_prefix_stays_fixed_while_browsing` and
   `ctrl_p_and_up_share_one_position` (S5).
7. `a_prefilled_command_is_recorded_once_run`: `o`, then Enter.
8. `committing_in_the_selection_pane_records_its_override_line`, and
   that running the recalled line on the same document is a no-op (S2).
9. `search_and_command_histories_are_separate` (G3).
10. The help pane test lists the new keys (S6).

## Measured outcome

Implemented 2026-10-04.

- The walk through a history is shared by both kinds of prompt
  (`tui/history.rs`: `history_step`, `HistoryBrowse`). The search
  prompts' own browse was rewritten onto it, and the command line uses
  it for `command_history`.
- An edit is detected by comparing the prompt with the line the walk
  last showed (`HistoryBrowse::shown`), not on each editing path. So
  typing, pasting and Tab completion all end a walk, while moving the
  cursor does not, as at the search prompts.
- S2 is implemented by `override_line_for_entry`, extracted from the
  management pane's `o`, which now uses it too. The tests covering `o`
  pass unchanged.
- Two spec 0246 tests asserted unfiltered `Up` and were adapted, keeping
  their point. `down_past_the_newest_history_entry_restores_what_was_typed`
  now has a history entry that starts with the draft.
  `editing_after_a_history_recall_ends_the_browse` starts its second
  walk with `Ctrl-P`/`Ctrl-N`. `up_at_a_colon_prompt_is_still_inert` is
  removed: test 4 replaces it.
- The test plan's items 1–10 are 16 new tests, all passing. All 1305
  protolens tests pass locally; clippy and `cargo fmt --check` are
  clean. The Nix sandbox test run (`nix-build -A rust-tests`) passes in
  full: all 34 test binaries.
