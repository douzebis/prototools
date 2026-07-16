<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Pane: help and session chrome

*last verified: 2026-07-16*

## Executive summary

A handful of session-level surfaces don't belong to any one pane above:
the startup splash, the `F1` help overlay, the always-present status bar,
and the confirmation flows for quitting and suspending. What unifies them
is that each works identically regardless of which "real" pane
(main/override-select/manage) currently has focus — they're checked
centrally, ahead of any focus-specific key dispatch, rather than being
threaded individually into every pane's own key handler.

## Technical detail

### Centrally-checked, focus-independent keys

`Ctrl-Z` (suspend), a pending quit confirmation, and `F1` (open help) are
all checked at the very top of the key-handling entry point, before
dispatch branches on which pane has focus. This ordering is deliberate,
not incidental: these three concerns apply uniformly to the whole
session regardless of what the user happens to be doing inside a pane,
so implementing them as an early-exit check avoids needing the same
three checks duplicated (and kept in sync) inside every pane's own key
handler.

### Quit confirmation is a one-shot flag, not a modal

Pressing `q` the first time doesn't open a dialog — it sets a boolean and
prompts via the ordinary status-message mechanism. The *next* keypress,
of any kind, is intercepted by the same central check: a second `q`
confirms, anything else silently cancels. This makes the confirmation
state trivially resettable (any stray keypress clears it) at the cost of
being slightly more permissive than a true modal would be — pressing `q`
then immediately doing something else is treated as "cancel," not as
"do that other thing, but remember I still want to quit."

### Suspend leaves the terminal exactly as a clean exit would

`Ctrl-Z` doesn't just raise `SIGTSTP` — it first runs the same terminal
teardown a normal exit runs (draining any mouse events still queued so
they don't leak into the shell as escape-sequence garbage on resume,
restoring cooked mode, leaving the alternate screen), and on resume
re-establishes raw mode/alternate screen/mouse capture and forces a full
redraw, since another program may have used the terminal while
protolens was stopped. This mirrors — and deliberately reuses — the same
cleanup path a panic hook uses, so there is exactly one "return the
terminal to a sane state" implementation serving three different exit
paths (normal exit, suspend, panic).

### Help is static text, not generated from key bindings

The `F1` help overlay's content is a hand-maintained block of text, not
derived from the key-dispatch match arms it documents. This is a
conscious trade-off: generating it from the dispatch table would
guarantee the two never drift apart, but would also produce documentation
ordered and phrased however the code happens to be organized internally,
rather than grouped the way a user actually thinks about the tool's
features (movement, folding, search, overrides, management). The
maintenance cost of updating both when a binding changes is accepted in
exchange for help text that reads as a guide rather than a dump of match
arms.

### Status bar reflects the cursor, not the whole document

The always-visible status line shows only information about the node
currently under the cursor (its positional path, byte range, resolved
type, line number) — it never summarizes the document as a whole. This
keeps it cheap to recompute on every single frame (it's one node's worth
of lookups, not a document-wide scan) and keeps its content directly
actionable: everything shown there is either useful for orienting where
the cursor is or is the input to some other cursor-relative action (like
the default `:extract` filename, which embeds the same byte range shown
in the status line).
