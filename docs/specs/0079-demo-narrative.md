<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0079 — Demo narrative and structure

**Status:** draft
**App:** demo

---

## Background

The current `demo/01-tutorial.sh` is a thin replay of `docs/tutorial.md` — a
sequence of commands with no narrative arc.  For a live presentation audience
the script needs to tell a story: why protobufs matter, what is hidden inside a
binary blob, and how prototools lets you see things that standard decoders
hide.

This spec clarifies the division of responsibility between the tutorial and the
demo, establishes presentation guidelines, and defines the narrative arc.

Concrete googleapis command examples are collected separately in
`docs/demo-examples.md`.

---

## The robustness thesis

A recurring theme in the demo is one that rarely gets stated explicitly but is
central to what prototools actually does:

> Writing a decoder or decompiler that works correctly on sanitized, well-formed
> input is moderately difficult.  Writing one that also survives — and does a
> *useful* job — in the presence of incomplete, non-canonical, or deliberately
> malformed input is much harder.

Standard protobuf decoders (protoc, language SDKs) are designed for the happy
path: they assume the input is canonical, produced by a conforming encoder, and
matches the declared schema.  Any deviation is either silently normalized
(over-long varints), silently discarded (repeated optional fields, unknown
fields), or rejected with an opaque error.

prototools is designed for the unhappy path:

- **Incomplete**: no schema available → raw field-number rendering (`--raw`),
  auto-inference from a DB.
- **Non-canonical**: over-long varints, repeated optionals, unexpected field
  ordering → preserved verbatim, annotated, round-trippable.
- **Malformed**: invalid wire tags, truncated varints → rendered as
  `INVALID_TAG_TYPE` / `INVALID_VARINT` rather than silently dropped.
- **Schemaless**: binary descriptor blobs without source → reproto decompiles
  them back to `.proto`.

This framing is worth making explicit in the demo, even briefly.  It answers the
implicit question "why not just use protoc?" — protoc is fine when everything is
well-formed.  prototools is for when it isn't.

---

## Division of responsibility

### `docs/tutorial.md` — reference walkthrough

Prose-heavy.  Every command is explained.  Covers all features systematically.
Meant to be read at a desk, not projected.  The canonical source of truth for
how each feature works.

### `demo/01-tutorial.sh` (and any companion deck) — live presentation

Audience-facing.  Punchy.  Selects a subset of tutorial material and adds
showmanship.  Follows a narrative arc (hook → mystery → reveal → forensics).
The demo script is the executable form of the deck: each block corresponds to
a slide or a beat in the live presentation.

The two are kept in sync: when a tutorial section changes its commands the
demo script is updated to match.  But the demo script is allowed to omit
sections and to reorder material for narrative effect.

---

## Presentation guidelines

### Grouping and pacing

The presenter advances by hitting ENTER.  Each ENTER should correspond to one
meaningful beat — a thought, a reveal, or a command whose output is worth
pausing on.  Rules of thumb:

- **Narrative blocks** (`# \` … `#`): one block per slide beat.  Long
  narratives are split into two blocks so the presenter can pause mid-story.
- **Setup commands** that produce no interesting output (e.g. `export`,
  variable assignments, intermediate build steps) are grouped on one ENTER.
- **Reveal commands** whose output is the point of the beat stand alone.
- **Paired comparisons** (e.g. two `hexdump` lines) are grouped together so
  both lines appear before the audience sees any output.
- **File display**: use `bat --style=numbers,header-filename -l LANG FILE`
  to display a file with syntax highlighting, line numbers, and filename
  header.  For large files where only the first few lines are the point,
  add `-r :N` to limit the output to N lines.  Do not use bare `cat FILE`
  or `cat FILE | head -N`.
- **Interactive browsing**: when the presenter needs to scroll or search,
  open the file in vim (`vim +'set ft=LANG' FILE`).  vim opens read-only
  in the terminal and closes cleanly with `q`.

### Blank lines in the script

A blank line in the script produces an empty ENTER press — the runner advances
but nothing happens on screen.  Use blank lines deliberately:

- **Before a new command or narrative block**: always add one blank line.  The
  runner's color change is sufficient to focus attention, but the blank gives
  the presenter a natural pause beat.
- **Notes about previous output** (`👆`-notes): a short inline comment
  (`# 👆 …`) that highlights something in the output of the immediately
  preceding command.  Three rules apply:
  1. **No blank line before it** — the note must follow the command with no
     separator, so it fires as the very next ENTER after the command output
     lands.  A blank line would insert an empty beat between command and note.
  2. **After the command, not before it** — the `👆` finger points *up* at
     output already on screen.  Placing the note before the command it
     describes is backwards.
  3. **Flush left** — every 👆-note, whether single-line or multi-line, must
     be opened with a `# \` line immediately before the `# 👆 …` line.  No
     exceptions.  The demo runner renders the `# \` opener as a bare
     continuation marker with no shell prompt, which causes the `👆` on the
     next line to also appear flush-left — visually aligned with the terminal
     output above it, unencumbered by a shell prompt.  A multi-line 👆-note
     is closed with a bare `#` terminator, exactly like a narrative block.
- **Section headers** (`demo/header "N. Title"`): always place one blank line
  before and one blank line after.  This gives the presenter two guard beats —
  one to let the previous section land, one to read the title before the first
  command appears.
- **Commands that open a viewer** (vim, xdg-open) and whose results need to be
  visible on the terminal before the viewer opens: pipe through
  `tee >(bat -l LANG)` before `| vim +'set ft=LANG' -`, so the output is
  rendered with syntax highlighting on the terminal before vim takes over.
  For large outputs where only a preview is needed, use `tee >(bat -r :N -l LANG)`
  to show just the first N lines.  Do not use `tee /dev/tty` — process
  substitution with bat is both cleaner and adds colour.
- **End-of-file sentinel**: the script must end with `# THE END` followed by
  several blank lines and a `# 👆 Intentionally adding a few newlines sentinel
  before exiting` comment.  The blank lines give the runner enough ENTER
  presses to clear the screen after the last beat without falling off the end
  of the file abruptly.  Do not remove them.

### VSCode workspace

During the demo a VSCode window is open with a workspace that includes the
`stash/` output directory (or relevant subdirectories).  This enables
**Go to Definition** (`right-click → Find Definition`) on import paths in the
reconstructed `.proto` files — a key demo beat.

Guidelines to keep the workspace manageable:

- **One workspace folder** — `stash/` — covers all reproto output.  All
  `reproto -O` commands write under `stash/` (e.g. `stash/meet-seed`,
  `stash/meet-pruned`) so a single workspace root sees all of them.
- **Do not multiply top-level workspace folders**.  Adding a separate folder
  per reproto run fragments the namespace and breaks cross-folder Go to
  Definition.
- **Stale file prevention**: always `rm -rf` the target subdirectory before
  each `reproto -O` command so the workspace reflects only the current run's
  output.  This is already done for the meet-* beats in the script.

### Multi-line comment syntax

Narrative text uses the `# \` continuation idiom so the runner displays the
whole block as a single prompt entry:

```
# \
#                                                                                \
# --- Section title ---                                                          \
#                                                                                \
# Body text...                                                                   \
#                                                                                \
#
```

Rules:
- First line is always bare `# \`.
- Every continuation line starts with `#` and ends with ` \` padded to column 82
  (80 chars of content + space + backslash).
- The second-to-last line (last content line) also ends with ` \` at column 82.
- Last line is bare `#` (no backslash) to close the block.  It is part of the
  block (displayed as a blank trailing line), not a separator.
- Empty lines within the block use `#` padded with spaces to column 82 then ` \`.
- A blank line in the script file after the closing `#` acts as a visual
  separator between blocks in the source; it produces no extra prompt entry.

### reproto command layout

Long `reproto` commands follow a canonical option ordering so they read
consistently and are easy to scan on a projected screen.  The canonical order
is:

```
reproto [-q] \
    [-O OUTPUT_DIR] \
    [--build-schema-db OUTPUT_DESC] \
    [--emit-scoring-html OUTPUT_HTML] \
    --use-variant descriptor \
    -I INCLUDE_DIR \
    [--seed 'desc:...' ...] \
    [--prune '...'] \
    INPUT_FILE_OR_DOT
```

Rules:
- `-q` (quiet) comes first if present.
- Output destinations (`-O`, `--build-schema-db`, `--emit-scoring-html`) come
  before mode options.
- `--use-variant descriptor` and `-I` come next (they configure the input
  interpretation).
- `--seed` and `--prune` qualifiers come last, just before the positional input.
- Each option is on its own line, indented 4 spaces.
- The positional input is always the last item, on its own line.
- When `-O` and `--build-schema-db` are both present, `-O` is omitted (the two
  modes are mutually exclusive in practice for demo purposes; use separate
  reproto invocations).

### Maintenance tooling

When adding or editing content lines in a block, use the following Python
snippet to pad a line to column 82 and append ` \`:

```python
content = "# Some text here"
padded = content.ljust(81) + "\\"   # 81 chars + backslash = 82 cols total
```

To restore the ` \` suffix on every last-content line (the line immediately
before a bare `#` terminator) after bulk editing, run:

```python
with open('demo/01-tutorial.sh', 'r') as f:
    lines = f.readlines()

fixed = []
for i, line in enumerate(lines):
    if i + 1 < len(lines) and lines[i + 1] == '#\n':
        stripped = line.rstrip('\n')
        if stripped.startswith('#') and not stripped.endswith('\\'):
            padded = stripped.rstrip().ljust(81) + '\\'
            fixed.append(padded + '\n')
            continue
    fixed.append(line)

with open('demo/01-tutorial.sh', 'w') as f:
    f.writelines(fixed)
```

---

## Goals

1. Add introductory material to the demo that explains why protobufs matter.
2. Build a short "binary mystery" sequence: start from raw bytes, make them
   meaningful step by step.
3. Introduce descriptors through the running example, including the
   self-referential twist (descriptors are themselves protobufs).
4. Reorder the non-canonical / forensics section: hidden fields first (simpler),
   OHB varint second (requires understanding varint encoding).
5. Keep a single running example throughout — `google.type.PostalAddress` — so
   the audience builds familiarity with one message rather than switching
   between examples.

---

## Non-goals

- Changing the tutorial prose or section order (the demo may reorder; the
  tutorial stays systematic).
- Adding new prototools features.
- Producing a polished slide deck (that is a separate deliverable; the spec
  covers narrative structure only).

---

## Quotes

Three quotes to use in the intro, in recommended presentation order:

**Quote 1 — the hook** (Hacker News, 2018, anonymous ex-Googler, item 18189458):
> "I spent 2.5 years at Google, and most of what I did was pushing one protobuf
> from one place to another."

**Quote 2 — supporting colour** (HN, 2019, anonymous, item 20132880):
> "The harsh truth of working at Google is that in the end you are moving
> protobufs from one place to another."

**Quote 3 — the authoritative pivot** (protobuf.dev/overview, Google):
> "Protocol buffers are the most commonly-used data format at Google.  They are
> used extensively in inter-server communications as well as for archival
> storage of data on disk."

Recommended flow: open with Quote 1 (the cynical hook — gets a laugh), follow
with Quote 3 (the "why it matters" pivot — reframes the story).  Quote 2 is
available as a reinforcement if needed.

---

## Specification

The demo is structured in eight sections.

### S1 — Setup

Tool version check, nix-build of the googleapis schema DB, and stash cleanup.
No audience-facing narrative — fast administrative beat.

### S2 — Protobufs are everywhere

Two narrative blocks (two ENTER presses — intentional, two distinct quotes):

- Quote 1 (HN hook), Quote 3 (authoritative pivot).
- Bridge: protobufs are compact, self-describing, language-neutral — the lingua
  franca of microservice communication.

### S3 — What's inside a protobuf?

Use `google.type.PostalAddress` as the running example throughout the demo.

1. Vocabulary block: protobuf / schema / descriptor.
2. `ls -lh` — establish the file is real and compact.
3. `hexdump -C` — raw bytes, what travels on the wire.
4. `prototext decode --raw` — field numbers and wire types without names,
   no descriptor set required.  Annotations are always on in raw mode.
5. `prototext decode --type google.type.PostalAddress` — with the right schema,
   the message becomes readable.
6. `vim postal_address.proto` — show the schema that unlocked it.

### S4 — Schemas are protobufs too

1. Narrative: next to every `.proto` sits a `.pb` — the same schema compiled
   by protoc into a `FileDescriptorProto`.
2. `prototext decode --type google.protobuf.FileDescriptorProto postal_address.pb`
   — the schema itself decoded as a protobuf.
3. Narrative (after the reveal): the schema for `FileDescriptorProto` is defined
   in `descriptor.proto` — self-referential.

### S5 — Schema auto-inference

1. `prototext decode PostalAddress.pb` (no `--type`) with `tee /dev/tty | vim`
   — auto-infer fires, score line visible before vim opens.
2. Narrative: score consolidates field coverage, wire type matches, value
   plausibility.
3. "Let's try another example and see what prototext does when two types are
   equally plausible."
4. `prototext decode UsableSubnetwork.pb` — tie, prototext asks for `--type`.
5. `prototext decode --type ... UsableSubnetwork.pb` — ambiguity resolved.

### S6 — Non-canonical protobufs

#### Hidden field

1. Narrative: wire format allows repeated optional fields; proto3 last-write-wins
   silently discards earlier occurrences — a steganographic vector.
2. Narrative: "we are going to slip a secret value before the real organization
   field."
3. Craft `postal_hidden.pb` via `prototext decode -a | sed | prototext encode`.
4. `hexdump -C postal_hidden.pb` — extra field is in there.
5. `protoc --decode` — only the last `organization` visible; secret gone.
6. `prototext decode` — both occurrences in wire order; secret exposed.

#### Over-long varint

1. Narrative: an extra byte on a varint does not change its value but makes the
   encoding non-minimal; standard decoders strip it silently.
2. Craft `postal_patched.pb` via `prototext decode -a | sed | prototext encode`.
3. `hexdump` comparison — one extra byte.
4. `prototext decode -a` — `val_ohb: 1` annotation visible.
5. Narrative: "two round-trips — prototext preserves the anomaly byte-exact;
   protoc silently strips it."
6. `prototext` round-trip + `diff` → `byte-exact`.
7. `protoc decode` → the OHB is gone, the revision field looks clean.

### S7 — Decompiling descriptors

1. Narrative: `postal_address.pb` is the compiled schema — a
   `FileDescriptorProto`.  `reproto` turns it back into readable `.proto`.
2. `prototext decode postal_address.pb | vim` — show what the binary looks like.
3. `reproto -q -O stash/reproto-out --use-variant descriptor postal_address.pb`
   — decompile.
4. `vim stash/reproto-out/google/type/postal_address.proto` — human-readable
   source recovered from the binary.
5. `reproto -O stash/googleapis-out --use-variant descriptor -I $GOOGLEAPIS_DESCS .`
   — decompile the entire googleapis DB (no `-q`; progress is reassuring for a
   long-running step).
6. Narrative: the proto language server understands the import graph — Go to
   Definition navigates across files, find-all-references works, full type
   hierarchy is explorable.
7. `code --reuse-window stash/googleapis-out` — open in VSCode.
8. Narrative: missing imports handled gracefully via orphan `///` comments;
   `--prune` makes this explicit and controlled.

### S8 — Seeding and pruning

1. Narrative: Simon's audit team only needs AuditLog — thousands of files
   collapse to the transitive closure.
2. `reproto -q -O stash/audit-seed ... google/cloud/audit/audit_log.pb`.
3. `find stash/audit-seed -name '*.proto' | sort` — the 8-file closure.
4. Narrative: Simon's tool never needs RPC error statuses — prune
   `google/rpc/status.proto`.
5. `reproto -q -O stash/audit-pruned ... --prune 'file:google/rpc/status.proto'`.
6. `find stash/audit-pruned -name '*.proto' | sort` — 7 files.
7. Narrative: the orphaned field is preserved as a `///` comment — nothing
   silently lost.
8. `vim stash/audit-pruned/google/cloud/audit/audit_log.proto` — show the
   orphan comment.
9. Closing narrative: four-bullet summary of what prototools gives you.

See `docs/demo-examples.md` for the concrete commands and file counts.

---

## Open questions

- Diagrams: the old `prototext.drawio.xml` has pages for "protobuf vanilla",
  "overhang", "interleaved", and "hidden fields" that could be adapted.
  Decide whether to port them to the OSS repo or produce new ones.
