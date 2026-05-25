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
- **File display**: prefer `cat FILE | vim -` over `cat FILE | head -N` when
  the content is worth reading in full — vim opens read-only in the terminal,
  lets the presenter scroll, and closes cleanly with `q`.  Use `head` only
  when showing just the first few lines is the point.

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

### S1 — Introductory beat

Intro text covering:

- Protobufs are Google's internal data interchange format, now open-source and
  ubiquitous: gRPC, Kubernetes, Android, Cloud APIs, and most large-scale
  distributed systems use them.
- They are compact (binary), self-describing (with a schema), and
  language-neutral — which is why they became the lingua franca of
  microservice communication.
- Open with Quote 1 (the cynical hook), optionally followed by Quote 2 (the
  reinforcement).  The point: protobufs are everywhere, understanding them is
  a basic skill for anyone debugging, auditing, or operating distributed systems.

### S2 — Binary mystery sequence

Use `google.type.PostalAddress` as the running example throughout the demo.

Steps:

1. Show the raw binary of a `PostalAddress.pb` with `hexdump -C`.
2. Decode it *without* a schema (`prototext decode` with no `--descriptor`):
   show field numbers and wire types — meaningful structure emerges, but no
   names.
3. Decode it *with* the googleapis schema DB and no `--type` flag: auto-infer
   fires, field names appear, the message becomes readable.
4. Show the score line — explain briefly what it means.

### S3 — Descriptor explainer

Still using `PostalAddress`:

1. Show what a descriptor *is*: a compiled `.proto` schema, serialised as a
   binary protobuf (`FileDescriptorSet` / `FileDescriptorProto`).
2. Reveal the self-referential twist: the descriptor format is itself defined
   in `descriptor.proto`, so a descriptor file is a protobuf whose schema is
   `google.protobuf.FileDescriptorSet`.
3. Demonstrate: decode `google/type/postal_address.pb` as a
   `FileDescriptorProto` with `prototext decode` — it shows the schema for
   `PostalAddress` in human-readable form.

### S4 — Ambiguous inference

The `UsableSubnetwork` example from the existing tutorial: two types tie, the
user must supply `--type` to resolve.  Keeps the running example theme —
"sometimes the binary alone is not enough."

### S5 — Non-canonical encodings: hidden field (forensics beat)

The `PostalAddress` hidden-field example (Section 6 of tutorial):

1. Show the crafted `postal_hidden.pb`.
2. Show `protoc --decode` → only `"S3NS"` visible.
3. Show `prototext decode` → both `organization` values in wire order, secret
   exposed.
4. Explanation: proto3 last-write-wins silently discards earlier occurrences.
   This is a real steganographic / exfiltration vector.

### S6 — Non-canonical encodings: OHB varint

The over-hanging byte example (Section 5 of tutorial), *after* S5.  By this
point the audience understands wire format well enough to appreciate the
varint trick.

1. Show `postal_patched.pb` — one extra byte on `revision`.
2. `protoc --decode` / standard SDKs: silently normalise, no trace.
3. `prototext decode -a`: `val_ohb: 1` annotation; score drops to -11.
4. Lossless round-trip via `prototext encode` still works.

### S7 — reproto: decompile and navigate

Demonstrates reproto as a schema recovery and navigation tool:

1. Decompile a single `FileDescriptorProto` back to `.proto` source.
2. Decompile an entire schema DB — show the reconstructed tree.
3. Seed on one descriptor to pull only its transitive closure.
4. Prune annotation boilerplate to keep only business logic.
5. Open the result in VSCode — imports are live links, Go to Definition works.

See `docs/demo-examples.md` for the concrete commands and file counts.

---

## Open questions

- Diagrams: the old `prototext.drawio.xml` has pages for "protobuf vanilla",
  "overhang", "interleaved", and "hidden fields" that could be adapted.
  Decide whether to port them to the OSS repo or produce new ones.
