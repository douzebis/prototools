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

### S7 — Decompiling schemas and building scoring databases

#### Decompilation

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

#### Scoring DB

1. Narrative: the `.proto` sources are useful for reading, but prototext's
   auto-inference needs a scoring DB — a compiled schema with a Hopcroft graph
   baked in.
2. `reproto ... --build-schema-db stash/audit.desc --emit-scoring-html stash/audit.html`
   for AuditLog.
3. Hopcroft narrative: IpRules example — Allowed and Denied have opposite
   semantics but identical wire structure; Hopcroft finds this automatically.
4. `reproto ... --emit-scoring-html stash/iprules.html ip_rules.pb`.
5. `xdg-open stash/iprules.html` — raw graph (5 nodes), inspect Allowed/Denied.
6. Graph legend narrative (audience reads while looking at the raw graph).
7. `xdg-open stash/iprules-hopcroft.html` — Hopcroft graph (4 nodes),
   Allowed/Denied merged.
8. At-scale narrative: 8 OperationMetadata types across 8 services, same wire
   shape.
9. `reproto ... --emit-scoring-html stash/opmeta.html $GOOGLEAPIS_DB`.
10. `xdg-open stash/opmeta.html` / `xdg-open stash/opmeta-hopcroft.html`.

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
