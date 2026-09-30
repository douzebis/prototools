<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0376 — a comment comes back as written

Status: implemented
Implemented in: 2026-09-30
App: reproto
Refs: docs/specs/0375-a-game-of-life-to-spy-on.md (the life binaries keep
      life.proto's SourceCodeInfo, so reproto's rendering of comments is
      part of the workshop demo)

## Background

A comment in a `.proto` file reaches reproto through the descriptor's
`SourceCodeInfo`, where `protoc` stores, for each line, exactly the text
that followed `//`, and joins the lines with `\n`, ending with one. For

```proto
// SPDX-FileCopyrightText: 2026 Frederic Ruget
//
// SPDX-License-Identifier: MIT
```

it stores `" SPDX-FileCopyrightText: 2026 Frederic Ruget\n\n SPDX-License-Identifier: MIT\n"`.
Indentation before `//` is not part of the text, spaces after `//` are,
and a block comment `/* … */` is stored with its leading whitespace and
`*` column removed (checked with `protoc` 32.1, 2026-09-30).

reproto renders a comment by calling `.strip()` on the whole string,
splitting it on `\n`, and writing `// ` before each line
(`source_info.py`, `re_file.py`, `text.py`). `.strip()` removes the space
of the first line only, so every other line gains one: the decompiled
header above reads

```proto
// SPDX-FileCopyrightText: 2026 Frederic Ruget
// 
//  SPDX-License-Identifier: MIT
```

with a trailing space on the blank line and two spaces after `//` on the
last. It shows in the GreHack 2026 demo, where reproto decompiles the
life binaries' embedded descriptor, comments included (spec 0375).

## Goals

- **G1.** A comment reproto renders from `SourceCodeInfo` comes back as
  it was written: each line is `//` followed by exactly the stored text.
- **G2.** The comments reproto writes itself (the file-name header, the
  anomaly notes) look as they do today.

## Non-goals

- **N1. Which comments reproto renders, and where.** Today: file-level
  comments, and message-level ones, inside the message body. Field,
  enum and service comments are not rendered; this spec does not change
  that.
- **N2. Block comments as blocks.** `protoc` does not record that a
  comment was a `/* … */` one; it comes back as `//` lines, as today.

## Specification

- **S1. The renderer writes `//`, not `// `.** A comment line's text is
  exactly what follows `//` (`text.py`, `Block.flush`).
- **S2. Stored comments are not stripped.** A comment string loses its
  one final `\n`, and is then split on `\n`; each piece is a line as
  stored (`source_info.py`, `re_file.py`). An empty stored line renders
  as a bare `//`.
- **S3. reproto's own comments bring their space.** The call sites that
  write reproto's own comment text prefix it with a space: the file-name
  header (`re_file.py`) and the anomaly notes (`anomalies.py`). There is
  one comment convention, S1's, and no second kind of comment line.

## Alternatives considered

### Strip at most one leading space per line

Right for comments written `// text`, which is nearly all of them, but it
turns `//text` into `// text`: a guess about how people write comments,
where S2 needs none.

### A separate line kind for source comments

Would leave reproto's own comment call sites untouched, at the cost of
two conventions for one thing. Rejected in favor of S3.

## Test plan

1. `test_comments_come_back_as_written`: a fixture holding an indented
   `//`, a `//` with no space, extra spaces after `//`, an empty comment
   line and a block comment, as file-level and message-level comments
   (leading, detached, trailing), compiled with `--include_source_info`
   and decompiled. Every stored comment line appears in the output as
   `//` plus exactly its text; no output line ends in a space.
2. The same fixture's file header survives a second `protoc`: the
   decompiled file, compiled again, holds the same detached comments on
   `syntax` as the original.
3. reproto's own header still reads `// <file name>`, with its space.
4. The full reproto suite passes; golden outputs that change differ only
   in comment continuation lines and blank comment lines.

## Measured outcome

Measured 2026-09-30, reproto from the working tree, protoc 32.1.

1. Passes: `reproto/src/reproto/tests/test_comments.py`, fixture
   `tests/fixtures/comments.proto`. Two of its four tests failed before
   the fix: the blank comment line came out as `// `, and the header did
   not survive a second `protoc`.
2. Passes.
3. Passes.
4. Passes: 284 tests (280 before, and these 4). No golden output changed:
   none held a multi-line comment.

On the life binaries (spec 0375), protoscan then reproto now give back
`life.proto`'s header exactly as written. The split stays inline at the
six call sites, as S3's single convention implies; no helper.
