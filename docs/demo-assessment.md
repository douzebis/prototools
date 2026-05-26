---
# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

Section 1 — Setup

- nix-build runs live during the demo and could take a long time or fail visibly. Audiences don't care about Nix. Consider pre-building and
hardcoding the store path (as line 39 once did), or at least wrapping it in a comment explaining what's happening.
  → Will be short since cached in the nix store; acceptable as-is.
- The rm -rf block is brutally long — 5 lines of paths the audience doesn't care about. It belongs in setup but should be invisible, or at least
 condensed. → Replace with `rm -r stash/*`.
- export GOOGLEAPIS_PBS — the variable name leaks implementation detail. Fine internally, but the comment "Companion paths" is cryptic.
  → Drop the comments; three bare variable initializations are self-evident.

Section 2 — Protobufs are everywhere

- Two narrative blocks back to back with no command between them — that's two ENTER presses to read text, which can feel slow. Consider merging
them into one block (fits within 82 cols). → Acceptable: they are two distinct quotes, two ENTER presses are fine.
- The pivot from "cynical quote" to "lingua franca" is abrupt. Missing a beat: why does this matter to security/audit people specifically? The
audience is left to infer.

Section 3 — What's inside a protobuf?

- Two vim opens in a row (lines 61–62): hexdump | vim - then vim PostalAddress.pb. The second one opens the raw binary in vim — garbled bytes.
Drop it.
- `--type google.protobuf.Empty` decode is clever but requires explanation in the narrative — currently there's no narrative block before it, just
 an inline comment. The audience won't understand why we're decoding as Empty.
  → This is a trick: without a type hint, decode tries to infer. Consider adding a `--raw` option to decode that implicitly uses
  google.protobuf.Empty (check whether that type is available as a built-in).
- The vocabulary block is good but descriptor is defined before it's demonstrated, which means it lands as abstract terminology. Could move it
to section 4.

Section 4 — Schemas are protobufs too

- The command on line 86 is a single very long line (no line breaks). Hard to read on a projected screen. → Reformat this command and any
  others with the same defect. Also: establish a guideline for structuring such commands — option ordering, line-splitting, and display
  method (pipe to terminal? vim? vscode?).
- The postal_address.pb file decoded as FileDescriptorProto — the audience needs to understand why there's a .pb file next to the .proto. One
sentence of narrative is missing here. → Add it.
- No narrative after the command — the "self-referential" point is made before the reveal, not after. Flip it: show the decode output first,
then explain what just happened. → Fix the order.

Section 5 — Schema auto-inference

- Line 98: pbtxr typo — should be pbtxt. → Fix. Also: because the audience's attention is drawn to the score, output to terminal as well as
  vim: replace `| vim` with `| tee /dev/tty | vim`.
- Two narrative blocks separated only by the decode command — the tie/ambiguity beat (lines 106–109) would land better after showing the
successful inference. → Replace the second narrative block with something like "let's try another example" and let the audience discover that
prototext did not decode but instead asked for clarification.
- The UsableSubnetwork example is a context switch — it's a completely different message from PostalAddress. → Acceptable: it is deliberately
  another example from googleapis.

Section 6 — Non-canonical protobufs

- hexdump -C stash/postal_hidden.pb + vim stash/postal_hidden.pb — two openings of the same file (lines 145–146). The vim of a binary file
adds nothing after the hexdump. Drop it.
- The sed command that crafts the hidden field (line 141) is hard to parse on screen — the audience sees implementation plumbing, not the
concept. → Add a narrative block before it that explicitly says "we're going to slip a secret value before the real one."
- The OHB round-trip comparison (lines 183–200) is the strongest forensic beat in the script but it's buried. The byte-exact / not-byte-exact
echo is satisfying. → Add a narrative block that names what's being demonstrated before the commands run. Also show the protoc decode output
to demonstrate that the OHB is transparent to a standard decoder.
- The protoc round-trip (lines 191–200) is complex and noisy — the piped protoc→protoc will lose the audience. → Replace with just showing
  the protoc decode output, where it is obvious that the OHB has been silently dropped.

Section 7 — There is more

- Section title is no longer appropriate. → Replace with something more specific.
- prototext decode $GOOGLEAPIS_DESCS/google/type/postal_address.pb (line 212) — no narrative block before it. The audience doesn't know what
they're about to see. What is postal_address.pb (as opposed to postal_address.proto)? This is the bridge to "schemas are protobufs too."
  → Add context.
- reproto -O stash/googleapis-out (line 225) has no -q flag — will show all progress output. → Keep it: for a long-duration call this is
  intentional; the stages are self-describing and reassuring to the audience.
- code --reuse-window stash/googleapis-out — no narrative about what to do in VSCode. The "Go to Definition" beat from spec 0079 S7 is
completely missing. → Add one or more lines explaining that we are going to navigate the decompiled .proto files using the VSCode proto
language server.
- The tree stash/audit-seed beat (line 243) shows one line per folder nesting level — wasteful on screen. → Replace with a find command.
- grep '///' stash/audit-pruned/... (line 261) — the grep output itself is the reveal. → Replace with opening the file in vim or vscode.
  Add a one-liner about the benefit of orphaned lines (nothing silently lost).

Section 8 — Building a scoring DB

- The bridge from section 7 to 8 is weak — the connection to Simon's audit team narrative is dropped. → Restructure: (1) introduce proto
  decompilation (current start of section 7); (2) pivot to "now that reproto understands descriptors, let's use it to build a database for
  prototext type inference" — merge current section 8 into section 7; (3) create a new section 8 on seeding and pruning for Simon's team.
- The graph legend block (lines 301–311) interrupts the flow between building and opening the graph. → Move it after xdg-open so the
audience can look at the graph while reading the legend.
- xdg-open stash/iprules.html / xdg-open stash/iprules-hopcroft.html — no narrative between them. → Add a beat for the audience to look at
the raw graph and spot Allowed/Denied before the Hopcroft reveal.
- The OperationMetadata beat ends abruptly with two xdg-open calls and no closing thought. → Add a closing beat.
- "THE END" is informal — fine for a script comment. → Add a closing narrative block that lands the key message: what prototools gives you.
