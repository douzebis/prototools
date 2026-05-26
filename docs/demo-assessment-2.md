---
# SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

Second-pass critical review of demo/01-tutorial.sh
---

Section 1 — Setup

- `rm -rf stash/*` is cleaner but will silently delete anything the user has put
  in stash/ (e.g. from a previous partial run they want to keep).  Low risk for
  a demo machine, but worth noting.
- The nix-build line produces a store path like
  `/nix/store/abc...-googleapis-db/googleapis.desc`.  The three `export` lines
  that follow derive PBS and DESCS from `dirname` of that path.  If nix-build
  fails or produces output on stderr, the variable will be empty and every
  subsequent command silently breaks.  Consider adding a guard:
  `[[ -f "$GOOGLEAPIS_DB" ]] || { echo "nix-build failed"; exit 1; }`.

Section 2 — Protobufs are everywhere

- Still no "why should a security audience care?" bridge.  The two quotes
  establish ubiquity but the leap to "and here is why prototools matters for
  your work" is never made.  Even one sentence — e.g. "When something goes wrong
  on the wire, you need to read what was actually sent, not what the SDK chose
  to show you." — would anchor the rest of the demo.

Section 3 — What's inside a protobuf?

- `--type google.protobuf.Empty` is used to get a raw field-number view without
  inference.  There is no narrative explaining why Empty is the right type to
  pass here.  An audience member will wonder: "why Empty?  Is something
  missing?"  A one-liner — "Empty has no fields, so the decoder shows the raw
  wire structure" — would prevent confusion.
- The vocabulary block (protobuf / schema / descriptor) is still in section 3,
  defined before descriptor is demonstrated.  "descriptor" will be abstract
  until section 4.  Either move the vocabulary block to just before section 4,
  or remove the descriptor line here and reintroduce it naturally in section 4.
- The `ls -lh` beat is fine for establishing "this is a real file", but the
  file size (a few hundred bytes) is never commented on.  Pointing out the
  compactness relative to the JSON equivalent would reinforce the "compact"
  claim from section 2.

Section 4 — Schemas are protobufs too

- The new narrative before the command ("next to every .proto in our DB sits
  a .pb") is good.  However, it doesn't explain *who* compiled those .pb files
  or when.  The audience may wonder: "did reproto produce these, or did protoc?"
  One clause — "compiled by protoc and shipped with the googleapis Nix package"
  — would close the gap.
- The narrative after the command ("self-referential!") comes after the decode
  output is shown — good.  But the section ends there with no transition to
  section 5.  The jump from "schemas are protobufs" to "auto-inference" feels
  abrupt.  A one-liner bridge — "This means prototext can score a binary against
  every known schema type — including schemas themselves." — would connect the
  two ideas.

Section 5 — Schema auto-inference

- `tee /dev/tty | vim` is a good improvement.  However, `tee /dev/tty` will
  interleave with the vim startup output unless vim's terminal handling absorbs
  it cleanly.  Worth testing: on some terminals the score line scrolls past
  before vim opens.  If so, consider `| tee >(cat) | vim` or simply outputting
  to a temp file and opening it.
- The ambiguity narrative ("let's try another example — and see what prototext
  does when two types are equally plausible") is now a good beat.  But the
  follow-up ("With --type the ambiguity is resolved") still uses an inline
  comment rather than a narrative block.  The resolution is as interesting as
  the tie; it deserves a line of commentary.
- The UsableSubnetwork decode with --type (line ~90) is on a single long line
  after the reformatting fix was applied to some commands but not all.  Check
  that it was also wrapped.  (It was reformatted in this pass — verify it
  renders cleanly at 80 cols on a projected screen.)

Section 6 — Non-canonical protobufs

- The new narrative before the sed craft ("We are going to slip a secret value
  before the real organization field") is good.  However, the sed command
  itself (`sed '/^organization.../i organization: "Entrance secret PIN code:
  666*"  #@ string = 11'`) remains opaque.  The `#@ string = 11` annotation is
  prototext-internal syntax that the audience has not seen explained.  Either
  add a brief gloss ("the #@ annotation tells prototext the wire encoding") or
  hide the annotation behind a helper script.
- The OHB section: the new narrative block ("Two round-trips: prototext
  preserves the anomaly byte-exact. protoc silently strips it.") is a good
  framing.  The protoc decode replacement (showing the clean output) works well
  as the reveal.  However the `diff` + `echo byte-exact` beat that precedes it
  is now slightly awkward in context: the audience sees "byte-exact" printed,
  then opens vim to see the "clean" protoc output.  Consider whether "byte-
  exact" needs to come first, or whether it is sufficient to just show the protoc
  output and say "the OHB is gone."
- `Compare with the canonical version: the score drops because of the anomaly`
  (narrative block, lines ~180) is now orphaned — the section restructuring
  removed the commands that demonstrated the score comparison.  Either restore
  the score comparison or remove this narrative block.

Section 7 — Decompiling schemas and building scoring databases

- The section title is improved.  It is now accurate but long — may feel
  unwieldy when demo/header prints it.  Consider shortening to "Decompiling and
  scoring" or "Schema decompilation".
- `prototext decode $GOOGLEAPIS_DESCS/google/type/postal_address.pb | vim` —
  the new context ("postal_address.pb is the compiled schema") makes this make
  sense.  Good.
- The VSCode narrative ("Go to Definition navigates across files") is now
  present.  But it is a narrative block followed immediately by `code
  --reuse-window` with no scripted beat *inside* VSCode.  The audience will
  watch VSCode open, then wait.  Consider adding a commented prompt: "# Open
  google/cloud/audit/audit_log.proto and Ctrl-click on google.rpc.Status" so
  the presenter knows what to do next.
- The scoring-DB section (audit.desc, iprules, opmeta) is now merged into
  section 7.  The section is consequently very long — it covers decompilation,
  VSCode navigation, scoring DBs, Hopcroft, and two graph examples.  This may
  be too much for a single section on stage.  Consider whether the scoring-DB
  content should become its own section 8 (with seeding/pruning as section 9),
  or whether section 7 needs clear internal `demo/header`-style sub-beats.
- The legend is now placed after the first `xdg-open` (raw graph) and before
  the second (Hopcroft).  This is better.  However the presenter must now read
  the legend *while* the raw graph is visible in the browser.  That is the right
  moment, but it requires the presenter to split attention.  A spoken cue in the
  narrative ("take a moment to look at the two amber nodes — those are Allowed
  and Denied") would guide the audience before the legend text appears.
- The OperationMetadata beat still ends with two bare `xdg-open` calls.  The
  closing narrative beat ("prototools gives you…") is now in section 8, not
  here.  There is still no spoken moment between opening opmeta.html and
  opmeta-hopcroft.html.

Section 8 — Seeding and pruning

- Good: seeding/pruning is now its own section, and the Simon's-team narrative
  is reunited with it.
- `find stash/audit-seed -name '*.proto' | sort` replaces `tree` — correct per
  the assessment.  The output will be a flat list of paths.  On a projected
  screen the paths (`stash/audit-seed/google/cloud/audit/...`) are long and the
  folder structure is less visible than with tree.  Consider `find ... | sed
  's|stash/audit-seed/||'` to strip the prefix, making the paths shorter and
  the structure clearer.
- The orphan reveal now opens the full file in vim rather than grep.  Good.
  But the file may be long — the audience needs to navigate to the orphaned
  field.  Consider `vim +/'^  ///'` to jump directly to the first orphan line.
- The closing narrative bullet list is a strong finish.  Four tight bullets
  landing the key capabilities.  One suggestion: the first bullet ("a forensic
  decoder that preserves wire anomalies standard tools hide") could name the
  tool explicitly — "prototext: a forensic decoder…" — to reinforce the brand
  before the audience disperses.
