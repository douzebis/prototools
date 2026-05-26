<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

Third-pass critical review of demo/01-tutorial.sh
---

This pass reviews the script as it stands after the S7/S8 reorder, the 👆-note
fixes, and the [[comment]] resolutions.  It focuses on what is still rough, not
on what has already been fixed.

---

Section 1 — Setup

- The three `export` lines derive GOOGLEAPIS_PBS and GOOGLEAPIS_DESCS from
  `dirname` of the store path.  These names carry no meaning for a live
  audience.  They appear in commands throughout the demo but are never
  explained.  The presenter is left having to mentally skip over long
  `$GOOGLEAPIS_DESCS/...` prefixes.  Consider either aliasing them to shorter
  names (DESCS, PBS) or not mentioning them in the narrative at all and letting
  the commands speak for themselves with short comments.

- `rm -rf stash/*` is a silent, irreversible line with no narrative.  On stage
  this will flash by without explanation.  A one-liner inline comment — "# Start
  clean" — is the minimum; it also reassures a live audience that this is
  intentional.  (A bare `rm -rf` on stage reads as dangerous.)


Section 2 — Protobufs are everywhere

- The two quotes establish ubiquity.  The closing narrative ("compact,
  self-describing, language-neutral — the lingua franca of microservice
  communication") is a good summary.  But there is still no sentence connecting
  ubiquity to *why the audience should care*.  The demo jumps straight to "what
  is inside a protobuf?" without ever saying "so when something goes wrong, you
  need to be able to read what was actually on the wire."  One bridge sentence
  here would anchor everything that follows.

- The HN quote ("pushing one protobuf from one place to another") is cynical and
  funny — but the Google quote that follows is earnest and official.  The tonal
  whiplash can work as a deliberate contrast, but the presenter needs to play it
  consciously.  There is no cue in the script to do that.  A word in the
  narrative block — e.g. "and the vendor agrees:" — would smooth the transition.


Section 3 — What's inside a protobuf?

- `ls -lh` gives a file size, but the demo never uses that size to make a point.
  Previous assessments noted the compactness angle; it remains unaddressed.  The
  file is a few hundred bytes for a rich structured message.  One inline comment
  — "# a few hundred bytes for a rich structured message" — would let the
  presenter say something interesting before moving on.

- After `hexdump -C ... | tee /dev/tty | vim -`, the audience sees raw hex in
  vim.  There is no 👆-note and no inline comment.  The presenter has to
  improvise the explanation ("this is what travels on the wire") without any
  prompt in the script.  Add a brief inline comment after the command.

- After `prototext decode --raw ... | tee /dev/tty | vim +'set ft=pbtxt' -`, the
  👆-note ("No schema yet: field numbers and wire types, but no names") is
  correct and well-placed.  Good.  However, the jump from "no schema" to "with
  the right schema" (next command) happens with only an inline comment — no
  narrative block explaining *how* prototext knows which schema to use.  The
  audience is left thinking it's magic.  A one-liner — "we give it the schema
  explicitly with --type" — before the next command would close that gap.

- `vim $GOOGLEAPIS_DESCS/google/type/postal_address.proto` opens a file with no
  preceding narrative and no 👆-note.  The inline comment ("Here is the schema
  that unlocked it") is the only signal.  This is one of the most important beats
  in the section — the audience sees *the key* — but it has the thinnest
  framing.  Promote the inline comment to a narrative block, or at minimum add a
  spoken cue that the presenter can follow.


Section 4 — Schema auto-inference

- The opening narrative explains scoring well.  But it immediately says "thousands
  of types" and "picks the best match" without telling the audience *how many*
  types are in the googleapis DB.  Adding the actual number (or an order of
  magnitude — "~10 000 message types") would make the scoring claim concrete and
  impressive rather than vague.

- After the successful PostalAddress inference, there is no 👆-note.  The score
  line is the headline result, but the script does not point at it.  The `👆`
  note appears later in the narrative block, which is correct per the spec.
  However the narrative block is four lines long and mixes two ideas: the score
  explanation, and the segue to the next example.  These could be two separate
  beats — pause for the score, then a separate narrative for "let's try another."

- The ambiguity beat (UsableSubnetwork, two equal scores) is good in concept.
  But after the tie is revealed, the resolution command has only an inline comment
  ("With --type the ambiguity is resolved").  The inline comment is too brief for
  something that introduces `--type`, a flag the audience will see again.  A
  short narrative block — even one line — would give the presenter a moment to
  explain the pattern before running the command.

- The `decode` command for UsableSubnetwork (line ~95) produces output directly to
  the terminal, with no `tee /dev/tty | vim`.  The tie message vanishes as soon
  as the next command runs.  Since the tie message is the reveal, it should stay
  visible.  The simplest fix: add `| cat` (no-op) or ensure the step halts here
  before the presenter advances.  Actually the issue is that the output is already
  on screen when the audience reads the 👆-note — that part is fine.  But if the
  next command scrolls the tie off screen, the note's reference is lost.  The
  script should not advance past this note until the audience has seen both the
  tie and the note together.  This is inherent to the demo runner's step-by-step
  model, so it is fine as-is — but worth the presenter being aware of.


Section 5 — Non-canonical protobufs

- Two `vim` calls on the postal_address.proto schema in this section: one at the
  start of section 5 (line 121), and one was present in section 3 (line 67).
  Section 5's vim open has a narrative before it ("--- Hidden field ---"), which
  frames it as "look at the schema before we tamper with it."  But the narrative
  block reads as a header, not as an instruction.  The presenter needs to
  articulate why they are opening the schema again.  Add one sentence: "Let's
  look at the schema one more time before we tamper with it."

- The sed command that crafts `postal_hidden.pb` is the most opaque line in the
  entire script.  The `#@ string = 11` annotation is unexplained syntax.  The
  narrative before it says "slip a secret value before the real one" — good
  framing — but the implementation detail leaks through anyway.  Two options:
  (a) add a brief gloss: "# (#@ annotations are prototext's wire-encoding hints)"
  or (b) hide the sed behind a helper script.  Go with option (a).

- After `hexdump -C stash/postal_hidden.pb | tee /dev/tty | vim -`, the 👆-note
  ("The hidden field is right there in the binary.") is now correctly placed.
  Good.  But "right there" without a pointer is vague — hex is hard to read on
  stage.  The original note said "field 6" which was removed because it was hard
  to read.  Consider adding "look for two consecutive 5a-prefixed records" or
  some other concrete pointer that a presenter can use.  Alternatively, annotate
  the hex output itself (not in the script — in the narrative block after the
  command) with "field 6 appears twice."  The audience does not need to read the
  hex themselves; the presenter pointing at the screen is enough — but the script
  should give the presenter something to say.

- The `diff - stash/postal_patched.pb && echo byte-exact` beat is the strongest
  forensic moment in the entire demo — prototext is byte-exact, protoc is not.
  Yet there is no narrative block before this command to prime the audience.  The
  inline comment "# prototext round-trip: the over-hung byte is preserved exactly"
  is good but insufficient: the preceding command already showed the round-trip.
  The audience needs to understand that we are now *comparing* the two.  A
  narrative block — "Let's verify the round-trip is lossless: diff says
  byte-exact." — would give the presenter a spoken cue and let the `byte-exact`
  echo land as a punchline.


Section 6 — Building a scoring database

- The vocabulary recap at the top of the section (protobuf / schema / descriptor)
  is helpful context for what follows.  Good placement here — before descriptors
  are used, not before they are demonstrated (the old problem is fixed).  One
  minor issue: the definitions use em-dashes (`—`) and left-align, but the
  columns are not aligned, so on screen the definitions appear ragged.  This is a
  minor cosmetic point; the content is clear.

- The reproto `--build-schema-db` command has eight `--seed` flags.  On a
  projected screen this will scroll for a long time.  The audience will lose the
  thread.  There is no narrative block before it explaining *why* eight seeds —
  just a one-liner inline comment.  The narrative block above explains the
  FileDescriptorProto decode, not the DB build.  Insert a narrative block between
  the FileDescriptorProto beat and the DB build beat that explains the goal: "8
  services define OperationMetadata with the same wire shape — let's build one
  scoring DB for all of them."

- The two `prototext decode` commands that follow the DB build should demonstrate
  two contrasting outcomes: one unique match (functions/v2 fixture, score 26 with
  extra fields) and one 8-way tie (batch/v1 fixture, identical 7-field shape).
  The tie then motivates the Hopcroft section.  Both results need 👆-notes to land
  the point; the inline comment alone is not enough.

- The scoring graph is opened with `xdg-open stash/opmeta.html` followed
  immediately by a narrative block (the legend).  `stash/opmeta-hopcroft.html` is
  a sibling product: reproto automatically produces both the raw graph and the
  Hopcroft-minimised graph from a single `--emit-scoring-html` invocation.  The
  narrative should say so — audiences will wonder where the second file came from.

- The IpRules beat ("5 nodes raw, 4 nodes after Hopcroft") is good but the
  narrative before it only shows the proto definitions.  It does not explain *why*
  Allowed and Denied collapse: their wire shapes are identical, so the scoring
  automaton cannot distinguish them.  This is the punchline of the Hopcroft story.
  The narrative block already says "Hopcroft merges them automatically" — good —
  but does not say *what that means for the user*: a binary that could be either
  Allowed or Denied will match the same node in the graph, and prototext will
  report a tie.  That is the actionable insight.  One more sentence would close
  it.

- There is no narrative or command between `xdg-open stash/iprules.html` and
  `xdg-open stash/iprules-hopcroft.html`.  The presenter is expected to point at
  the raw graph, identify Allowed and Denied as separate nodes, then advance.  But
  the script gives no spoken cue for this.  Add a brief narrative block: "Look at
  the raw graph: Allowed and Denied are separate amber nodes.  Now watch Hopcroft
  collapse them."


Section 7 — Decompiling descriptors

- The section opens well: the narrative explains where descriptors come from and
  why decompilation is useful.  Good.

- The intro comment before the `prototext decode` command ("First, let's decode
  the PostalAddress descriptor itself — a binary .pb file that encodes the schema
  of PostalAddress as a FileDescriptorProto") is an inline two-line comment, not
  a narrative block.  On stage the presenter will have to read it as a comment.
  Promote this to a narrative block so the presenter has a proper pause beat
  before the reveal.

- After `reproto -q ... $GOOGLEAPIS_DESCS/google/type/postal_address.pb` (the
  single-file decompile), the 👆-note ("Human-readable .proto source, recovered
  from the binary descriptor.") is correct.  Good.  But there is no narrative
  explaining what the audience is now looking at in vim — how does it compare to
  what we saw earlier in section 3?  The PostalAddress .proto appears twice in the
  demo (section 3 and section 7); the presenter should say something like "this is
  the same schema we saw in section 3, but now reproto produced it, not protoc."

- `reproto -O stash/googleapis-out --use-variant descriptor -I $GOOGLEAPIS_DESCS .`
  runs without `-q` — intentional, per previous assessments.  But there is no
  narrative *after* it finishes to say what to do in VSCode.  The narrative block
  before `code --reuse-window stash/googleapis-out` mentions Go to Definition and
  find-all-references, but the presenter has no scripted beat to follow inside
  VSCode.  A commented presenter cue — `# Navigate to google/type/postal_address.proto`
  `# and Ctrl-click on an import` — would make this beat executable rather than
  improvised.

- The `--prune` bridge at the end of the section ("What if some descriptors are
  missing…") transitions into section 8.  This is well-written.  However it ends
  with "The --prune flag makes this explicit and controlled" before the section
  header appears.  On stage the presenter advances past this block, sees a blank
  beat, then hits the section header.  Consider removing the blank line between
  the closing narrative and the section header so the transition is immediate.


Section 8 — Seeding and pruning

- `find stash/audit-seed -name '*.proto' | sort` outputs full paths prefixed with
  `stash/audit-seed/`.  On a projected screen these are long.  Previous assessment
  suggested `sed 's|stash/audit-seed/||'` to strip the prefix — still unaddressed.
  The naked paths are workable but not elegant.

- `code --reuse-window stash/audit-seed/google/cloud/audit/audit_log.proto`
  opens a single file in VSCode.  No narrator cue follows — the presenter is
  expected to improvise what to say while VSCode opens.  A one-line comment —
  "# Point out the Status field — that is what we are about to prune" — would
  give the presenter a concrete action and prepare the audience for the next beat.

- The same issue arises after `code --reuse-window stash/audit-pruned/...`: the
  audience needs to know *what to look at* in the file.  The orphaned `///` comment
  is the reveal.  Add a presenter cue: `# Scroll to the status field — now a ///
  orphan`.  Previous assessment suggested `vim +/'^  ///'` as an alternative to
  jumping directly to the orphan; that is still unaddressed.


Conclusion

- The recap bullet list has five items but two of them overlap conceptually:
  "a schema DB that infers protobuf types without knowing the .proto source" and
  "a schema DB builder that collapses structurally equivalent types" both describe
  the scoring DB.  To a first-time audience these sound like the same thing.
  Consider merging them or clarifying the distinction: one is about *inference*
  (scoring), the other is about *deduplication* (Hopcroft).

- The conclusion has no call to action or pointer to resources — no URL, no repo,
  no "try it yourself."  The opening narrative block (section 1) mentions
  `github.com/ThalesGroup/prototools/blob/main/docs/tutorial.md` but by the time
  the conclusion lands, the audience has long forgotten it.  Repeat the repo URL
  (or a short alias) in the conclusion so it is the last thing on screen.

- There is no spoken farewell — the demo ends with `# THE END` and the sentinel
  newlines.  That is fine mechanically.  But it means the last thing on the
  *presenter's* screen is the conclusion bullet list, with no scripted closing
  word.  One final inline comment — `# Thank the audience; invite questions.` —
  would make the handoff clean.
