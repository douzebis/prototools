<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

Demo timing estimate for demo/01-tutorial.sh
---

Beat-by-beat wall-clock estimate.  Two components per beat:
- machine time: command runs, no presenter input
- presenter time: reading narrative, talking, navigating vim/VSCode

---

S1 — Setup (~3 min)
- `--version` x2: instant
- `nix-build` (cached): ~5 s
- `rm -rf stash/*`: instant
- Presenter intro / context-setting: ~2 min

S2 — Protobufs are everywhere (~3 min)
- 3 narrative blocks: ~3 x 30 s read+talk = 1.5 min
- No commands — pure presenter time: ~1.5 min discussion

S3 — What's inside a protobuf? (~6 min)
- `ls -lh`: instant, ~15 s comment
- `hexdump | vim`: ~30 s machine, ~1 min in vim
- `prototext decode --raw | vim`: ~5 s machine, ~1 min in vim
- `prototext decode --type | vim`: ~5 s machine, ~1 min in vim
- `vim postal_address.proto`: ~1 min browsing

S4 — Schema auto-inference (~6 min)
- Narrative block: ~30 s
- `prototext decode` (inference, large DB): ~10 s machine, ~1 min in vim + narrative
- `prototext decode UsableSubnetwork` (tie): ~10 s, ~30 s discussion
- `prototext decode --type UsableSubnetwork | vim`: ~5 s, ~1 min in vim

S5 — Non-canonical protobufs (~12 min)  — richest section
- 2 narrative blocks (hidden field intro): ~1 min read
- `vim postal_address.proto`: ~30 s
- Narrative + sed craft: ~30 s machine, ~30 s explain
- `hexdump | vim`: ~30 s + 1 min vim
- `protoc decode | vim`: ~5 s + 1 min vim
- `prototext decode | vim`: ~5 s + 1 min vim + 👆 discussion
- OHB narrative blocks: ~1 min read
- `sed | encode` craft: ~5 s + ~15 s explain
- `hexdump head -1` x2 (diff): ~15 s + 30 s explain
- `prototext decode -a | vim`: ~5 s + 1 min vim + 👆 discussion
- `protoc decode | vim` (OHB gone): ~5 s + 1 min vim
- `diff && echo byte-exact`: instant, ~30 s punchline

S6 — Building a scoring database (~10 min)
- 2 narrative blocks (vocab + FDP): ~1 min
- `prototext decode FileDescriptorProto | vim`: ~5 s + 1 min vim
- 2 narrative blocks: ~30 s
- `reproto --build-schema-db` (9 seeds): ~15-30 s machine + ~30 s explain
- `prototext decode functions/v2 | vim`: ~5 s + 1 min vim + 👆 discussion
- Narrative + `prototext decode batch/v1 | vim`: ~5 s + 1 min vim + 👆 tie discussion
- `xdg-open opmeta.html` + legend narrative + graph discussion: ~2 min
- `xdg-open opmeta-hopcroft.html` + discussion: ~1 min
- IpRules narrative: ~30 s
- `reproto -q iprules`: ~10 s
- `xdg-open iprules.html` + discussion: ~45 s
- `xdg-open iprules-hopcroft.html` + discussion: ~45 s

S7 — Decompiling descriptors (~8 min)
- Narrative (where descriptors come from): ~30 s
- Inline intro + `prototext decode postal_address.pb | vim`: ~5 s + 1 min vim
- `reproto -q` single file: ~5 s
- `cat | tee | vim` result: ~1 min
- Narrative: ~15 s
- `reproto -O googleapis-out` (no -q, all files): ~30-60 s machine
- Narrative + `code --reuse-window`: ~1 min VSCode navigation
- Transition narrative to S8: ~15 s

S8 — Seeding and pruning (~8 min)
- Narrative (Simon's team): ~30 s
- `reproto -q audit-seed`: ~10 s
- `find | sort`: instant + 👆 discussion ~30 s
- Narrative + `code audit_log.proto`: ~1 min VSCode
- Narrative (prune motivation): ~30 s
- `reproto -q audit-pruned`: ~10 s
- `find | sort`: instant + ~15 s
- Narrative: ~20 s
- `code audit-pruned audit_log.proto`: ~1 min VSCode + orphan discussion

Conclusion (~1 min)
- Narrative bullet list: ~1 min read + closing words

---

Total: ~57 min  →  budget 55-65 min

---

Notes

- This is part 1 of a two-part demo.  No time budget is allocated here for
  part 2.

- The heaviest sections are S5 (~12 min, two sub-stories and many vim opens)
  and S6 (~10 min, graph browsing in the browser).

- Key risk: borderline for a one-hour slot with no slack for live questions,
  technical hiccups, or a slow nix-build.

- If the target is 45 min, the natural cuts are:
    - S6 IpRules detour (~3 min) — drop if Hopcroft point is already made
    - One of the two vim opens in S5 (e.g. skip the hexdump vim, keep the
      prototext view)
    - S7 VSCode navigation (show the file list, skip the live Go-to-Definition)
