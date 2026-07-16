<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# gRPConf 2026 — Submission Proposal

**Tool:** prototools
**Proposed format:** Talk (20 min — standard gRPConf session slot)

---

## Proposed title

**"What's really in that .pb file? Lossless decoding, schema inference, and
descriptor archaeology with prototools"**

Alternative: **"Beyond protoc --decode: lossless decoding, schema inference,
and descriptor decompilation for the working gRPC engineer"**

---

## Abstract (public-facing)

Standard protobuf tooling has a blind spot. `protoc --decode` silently
normalises non-canonical bytes, requires the original `.proto` source files,
and has no idea which type a mystery blob might be. Engineers working with
gRPC in the wild — debugging network captures, analysing extracted binaries,
reverse-engineering third-party services, or auditing messages for data
smuggling — regularly hit this wall.

prototools is a pair of open-source CLI tools (MIT, Thales / Atlant.is) that
fill this gap.

**prototext** is a lossless, bidirectional converter between binary protobuf
wire format and human-readable text. It decodes with or without a schema,
preserves every non-canonical byte via inline annotations, and round-trips
byte-exact. Supply a descriptor DB and it automatically infers the message
type across a corpus of thousands of schemas in under a second — surfacing
ties and ambiguities rather than silently picking one.

**reproto** reconstructs compilable `.proto` source files from any
`FileDescriptorSet`, handling proto2, proto3, and editions. Its
`--force-proto2-output` flag translates an editions descriptor to
wire-compatible proto2 source — a practical escape hatch for Rust
developers using the prost / prost-reflect crates, which do not yet support
editions syntax, while preserving full wire-level compatibility. A
companion tool, `protoscan`, scans binaries and firmware images for
embedded descriptor blobs and feeds them to reproto for source recovery.

The talk is built around four live terminal demos using a pre-built
googleapis schema DB (~8 000 types). No slides-only material: every claim
is demonstrated in a shell.

---

## Talk outline (sketch — to be detailed after acceptance)

*The full tutorial (`demo/01-tutorial.sh`) runs 8 sections in ~1 hour.
A 20-minute slot fits roughly 2–3 sections. The detailed talk design is
deferred until after acceptance; what matters now is the submission
material below.*

Rough allocation:
- Framing: 2 min
- What's inside a protobuf + hidden-field demo: 7 min
- Schema auto-inference: 6 min
- Decompiling descriptors + `--force-proto2-output` mention + wrap-up: 5 min

The full tutorial is also available as a 1-hour workshop format
(`demo/01-tutorial.sh`) for venues that offer longer slots (e.g. KubeCon
tutorial track, 75 min).

---

## CFP requirements (gRPConf North America 2026)

*Source: https://events.linuxfoundation.org/grpconf/program/cfp/*
*Submission portal: https://sessionize.com/grpconf-north-america-2026/*

### Key dates

| Milestone | Date |
|---|---|
| CFP closes | Sunday, **June 14, 2026** at 11:59 pm PDT |
| Notifications | Monday, July 6, 2026 |
| Schedule announced | Wednesday, July 8, 2026 |
| Event | Thursday, **September 3, 2026** — Mountain View, CA |

> **FLAG — deadline is June 14.** Depending on today's date this may be
> very close. Submit early; Sessionize does not allow editing after the
> deadline.

### Required submission fields

1. **Session title** — title case, inclusive language compliant.
2. **Session description** — third-person, error-free, explains problem,
   contribution, and relevance.
3. **Ecosystem benefit** — explicit explanation of what attendees gain.
4. **Case study flag** — yes/no designation.
5. **CNCF projects and open-source technologies** — list all relevant ones.
6. **Speaker profile** — name, company, job title, biography, photo
   (all displayed publicly on the schedule).
7. **Prior talk recording** — optional but strongly recommended by the
   programme committee.

### Format

- **Session Presentation** — 20 minutes, 1–2 speakers. ← target format
- Panel Discussion — 30 minutes, 3–5 speakers (all names required upfront;
  no all-male panels; no single-company panels).
- Codelab — 60 minutes, 1–3 instructors.

### Hard rules

- Maximum **two proposals per speaker** across all formats.
- Maximum one panel + one non-panel session if both are accepted.
- No sales/marketing pitches; no proprietary/closed-source technology.
- **No submissions previously presented at a Linux Foundation event within
  one year.** (prototools has not been presented at any LF event — clear.)
- All speakers must agree to the CNCF Code of Conduct.
- Accepted speakers receive one complimentary event pass.
- Slides must be uploaded before the event.

### Topic categories (pick one)

- Getting Started with gRPC
- gRPC in-Production
- gRPC + AI
- User Stories and Case Studies
- Implementation
- **Ecosystem and Tooling** ← correct category for prototools
- Codelabs

---

## Submission plan

### Step 1 — Google colleague conversation (do this first)

Before writing the final abstract, establish one of the following:

- **Option A (best):** Google colleague agrees to be listed as co-speaker
  for a 2–3 minute "why I use this" segment. Adds a Google name to the
  submission. Requires them to be comfortable being publicly associated
  with retro-engineering tooling.
- **Option B:** Permission to write "used by engineers at Google and
  Thales" in the abstract. Costs the colleague nothing but a sentence of
  approval.
- **Option C (minimum):** A GitHub star or public comment from the
  colleague before June 14, giving the programme committee something to
  find when they search the repo.

S3NS affiliation (Thales-Google JV) must appear explicitly in the speaker
bio regardless of what the colleague agrees to.

### Step 2 — record a short English-language demo screencast

The Sessionize form accepts a video link. Two existing recordings are
available but imperfect:

- Pivotal Paris 2018 — English, unrelated topic. Demonstrates ability to
  present in English.
- Thales internal — French, prototools-specific. Demonstrates mastery of
  the material.

The strongest supplement is a **3–5 minute English screencast** showing the
hidden-field demo and the schema auto-inference demo, recorded before
submitting. Upload to YouTube (unlisted is fine) and paste the link into
the Sessionize form. If time is short, submit both existing links with
brief annotations in the "additional notes" field.

### Step 3 — fill the Sessionize form

Use the draft material in the next section. Paste each field directly;
do not improvise in the form.

### Step 4 — prepare slides (required before the event if accepted)

16:9 aspect ratio, PDF format, max 50 MB. One slide per demo is enough;
the talk is terminal-driven. Prepare a fallback slide for each demo in
case of a network or environment failure.

---

## Draft submission material

### Draft title (choose one)

**Option A (problem-first):**
Beyond protoc --decode: Lossless Decoding, Schema Inference, and
Descriptor Archaeology with prototools

**Option B (hook-first):**
What's Really in That .pb File? Decoding, Inference, and Descriptor
Recovery for the Working gRPC Engineer

> Title must be in title case and follow inclusive language guidelines.
> Both options are clean. Option A is more searchable; Option B is more
> memorable in a programme listing.

---

### Draft session description

*(Third-person, as required by the CFP. ~250 words.)*

Every gRPC engineer eventually faces one of three situations: a binary
`.pb` blob of unknown type, a compiled descriptor with no `.proto` source,
or an editions descriptor that a downstream toolchain cannot consume.
Standard tooling stops short in all three cases: `protoc --decode`
requires both the original source files and the exact type name, silently
discards non-canonical bytes, and crashes on malformed input.

prototools is a pair of open-source CLI tools (MIT) that fill this gap.

**prototext** is a lossless, bidirectional converter between binary
protobuf wire format and human-readable text. It decodes with or without
a schema, preserves every non-canonical byte via inline annotations, and
round-trips byte-exact. When supplied with a descriptor DB it
automatically infers the message type — ranking all candidates from a
corpus of 8 000+ types in under a second, surfacing ties rather than
silently committing to one result. It also exposes a subtle but
exploitable wire-format property: repeated occurrences of an
`optional` field, where ordinary decoders apply last-write-wins and
silently discard all but the final value.

**reproto** reconstructs compilable `.proto` source files from any
`FileDescriptorSet`, handling proto2, proto3, and editions. Its
`--force-proto2-output` flag is a practical workaround for Rust teams
using the prost / prost-reflect crates, which do not yet support editions
syntax: translate the descriptor to wire-compatible proto2 source and
compile normally.

The talk is built around four live terminal demos using a pre-built
googleapis schema DB (~8 000 types). No slides-only material: every claim
is demonstrated in a shell.

---

### Draft ecosystem benefit statement

*(The CFP requires an explicit explanation of how attendees benefit.)*

Attendees leave with two immediately installable tools
(`cargo install --locked prototext`) and a concrete workflow for three
problems they are likely to have already encountered: decoding an unknown
protobuf payload without its schema, recovering `.proto` source from a
compiled descriptor, and consuming an editions descriptor from a service
whose toolchain predates editions support. The hidden-field demo also
raises awareness of a wire-format behaviour that is exploitable for data
smuggling and invisible to all standard SDKs and decoders — a security
insight with direct relevance to anyone operating gRPC services in
production.

---

### Draft CNCF projects and open-source technologies field

- Protocol Buffers (protobuf) — core subject
- gRPC — the transport and ecosystem context
- prost / prost-reflect (Rust crates) — the editions compatibility use case
- prototools (MIT, github.com/ThalesGroup/prototools) — the tool presented
- Rust / Cargo — implementation language and distribution
- Nix — reproducible build and demo environment

---

### Draft speaker bio

*(Public-facing; will appear on the schedule.)*

Frederic Ruget is a software engineer at S3NS, a Thales-Google joint
venture specialising in cloud security. He works on protobuf tooling and
binary analysis, and is the author of prototools, an open-source suite
of utilities for decoding, inspecting, and reconstructing protobuf
descriptors and wire-format messages. prototools is used by engineers at
S3NS and [Google / Thales — confirm with colleague before submitting].

*(Add: link to Pivotal Paris 2018 recording for English-language evidence.
Add: link to Thales internal recording or English screencast if available.)*

---

## Important flags

> **FLAG 1 — deadline: June 14, 2026.**
> The CFP closes in days. All steps above (colleague conversation,
> screencast, final abstract text) must be completed before then.
> Sessionize does not allow post-deadline edits.

> **FLAG 2 — "no LF event within one year" rule.**
> prototools has not been presented at any Linux Foundation event.
> Confirm this is still true. If it has been shown at KubeCon or any
> other LF/CNCF event in the past 12 months, the submission is ineligible
> or requires an explanation.

> **FLAG 3 — two-proposal maximum.**
> If submitting to gRPConf India as a rehearsal, that counts toward the
> two-proposal cap only if it is to the same Sessionize CFP. North America
> and India are separate CFPs — both can be submitted to independently.

> **FLAG 4 — retro-engineering framing.**
> The CFP explicitly prohibits "unlicensed or potentially closed-source
> technologies." `protoscan` (scanning binaries for embedded descriptors)
> could read as retro-engineering of proprietary software. The description
> should frame it as a diagnostic and interoperability tool, not a
> reverse-engineering tool. The hidden-field demo should be framed as a
> security audit capability, not as an exploit tutorial.

> **FLAG 5 — speaker photo required.**
> The Sessionize speaker profile requires a photo for public display.
> Have one ready before opening the submission form.

---

## Fit assessment — how prototools stacks up against past gRPConf programs

*Based on a review of gRPConf 2024 (Sunnyvale, Aug 27 2024), gRPConf 2025
North America (Sunnyvale, Aug 26 2025), and gRPConf India 2025 (Bengaluru,
Nov 19 2025).*

### What the conference looks like in practice

gRPConf is a single-day, single-track (or two-track) event organised by the
CNCF / Linux Foundation, held at Google offices, with an audience of gRPC
practitioners, maintainers, and power users. Sessions are **20-minute
presentations** (the default slot), with a small number of 60-minute
hands-on codelabs.

The program consistently falls into a handful of buckets:

- **Core gRPC internals** — language runtimes (gRPC-Go, gRPC-Rust, gRPC-Swift),
  load balancing, HTTP/3 transport, TLS deep dives. Typically by Google or
  language-runtime maintainers.
- **Production war stories** — case studies from Coinbase, Adobe, Cloudflare,
  Intuit, DigitalOcean, and similar. Focused on scale, latency, or migration
  lessons.
- **Observability and tooling** — OpenTelemetry, channelz, service meshes,
  debugging toolkits. A recurring theme across all three editions reviewed.
- **AI + gRPC** — new in 2025; MCP/A2A agent protocols, AI inference
  pipelines, "Should you use gRPC in your AI stack?" This track is growing
  rapidly.
- **Protobuf itself** — one dedicated talk per year: "Managing Protocol Buffers
  at Scale" (2024, Google), "Protobuf Editions" (2025, Google). Both were
  from Google internal teams.
- **Codelabs** — always present; Getting Started with gRPC in Go / Python /
  Java / Rust, plus observability deep dives.

The conference skews heavily toward Google speakers and gRPC maintainers,
but community and enterprise submissions are accepted and prominent —
Cloudflare, Apple, Adobe, Coinbase, Expedia, KodeKloud all appeared in
2024–2025.

### Strengths of the prototools submission

**1. The "ecosystem and tooling" category is an explicit CFP track.**
The 2026 CFP lists "Ecosystem and Tooling" as a named submission category.
prototools fits there precisely. The closest 2025 equivalent — "Black Box
No More: A Live Toolkit for Debugging gRPC" (KodeKloud, India) — was
accepted and well-received, validating the appetite for third-party
developer tooling.

**2. The protobuf/descriptor angle is perennially present.**
Every edition has had at least one protobuf-centric talk, and "Protobuf
Editions" was a 2025 topic. A talk that shows what you can do *with*
descriptors at runtime (decode, infer, decompile, downgrade) is a natural
complement and avoids duplicating what Google already covers.

**3. Live demos are exactly what gRPConf rewards.**
The 2024 and 2025 programs are full of demo-heavy sessions. "Black Box No
More" was explicitly pitched as a "live, hands-on session." The prototools
tutorial script is designed for presenter use — this is an advantage.

**4. The editions-to-proto2 angle is timely and concrete.**
"Protobuf Editions" was the 2025 talk; the 2026 audience will be living
with editions in production. The prost and prost-reflect crates — the
dominant Rust protobuf ecosystem — do not yet support editions syntax.
Rust teams receiving editions-compiled descriptors from upstream services
are already blocked. reproto's `--force-proto2-output` is a working
production workaround: translate the editions descriptor to wire-compatible
proto2 source, compile with protoc, use with prost as normal. This is a
concrete, nameable ecosystem problem with a concrete solution — the kind
of story that lands well at gRPConf.

**5. The security/hidden-field angle is unusual and memorable.**
None of the past sessions touched protobuf wire-level security. This
differentiates the submission from the usual "here is a useful tool"
narrative and gives programme committee members a strong reason to accept
it — it teaches something most attendees do not know.

### Weaknesses and risks

**1. The submission is from outside Google's core maintainer circle —
but Google adjacency is available and worth pursuing.**
The 2024–2025 programs are heavily Google-weighted for protobuf and core
gRPC content, but this is not a gatekeeping requirement. Cloudflare,
KodeKloud, Adobe, Coinbase, and Expedia were all accepted. The compensating
factor is a sharp problem statement and a compelling demo — both of which
this submission has.

That said, the speaker's affiliation with S3NS (a Thales-Google joint
venture) is a meaningful asset. "S3NS — a Thales-Google joint venture"
in the speaker bio signals Google adjacency without overclaiming and will
register with a programme committee that skews Google-heavy.

More concretely: at least one Google colleague is already using prototext
for personal projects, and Google is aware of the retro-engineering
toolchain. Three levers are worth pursuing before submitting, in
decreasing order of impact:

1. **Google co-presenter.** If the colleague using prototext is willing
   to be listed as a co-speaker — even for a 2–3 minute "here is why I
   reached for this" segment — that changes the submission's standing
   materially. It requires an explicit conversation about whether they are
   comfortable being publicly named in connection with retro-engineering
   tooling.
2. **Named Google user in the abstract.** "Used by engineers at Google
   and Thales" costs nothing if the colleague gives permission, and is
   strong evidence of ecosystem impact — an explicit CFP evaluation
   criterion.
3. **Informal public endorsement.** A GitHub star, comment, or LinkedIn
   mention from a named Google team member before the CFP closes gives
   the committee something to find when they search for the project.

**2. The AI angle is a narrow missed opportunity.**
The fastest-growing track in 2025 was gRPC + AI (MCP, A2A agent protocols,
inference pipelines). gRPC is already the transport layer for MCP services
(confirmed in the Intuit and Google India talks). A single sentence noting
that prototools can inspect MCP/A2A payloads without a schema — useful for
anyone debugging AI service traffic in the wild — adds genuine relevance
without distorting the talk. This is not about mentioning AI tools used
during development; it is about connecting the tool to a use case the
2026 audience will recognise.

**3. Prior speaker recordings exist but need framing.**
The CFP evaluation criteria mention "speaker expertise evidenced through
prior talk recordings." Two recordings are available: a 2018 English-language
presentation at Pivotal Paris (demonstrates English presenting ability,
unrelated topic), and a recent internal Thales presentation of prototools
to ~40 people in French (demonstrates mastery of the material, wrong
language). Submit both with brief annotations — the Thales video for
content credibility, the Pivotal video for English-language credibility.
A short (3–5 min) English-language screencast of the hidden-field and
schema-inference demos recorded specifically for the CFP would be the
strongest possible supplement.

### Verdict

**Fit: good, with secondary recommendations.**

The topic, format, and demo-first approach align well with what gRPConf
accepts. The protobuf-tooling niche is established, the editions angle is
timely, and the hidden-field security demo is a compelling hook that
distinguishes the submission from anything seen in 2024–2025.

Secondary recommendations:

- Add one sentence to the abstract connecting protobuf payload inspection
  to AI service debugging: gRPC is the transport for MCP/A2A agent
  protocols, and prototools can inspect those payloads without a schema.
- Submit both existing speaker recordings with brief annotations, and add
  a short English-language demo screencast (3–5 min) for strongest impact.
- Before submitting, approach the Google colleague who uses prototext about
  co-presenter or named-user options. State S3NS affiliation explicitly.
- Submit to the "Ecosystem and Tooling" category, not "gRPC in-production."
- Consider the gRPConf India CFP as a lower-stakes first submission.

### Sources consulted

- [gRPC Conf 2025 Schedule (sched.com)](https://grpcconf2025.sched.com/)
- [gRPC Conf 2024 Schedule (sched.com)](https://grpcconf2024.sched.com/)
- [gRPConf India 2025 Schedule with descriptions (sched.com)](https://grpconfindia2025.sched.com/list/descriptions)
- [gRPConf 2026 CFP — Linux Foundation Events](https://events.linuxfoundation.org/grpconf/program/cfp/)
- [gRPConf 2025 Announcement — grpc.io](https://grpc.io/blog/grpconf-2025-announcement/)

---

## References

- Repository: `github.com/ThalesGroup/prototools`
- Tutorial: `docs/tutorial.md`
- Annotation format reference: `docs/prototext/annotation-format.md`
- Schema matching design: `docs/schema-match.md`
- Performance benchmarks: `docs/prototext/performance.md`
- Editions-to-proto2 translation: `docs/reproto/force-proto2-output.md`
- Online docs: `https://douzebis.github.io/prototools`

---

## Other conferences to target

*Researched June 2026. Deadlines marked CLOSED are past; others are open
or upcoming.*

### Black Hat Europe 2026 — Arsenal

- **Dates:** December 7–10, 2026 — ExCeL London (Briefings: Dec 9–10)
- **Arsenal CFP deadline:** **June 19, 2026** at 11:59 pm PDT
- **Notifications:** July 22, 2026
- **Format:** Open demo booth, ~1h50m interactive session at a station
  with monitor, power, and network. No talk — attendees walk up and
  engage directly. Presenter brings their own laptop.
- **Requirements:** Tool must be open source with a public repository.
  At least 3 pages of English documentation required. No company branding,
  no paid pitches; tool-specific stickers/swag only.
- **Fit:** Excellent. Arsenal is specifically for open-source security and
  research tools. The interactive format suits a CLI tool well: attendees
  bring their own mystery `.pb` files, the presenter decodes them live.
  MIT license, GitHub repo, and the tutorial documentation satisfy all
  formal requirements. The security framing (hidden-field exploit,
  canonicality audit) is natural for a Black Hat audience without requiring
  a full academic-style research paper. Arsenal is lower-barrier than
  Briefings (no 10-page paper, no novel research requirement).
- **CFP link:** [europe-arsenal-cfp.blackhat.com](https://europe-arsenal-cfp.blackhat.com/)
- **Action:** CFP is open — **deadline June 19**, five days after gRPConf.
  Strongly consider submitting to both in the same week.

### EuroRust 2026

- **Dates:** October 14–17, 2026 — Barcelona & online
- **CFP deadline:** Not yet announced publicly (likely opens summer 2026)
- **Format:** ~30-min talks; workshops available
- **Fit:** Excellent for the Rust angle. reproto's prost / prost-reflect
  editions workaround is a directly relevant pain point for this audience.
  A talk titled "Bridging editions to prost: descriptor decompilation and
  schema inference in Rust" would land well even without the gRPC framing.
  The speaker bio is strengthened by prost-reflect PR #196 (fix for proto3
  `is_packed` default, merged May 24 2026 by Andrew Hickman) — a named,
  merged upstream contribution to a major Rust crate discovered while
  developing prototools.
- **Action:** Monitor [eurorust.eu](https://eurorust.eu/) for CFP opening.
  Prepare a Rust-focused abstract leading with prost / prost-reflect and PR #196.

### REcon — Montreal and Brussels

- **REcon 2026 Montreal:** June 19–21, 2026. CFP closed April 28 — already past.
- **REcon Brussels:** Ran in 2017–2018; no edition announced since.
  Monitor [recon.cx](https://recon.cx/) and @reconbrx.
- **Fit (if/when it returns):** REcon is a reverse engineering conference
  — hardware, firmware, protocol analysis, binary exploitation. The
  protoscan + reproto descriptor archaeology workflow is textbook RE.
  REcon pays speakers ($1 000 USD for new unpresented talks) and covers
  travel and hotel. A Brussels edition would be geographically convenient.
- **Action:** Monitor for REcon Montreal 2027 CFP (opens ~Feb–Mar 2027)
  and any Brussels announcement.

### Other venues (CFP closed for 2026; note for 2027)

| Conference | Dates | CFP closed | Fit |
|---|---|---|---|
| KubeCon NA 2026 | Nov 9–12, 2026 | May 31 | Good |
| CppCon 2026 | Sep 12–18, 2026 | May 17 | Moderate |
| RustConf 2026 | Sep 8–11, 2026 | Feb 16 | Good |
| Open Source Summit NA | ~Jun 2026 | Feb 16 | Moderate |
| DEF CON 34 | Aug 6–9, 2026 | May 1 | Conditional (security framing needed) |
| Black Hat USA 2026 | Aug 5–6, 2026 | Dec 2025 | Conditional (research angle) |
| REcon Montreal 2026 | Jun 19–21, 2026 | Apr 28 | Strong |

### Summary

| Conference | Dates | CFP status | Fit |
|---|---|---|---|
| **gRPConf NA 2026** | Sep 3, 2026 | Open — closes **Jun 14** | Excellent |
| **BH Europe 2026 Arsenal** | Dec 7–10, 2026 | Open — closes **Jun 19** | Excellent |
| gRPConf India 2026 | TBA (Nov?) | Watch for CFP | Good (rehearsal) |
| **EuroRust 2026** | Oct 14–17, 2026 | CFP not yet open — watch | Excellent (Rust angle) |
| REcon Brussels | No date announced | Watch @reconbrx | Excellent if it returns |
| KubeCon NA 2026 | Nov 9–12, 2026 | CLOSED (May 31) | Good (2027) |
| RustConf 2026 | Sep 8–11, 2026 | CLOSED (Feb 16) | Good (2027) |
| CppCon 2026 | Sep 12–18, 2026 | CLOSED (May 17) | Moderate (2027) |
| DEF CON 34 / BH USA 2026 | Aug 2026 | CLOSED | Conditional (2027) |
| REcon Montreal 2026 | Jun 19–21, 2026 | CLOSED (Apr 28) | Strong (2027) |

**Immediate actions (this week):**
1. Submit to **gRPConf NA 2026** before **June 14**.
2. Submit to **Black Hat Europe 2026 Arsenal** before **June 19** —
   a different format (interactive demo booth, not a talk), lower barrier,
   and open simultaneously. The two submissions do not conflict.
3. Monitor [eurorust.eu](https://eurorust.eu/) for CFP opening — prepare
   a Rust-focused abstract that leads with prost, prost-reflect, and the
   PR #196 upstream fix.
4. For all 2027 targets: gRPConf NA 2026 acceptance triggers the "no LF
   event within one year" rule for gRPConf 2027, but not for EuroRust,
   KubeCon, RustConf, CppCon, REcon, or Black Hat.
