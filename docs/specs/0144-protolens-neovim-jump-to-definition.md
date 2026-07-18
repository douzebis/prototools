<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0144 — protolens: `v` jumps to a type's declaration in a handed-off Neovim

Status: implemented
Implemented in: 2026-07-18
Refs: docs/specs/0111-protolens-v1-decode-navigate-extract.md (§"Type
      definition assistance", Phase 5 — the `$EDITOR` shell-out pattern
      this spec now supersedes with a mandatory Neovim-only mechanism),
      docs/specs/0141-reproto-embed-source-code-info.md (`SourceCodeInfo.
      Location` synthesis for message *and* enum declarations — both
      Step 1 and Step 2 are implemented, confirmed 2026-07-18), docs/specs/
      0137-protolens-primitive-type-override.md (the `None` sentinel +
      15 primitive keywords prepended to the override candidate list —
      these have no declaration to jump to), docs/specs/0117-protolens-
      override-save-restore.md (`:save-overrides`/`:restore-overrides`'s
      `complete_fs_path`, the precedent for this spec's `:proto-root`
      directory completion), docs/specs/0113-protolens-v1-tui-suspend-
      resume.md (D31, existing `Ctrl-Z`/`SIGTSTP` suspend — the terminal
      save/restore precedent this spec's handoff reuses), 2026-07-18
      discussion (external-editor proposal, critique, and two rounds of
      simplification — this spec's job-control design started from a
      disposable external draft, `/tmp/neovim.md`, now fully absorbed
      and self-contained here)
App: protolens

## Background

A type FQDN (message or enum) appears highlighted under the cursor in
three places in `protolens`'s TUI:

- the **override candidate list** (`override_select.rs`), in both
  `SortMode::Inferred` and `SortMode::Lexicographic` — `override_
  candidates[override_highlight].0`;
- the **management pane** entry list (`manage_pane.rs`) —
  `overrides.entries()[manage_highlight].r#type`;
- the **main pane**, implicitly, as the resolved type annotation on any
  message/group node — `tree[cursor].span.type_fqdn`.

Today there is no way to jump from any of these to the type's actual
declaration in its `.proto` source. Spec 0111 already anticipated this
("Type definition assistance", Phase 5) and already settled the
high-level approach: shell out to an editor, suspending/resuming the
TUI around it — explicitly rejecting an embedded-vim-as-library
approach — gated on a reproto-side spec synthesizing `SourceCodeInfo`
for the schema. That reproto-side spec (0141) is now fully implemented:
`SourceCodeInfo.Location` entries exist for message declarations
*and* enum declarations (`re_enum.py`), i.e. exactly the two
declaration kinds a "type used for overriding" can be (spec 0137's
candidate list is messages, groups, and enums — plus a closed set of
primitive keywords and a `None` sentinel, neither of which are
user-declared types with a location to jump to).

2026-07-18 discussion originally proposed a generic `$EDITOR` shell-out
with an optional `--vim` flag for tighter Neovim integration. After
critique — chiefly that the two modes are wildly different in scope,
that plain `$EDITOR` string-splitting/line-jump syntax isn't actually
portable across editors, and that mouse-click modifier support doesn't
exist anywhere in `mouse.rs` today — the scope was simplified: **drop
the generic `$EDITOR` path entirely; a same-terminal Neovim handoff via
POSIX job control is the only and mandatory mechanism.** No `--vim`
flag, no editor choice, no mouse binding — a single keyboard binding,
`v`, triggers the handoff wherever a jumpable FQDN is under the cursor.

## Goals

- **G1 (key binding, all three panes).** `v` (unmodified), checked
  centrally in `handle_key` — same tier as `F1`/`Ctrl-Z`/`:` (`key_
  dispatch.rs`'s existing "checked centrally here... regardless of
  focus" comments) — ahead of the `override_focus`/`manage_open &&
  manage_focus` dispatch branches, so it fires uniformly regardless of
  which pane currently has focus. `v` is unbound today in all three
  panes (verified: no `Char('v')` arm anywhere in `protolens/src`).

- **G2 (FQDN-under-focus resolution).** A new `fqdn_under_focus(&self)
  -> Option<String>` method, branching on the same focus state `handle_
  key` already inspects:
  - override pane focused: `self.override_candidates.get(self.
    override_highlight).map(|(f, _)| f.clone())`, but `None` if that
    string is `"protolens_internal.None"` (the sentinel, spec 0137 §G1)
    or one of `decode::ALL_PRIMITIVE_KEYWORDS` — neither has a
    declaration;
  - manage pane focused: `self.overrides.entries().get(self.manage_
    highlight).and_then(|e| e.r#type.clone())`, with the same `decode::
    MESSAGE_SET_ITEM_FQDN` substitution `manage_entry_type_label`
    already applies (jump to the real, displayed extension FQDN, never
    the internal shared sentinel);
  - otherwise (main pane): `self.tree.get(self.cursor).and_then(|n|
    n.span.type_fqdn.clone())`.
  - `None` in any branch (nothing highlighted, or it's the sentinel/a
    primitive keyword): `v` sets `self.message = "no declaration to
    jump to here".to_string()` and returns — same auto-dismissing
    mechanism as every other status notice (see G4's message-routing
    note).

- **G3 (declaration lookup).** Resolve the FQDN to a `MessageDescriptor`
  or `EnumDescriptor` via `ctx.pool().get_message_by_name`/`get_enum_
  by_name`. If neither resolves, `self.message = format!("unknown
  type: {fqdn}")` and stop. Otherwise, from its parent `FileDescriptor`'s
  `FileDescriptorProto` (`.name` — the relative proto path recorded at
  compile time — and `.source_code_info`), locate the `SourceCodeInfo.
  Location` whose `path` matches the descriptor's own position, using
  the standard protoc path convention (`FileDescriptorProto.message_
  type` = field 4, `.enum_type` = field 5 top-level / field 4 within a
  `DescriptorProto`, `DescriptorProto.nested_type` = field 3 — the
  exact convention `reproto`'s own `source_info.py`/`re_descriptor.py`/
  `re_enum.py` already use to *synthesize* these entries, so the lookup
  is a plain mirror of the write side, not new domain knowledge).
  Extract the 1-indexed `(line, column)` from the `Location`'s `span`
  (0-indexed in the wire format; protoc-family editors expect
  1-indexed). If no matching `Location` exists (shouldn't happen for
  any message/enum given spec 0141 Step 1+2, but degrade gracefully
  rather than panic), fall back to line 1, column 1 of the file.

- **G4 (`-I`/`--proto-root` resolution, static and dynamic).**
  `FileDescriptorProto.name` is a relative path (e.g.
  `acme/payload.proto`) with no other anchor recorded anywhere in the
  descriptor set.
  - New CLI flag `-I`/`--proto-root <dir>` (env `PROTOTEXT_PROTO_ROOT`
    — matching `--descriptor-set`'s own `PROTOTEXT_DESCRIPTOR_SET`
    naming, not a `PROTOLENS_`-prefixed variable; the internal
    `prototools` package embedding this `oss-prototools` repo sets this
    variable, so its name is shared/external contract, not free to
    diverge per-binary — `clap` `env` feature). **Optional** — unset by
    default, since a session that never presses `v` never needs it.
  - New `:proto-root <dir>` command (added to `COMMANDS`/`resolve_
    command` in `command_line.rs`), letting the user set or overwrite
    it mid-session. Validated at set-time: if `<dir>` doesn't exist or
    isn't a directory, `self.message = format!("not a directory:
    {dir}")` and the previous value (if any) is left unchanged.
    Argument completion: a new `complete_dir_path` (a thin variant of
    the existing `complete_fs_path`, `command_line.rs`, used today by
    `:save-overrides`/`:restore-overrides`) that filters candidates to
    directory entries only — files never appear as candidates for this
    command.
  - `v`'s resolution step: if `self.proto_root` is `None`,
    `self.message = "no proto root configured; set one with :proto-root
    <dir> or -I/--proto-root".to_string()` and stop. Otherwise resolve
    `self.proto_root.join(&file_proto.name)`; if that path doesn't
    exist on disk, `self.message = format!("proto source not found:
    {path} (under proto-root {root})")` and stop — in neither case is
    Neovim spawned.
  - All of the above route through `self.message` — the existing
    auto-dismissing notice mechanism (`render.rs`'s `track_message_
    timeout`: clears after `MESSAGE_TIMEOUT` (4s) *or* on the next
    normal-mode keypress, whichever comes first — the same single
    bottom bar already used for every other error in this codebase,
    e.g. `toggle_override`'s "cannot override..."). No new UI
    mechanism.

- **G5 (Neovim job-control handoff).** A new `#[cfg(unix)]` module
  (`protolens/src/tui/neovim.rs`) doing a same-terminal handoff to
  Neovim via POSIX job control — the same primitive a shell uses for
  `fg`/`bg`/`Ctrl-Z`, and the same general family of terminal
  save/restore this codebase's existing `suspend()` (`mod.rs`, spec
  0113 D31) already performs, but with an actual child process to
  manage rather than just `raise()`-ing a signal on itself.

  Built on the **`nix` crate** (new unix-only dependency; `libc` is
  already used for `suspend()`'s single `raise()` call, and this repo's
  locked `libc` version, 0.2.186, does in fact export `WIFEXITED`/
  `WIFSTOPPED`/`WEXITSTATUS`/`WTERMSIG` as safe `pub const fn`s —
  confirmed by reading the vendored source — so raw-`libc` bit decoding
  is not actually a blocker. The real case for `nix` is ergonomics/
  type-safety: `nix::sys::wait::waitpid` returns a safe `WaitStatus`
  enum instead of a raw status `i32` to decode by hand, `nix::unistd::
  Pid`/`nix::sys::signal::Signal` avoid raw, easily-mixed-up `i32`s,
  and `nix::sys::signal::killpg` — a dedicated process-group-signal
  primitive with no safe raw-`libc` equivalent — is exactly what's
  needed to resume a whole stopped process group, see below). Confirmed
  terminal-mode crate: `crossterm = "0.29"` (`protolens/Cargo.toml`).

  **State** — a single instance, stored as a field on `App` (`editor_
  state: EditorState`, alongside the existing `pending_editor_open`)
  rather than a process-global `static`: `main.rs` constructs exactly
  one `App` for the process's entire lifetime, so there is never a
  second `App` instance in the same process that could lose track of
  the handoff, and every other piece of session state (`should_
  suspend`, `quit_confirm`, etc.) already lives on `App` — an `App`
  field avoids `Mutex`/lock/poisoning ceremony entirely (this is a
  single-threaded event loop; there is no concurrency to guard against)
  and keeps `EditorState` transitions directly inspectable/settable in
  tests the same way other `App` fields already are. "Single instance"
  itself (not one per repo root) still holds: unlike a generic multi-
  repo editor-handoff tool, `protolens` has exactly one `--descriptor-
  set`/one proto source tree in scope per invocation, so per-repo
  generality is unnecessary.

  ```rust
  enum EditorState {
      NotRunning,
      Suspended { pgid: Pid, socket_path: PathBuf },
  }
  ```

  **`open_editor(req: EditorRequest)` behavior** (not to be confused
  with `key_dispatch.rs`'s `open_definition`, the no-argument G1-G4
  method that *arms* the request `open_editor` then consumes — see
  `protolens/src/tui/mod.rs`'s Specification subsection):

  - If `NotRunning`:
    1. Fork/exec `nvim --listen <socket> "+call cursor(<line>,<col>)"
       <file>` (socket path: a fixed, per-process-lifetime temp path,
       e.g. under `std::env::temp_dir()`, unique per `protolens` PID —
       single instance, so no per-repo derivation needed).
    2. `setpgid` the child into its own new process group.
    3. Save/disable the TUI's terminal state — leave the alternate
       screen, disable raw mode (the same calls `suspend()` already
       makes; factor into a shared helper if it stays clean, otherwise
       a sibling function).
    4. `tcsetpgrp(io::stdin(), pgid)` — give Neovim the foreground.
    5. `waitpid(pgid, WUNTRACED)`, blocking.
    6. On return, see "Regaining control" below.
  - If `Suspended { pgid, socket_path }`:
    1. Run `nvim --server <socket_path> --remote-tab <file>` followed by
       a separate `nvim --server <socket_path> --remote-send
       "<C-\><C-N>:call cursor(<line>,<col>)<CR>"` as short-lived helper
       processes, stdio redirected away from the tty (`/dev/null`) since
       they only need to reach the RPC socket, not draw anything. Two
       separate `--remote-*` calls, not one combined `--remote-tab
       +cmd`: live-tested against real Neovim 0.11.5 and confirmed the
       combined form does not apply the `+cmd` to the newly opened tab.
       `<C-\><C-N>` (not `<Esc>`) leaves *any* mode to Normal — `<Esc>`
       alone doesn't reliably escape every mode (e.g. Terminal mode).
    2. `killpg(pgid, SIGCONT)` to resume the whole stopped process group
       (not `kill`, which signals only the single leader process per
       POSIX `kill(2)` and would leave any other stopped group members —
       e.g. a `:terminal` job Neovim spawned, sharing the same pgid —
       never resumed). (Order matters: the `--remote-tab`/`--remote-
       send` requests are sent *before* resuming, so they're queued and
       applied as soon as Neovim's event loop starts running again,
       rather than racing the foreground handoff.)
    3. Same disable/`tcsetpgrp`/`waitpid` sequence as above.

  **Regaining control (after `waitpid` returns):**
  - `tcsetpgrp(io::stdin(), getpgrp())` first.
  - Re-enable raw mode, re-enter the alternate screen, force a full
    redraw (the terminal currently holds Neovim's last frame).
  - `WaitStatus::Stopped(..)` → `EditorState::Suspended { pgid,
    socket_path }`, ready for the next `v` to resume it.
  - Anything else (`Exited`/`Signaled`, or any other variant — the
    latter shouldn't occur in practice given only `WUNTRACED` is
    requested, but `next_state` degrades gracefully rather than
    panicking) → `EditorState::NotRunning`, clean up the socket file if
    Neovim didn't remove it. No dedicated logging mechanism exists
    anywhere in `protolens` (confirmed: no `log`/`tracing` dependency,
    no `eprintln!` anywhere under `tui/` — `main.rs`'s own `eprintln!`
    calls are all pre-TUI, before raw mode/the alternate screen are
    entered); an unexpected exit here instead routes through
    `app.message`, the same auto-dismissing bottom-bar notice every
    other failure in this spec already uses (e.g. `format!("nvim
    exited unexpectedly: {status:?}")`).

  **`SIGWINCH`:** the kernel only delivers it to the *foreground*
  process group, so a resize while `protolens` holds the terminal never
  reaches a stopped Neovim. After each `tcsetpgrp` handoff to Neovim,
  send it `SIGWINCH` once (verify during implementation whether current
  Neovim already re-queries the size on `SIGCONT`/foreground, in which
  case this is a no-op safety net rather than load-bearing).

  Not needed: `stty tostop` tricks, or reasoning about background
  writes corrupting the screen — a stopped Neovim is never resumed
  without also being immediately foregrounded in the same call.

- **G6 (Nix packaging — bundled into the `protolens` package itself).**
  The actual distributable `protolens` binary is the `crane.buildPackage`
  derivation in `nix/rust.nix` (consumed by both `default.nix`'s
  `ci`/`prototools` targets and, only incidentally, by `nix/shells.nix`
  as a `buildInputs` entry). Since Neovim is now a *mandatory* runtime
  dependency of the `v` key, it must be wrapped into that derivation
  itself — not bolted onto `nix/shells.nix` — so `nix-build -A
  protolens` alone produces a self-contained package where `v` works.
  Concretely, in `nix/rust.nix`'s `protolens` derivation: add
  `pkgs.makeWrapper` to `nativeBuildInputs`, and in `postInstall`
  (alongside the existing `protolensPostInstall` shell-completion
  install) `wrapProgram $out/bin/protolens` to prepend a pinned Neovim
  + `buf`'s built-in LSP onto `PATH` (confirmed via `buf lsp serve
  --help` against the sandbox's installed `buf` 1.59.0: `buf lsp serve`
  is the real subcommand, stdio by default — `--pipe string   path to a
  UNIX socket to listen on; uses stdio if not specified` — standard
  LSP-client wiring, no `protols` fallback needed), and point Neovim at
  a minimal
  committed Lua config (`.proto` filetype/syntax, LSP `root_dir` via
  `buf.yaml`/`buf.work.yaml`/`.git` walk-up, `gd`/find-references, a
  documented `Ctrl-Z`/`:suspend` keymap) via `NVIM_APPNAME` or an
  explicit `-u <config>` baked into the wrapper. `nix/shells.nix`
  itself needs no changes — it already just depends on `rust.protolens`,
  which is now self-contained. This repo has no `flake.nix` (uses
  `default.nix`/`nix-shell` with `NIXSHELL_REPO`); nothing above
  introduces one.

- **G7 (tests).** Unit tests (mocked fork/exec, not spawning real
  `nvim` — matching this codebase's existing convention of never
  spawning real external processes in unit tests) for: socket-path
  derivation, and `next_state` (see Specification) — a pure `WaitStatus
  -> EditorState` function directly unit-testable with real, publicly-
  constructible `WaitStatus`/`Pid`/`Signal` values, no mocking needed.
  An integration test covering the real lifecycle: open a
  throwaway two-file proto pair (one importing the other) via the real
  job-control module, send `SIGTSTP`, confirm `Suspended` + exactly one
  `nvim` process, call `open_definition` again for the second file and
  confirm no second process spawned + foreground handed back
  correctly, then quit and confirm `NotRunning` + socket cleanup.
  Best-effort headless go-to-definition check via the LSP; documented
  as deferred to manual QA if infeasible headless. Plus `protolens`-
  side unit tests for `fqdn_under_focus`/G3's lookup: one per pane, the
  sentinel/primitive-keyword no-op case, the unknown-FQDN case, the
  unconfigured-`proto_root` case, and the "proto source not found"
  case — each asserting the exact `self.message` text, all without
  spawning `nvim`. A `:proto-root` command test: valid dir accepted,
  non-existent/non-directory rejected with the previous value
  preserved, and a `complete_dir_path` completion test asserting files
  are excluded from candidates.

## Non-goals

- N1: No generic `$EDITOR` fallback and no `--vim` flag — the Neovim
  job-control handoff is the only mechanism; there is no other mode to
  select.
- N2: No support for editors other than Neovim.
- N3: No non-Unix support — `#[cfg(unix)]` throughout, mirroring
  `suspend()`'s existing scope; `v` is a documented no-op ("unsupported
  on this platform") on non-Unix builds.
- N4: No mouse/Ctrl-click binding — keyboard-only (`v`), dropped per
  2026-07-18 feedback (`mouse.rs` has no modifier handling today; this
  avoids adding a new class of plumbing for a redundant path).
- N5: No "resume Neovim in the background without foregrounding" mode.
- N6: No broader Neovim plugin ecosystem beyond the minimal committed
  Lua config.
- N7: No multi-repo/multiple-concurrent-`EditorState` support (see
  G5) — one instance is sufficient for `protolens`'s single-
  descriptor-set-per-invocation architecture.
- N8: No change to how `SourceCodeInfo` is synthesized on the reproto
  side (spec 0141 is complete and unmodified by this spec) — this spec
  is purely a consumer.
- N9: No new status-line/message-display mechanism — `self.message`'s
  existing auto-dismiss-on-timeout-or-keypress behavior already covers
  every notice this spec needs.

## Specification

### `protolens/Cargo.toml`

New unix-only dependency alongside the existing `libc = "0.2"` (kept —
still used by `suspend()`'s `libc::raise`):

```toml
[target.'cfg(unix)'.dependencies]
libc = "0.2"
nix = { version = "0.29", features = ["process", "signal"] }
```

### `protolens/src/main.rs`

New `Cli` field, same shape as `descriptor_set` (line 42-43):

```rust
/// Root directory `.proto` source files are resolved against for `v`'s
/// jump-to-definition (spec 0144). Shares its env var naming with
/// `PROTOTEXT_DESCRIPTOR_SET` (spec 0090); set externally by the
/// internal `prototools` package embedding this repo. Optional — `v`
/// reports a message (rather than failing at startup) when unset.
#[arg(long = "proto-root", short = 'I', env = "PROTOTEXT_PROTO_ROOT")]
proto_root: Option<PathBuf>,
```

Threaded into `App::new`'s call site (main.rs:199-206) as a new trailing
argument; `App::new` stores it verbatim into the new `proto_root` field
below.

### `protolens/src/tui/mod.rs`

New `App` field, alongside `should_suspend` (mod.rs:815):

```rust
/// `-I`/`--proto-root`'s resolved value, or `:proto-root`'s last
/// successfully-set value (spec 0144 G4) — `None` until either is set.
pub proto_root: Option<PathBuf>,
```

New field, alongside `should_suspend` (mod.rs:815), following the same
"flag set in `handle_key`, acted on in `run_loop`" split `should_suspend`
already uses (`run_loop` owns the `Terminal` handle `handle_key` doesn't):

```rust
/// Armed by `open_definition` (G1-G4) once a `v` press has fully
/// resolved to a real, on-disk `.proto` location; consumed by
/// `run_loop` right after the `handle_key` call that armed it, which
/// calls `neovim::open_editor` (G5) with the `Terminal` handle only it
/// owns. Mirrors `should_suspend`'s own split for the same reason.
#[cfg(unix)]
pub pending_editor_open: Option<neovim::EditorRequest>,
```

New field, alongside `pending_editor_open` — the handoff's own state
machine (G5), stored on `App` rather than a process-global `static`
(see G5's "State" rationale: exactly one `App` per process, no
concurrency to guard against):

```rust
/// `v`'s Neovim handoff state (spec 0144 G5) — `NotRunning` until the
/// first successful `open_editor` call, `Suspended` whenever a
/// handed-off Neovim is currently stopped in the background.
#[cfg(unix)]
pub(crate) editor_state: neovim::EditorState,
```

`App::new` initializes it to `neovim::EditorState::NotRunning`,
alongside its existing field-by-field initialization of every other
`App` field.

`COMMANDS` (mod.rs:112-119) gains `"proto-root"`:

```rust
const COMMANDS: &[&str] = &[
    "extract",
    "quit",
    "type-as",
    "type-as-raw",
    "save-overrides",
    "restore-overrides",
    "proto-root",
];
```

`run_loop` (mod.rs:1270-1277), immediately after the existing
`should_suspend` check, same tier:

```rust
#[cfg(unix)]
if let Some(req) = app.pending_editor_open.take() {
    neovim::open_editor(terminal, app, req)?;
}
```

New module declaration alongside the existing `mod` list (mod.rs:1281-1289):

```rust
#[cfg(unix)]
mod neovim;
```

### `protolens/src/tui/key_dispatch.rs`

New centrally-checked binding, immediately after the existing `:`
command-line check (key_dispatch.rs:254-259) and before the
`override_focus`/`manage_open` dispatch branches — so it applies
uniformly across all three panes, same tier as `Ctrl-Z`/`F1`/`:`:

```rust
// `v` jumps to the FQDN under focus's declaration in a handed-off
// Neovim (spec 0144 G1) — checked centrally here, ahead of every
// focus-specific dispatch, so it works identically in the override
// pane, the manage pane, and the main pane. Unix-only (mirrors
// `Ctrl-Z` above): no terminal job-control equivalent elsewhere.
#[cfg(unix)]
if key.code == KeyCode::Char('v') && key.modifiers.is_empty() {
    self.open_definition();
    return;
}
```

New methods, placed in `key_dispatch.rs` near `handle_key`:

```rust
/// Resolve the type FQDN currently under focus (G2) — the override
/// candidate pane (either sort mode), the manage pane, or the main
/// pane, whichever currently holds focus. `None` when the focused row
/// has nothing to jump to: an empty candidate list/tree, the `None`
/// sentinel or a primitive keyword row (spec 0137), or the internal,
/// non-real `decode::MESSAGE_SET_ITEM_FQDN` placeholder (spec 0120/
/// 0135) — never registered as a real message in the pool, so it has
/// no declaration of its own to jump to.
#[cfg(unix)]
fn fqdn_under_focus(&self) -> Option<String> {
    if self.override_focus {
        let (fqdn, _) = self.override_candidates.get(self.override_highlight)?;
        if fqdn == "protolens_internal.None"
            || decode::ALL_PRIMITIVE_KEYWORDS.contains(&fqdn.as_str())
        {
            return None;
        }
        return Some(fqdn.clone());
    }
    let fqdn = if self.manage_open && self.manage_focus {
        self.overrides.entries().get(self.manage_highlight)?.r#type.clone()?
    } else {
        self.tree.get(self.cursor)?.span.type_fqdn.clone()?
    };
    (fqdn != decode::MESSAGE_SET_ITEM_FQDN).then_some(fqdn)
}

/// `v` (G1): resolve the FQDN under focus (G2), look up its
/// declaration (G3), resolve it against `proto_root` (G4), and — if
/// everything checks out — arm `pending_editor_open` so `run_loop` can
/// hand off to Neovim (G5) once it regains control of the `Terminal`.
/// Any failure along the way is reported via `self.message` (the
/// existing auto-dismissing bottom-bar notice) and stops here.
#[cfg(unix)]
fn open_definition(&mut self) {
    let Some(fqdn) = self.fqdn_under_focus() else {
        self.message = "no declaration to jump to here".to_string();
        return;
    };
    let Some((rel_path, line, col)) = neovim::locate_declaration(self.ctx.pool(), &fqdn) else {
        self.message = format!("unknown type: {fqdn}");
        return;
    };
    let Some(proto_root) = &self.proto_root else {
        self.message =
            "no proto root configured; set one with :proto-root <dir> or -I/--proto-root"
                .to_string();
        return;
    };
    let abs_path = proto_root.join(&rel_path);
    if !abs_path.is_file() {
        self.message = format!(
            "proto source not found: {} (under proto-root {})",
            rel_path.display(),
            proto_root.display()
        );
        return;
    }
    self.pending_editor_open = Some(neovim::EditorRequest { path: abs_path, line, col });
}
```

### `protolens/src/tui/command_line.rs`

New argument-completion arm in `start_tab_completion` (command_line.rs:
159-176), alongside the existing `save-overrides`/`restore-overrides` arm:

```rust
Some((cmd, arg_prefix)) if resolve_command(cmd) == Ok("proto-root") => {
    self.complete_dir_path(cmd, arg_prefix);
}
```

New `complete_dir_path`, a directory-only variant of the existing
`complete_fs_path` (command_line.rs:234-269) — same directory-listing
and token-replacement shape, filtered to `is_dir()` entries only (files
are never valid `:proto-root` arguments):

```rust
/// `:proto-root <dir>`'s argument completion (spec 0144 G4) — same
/// shape as `complete_fs_path`, but directory entries only: a file is
/// never a valid `:proto-root` argument.
pub(super) fn complete_dir_path(&mut self, cmd: &str, arg_prefix: &str) {
    let (dir_part, file_prefix) = match arg_prefix.rfind('/') {
        Some(i) => (&arg_prefix[..=i], &arg_prefix[i + 1..]),
        None => ("", arg_prefix),
    };
    let read_dir_path = if dir_part.is_empty() { Path::new(".") } else { Path::new(dir_part) };
    let entries = match std::fs::read_dir(read_dir_path) {
        Ok(rd) => rd,
        Err(e) => {
            self.message = format!("cannot list '{}': {e}", read_dir_path.display());
            return;
        }
    };
    let mut matches: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(file_prefix) {
            continue;
        }
        matches.push(format!("{dir_part}{name}/"));
    }
    if matches.is_empty() {
        self.message = format!("no directory matches '{arg_prefix}'");
        return;
    }
    matches.sort_unstable();
    let token_start = cmd.chars().count() + 1;
    self.apply_completion(token_start, arg_prefix.chars().count(), matches);
}
```

New dispatch arm in `run_command` (command_line.rs:344-361), alongside
`run_save_overrides`:

```rust
Ok("proto-root") => self.run_proto_root(tokens.collect()),
```

New handler, same shape as `run_save_overrides` (command_line.rs:558-572):

```rust
/// `proto-root <dir>` (spec 0144 G4): validates and sets `proto_root`
/// dynamically, overriding `-I`/`--proto-root` for the rest of the
/// session. Invalid input leaves the previous value untouched.
pub(super) fn run_proto_root(&mut self, args: Vec<&str>) {
    if args.is_empty() {
        self.message = "proto-root: missing directory".to_string();
        return;
    }
    let dir = PathBuf::from(args.join(" "));
    if !dir.is_dir() {
        self.message = format!("not a directory: {}", dir.display());
        return;
    }
    self.message = format!("proto-root set to {}", dir.display());
    self.proto_root = Some(dir);
}
```

### `protolens/src/tui/neovim.rs` (new file)

G3's declaration lookup. Confirmed against the vendored `prost-reflect`
0.16.3 source (`descriptor/api.rs`): both `MessageDescriptor::path()`
(line ~742) and `EnumDescriptor::path()` (line ~1424) already return
the exact `SourceCodeInfo.Location.path` array the owning
`FileDescriptorProto` was compiled with (doc comment: "Gets the path
where this message/enum type is defined ..., e.g. `[4, 0]`"/`[5, 0]`)
— no manual path reconstruction (walking `parent_message()` chains,
re-deriving protoc's message_type=4/enum_type=5/nested_type=3 field-
number convention) is needed on the read side:

```rust
use std::path::PathBuf;

use prost_reflect::DescriptorPool;

/// A fully-resolved `v` target: an absolute `.proto` path plus a
/// 1-indexed line/column, ready to hand to Neovim's `cursor()`.
pub(crate) struct EditorRequest {
    pub(crate) path: PathBuf,
    pub(crate) line: u32,
    pub(crate) col: u32,
}

/// Resolve `fqdn` (a message or enum) to the `.proto` file it's
/// declared in (relative to the descriptor set's own compile root,
/// e.g. `path/to/my_package.proto` — `FileDescriptor::name()`'s own
/// documented format) and its 1-indexed declaration line/column,
/// via `prost_reflect`'s own `path()` (see doc comment above) matched
/// against a linear scan of `source_code_info.location`. Returns
/// `None` only when `fqdn` doesn't resolve to any message or enum in
/// `pool` at all (G3's "unknown type" case — G2 already screens out
/// primitives/sentinels/the internal MessageSet-item FQDN before this
/// is ever called). Falls back to line 1, column 1 — never `None` —
/// when the type resolves but the file's `SourceCodeInfo` has no
/// matching `Location` (e.g. the descriptor set was compiled without
/// `--include_source_info`); `SourceCodeInfo.Location.span` is
/// 0-indexed `[start_line, start_col, end_line]`/`[start_line,
/// start_col, end_line, end_col]` (standard protoc convention).
pub(crate) fn locate_declaration(
    pool: &DescriptorPool,
    fqdn: &str,
) -> Option<(PathBuf, u32, u32)> {
    let (file, path) = if let Some(m) = pool.get_message_by_name(fqdn) {
        (m.parent_file(), m.path().to_vec())
    } else if let Some(e) = pool.get_enum_by_name(fqdn) {
        (e.parent_file(), e.path().to_vec())
    } else {
        return None;
    };
    let (line, col) = file
        .file_descriptor_proto()
        .source_code_info
        .as_ref()
        .and_then(|sci| sci.location.iter().find(|loc| loc.path == path))
        .map(|loc| (loc.span[0] as u32 + 1, loc.span[1] as u32 + 1))
        .unwrap_or((1, 1));
    Some((PathBuf::from(file.name()), line, col))
}
```

G5's job-control handoff. Built on the `nix` crate (`process`/`signal`
features — see Cargo.toml above), not raw `libc`: while `libc` 0.2.186
(this repo's locked version) does export `WIFEXITED`/`WIFSTOPPED`/
`WEXITSTATUS`/`WTERMSIG` as safe `pub const fn`s (confirmed by reading
the vendored source — no bit-decoding blocker), `nix::sys::wait::
waitpid` still returns a strictly more ergonomic, safe `WaitStatus`
enum instead of a raw status `i32`, and `nix::sys::signal::killpg` — a
dedicated process-group-signal primitive `libc` has no safe wrapper
for — is exactly what resuming a whole stopped process group needs
(see below). `Command::spawn` (`std::process`) is used for the actual
fork+exec (safer than a raw `libc::fork`/`execvp` pair, and this is the
only place in `protolens` that needs to spawn a child at all); `nix` is
used only for the pieces `std::process` has no API for — process-group
placement, controlling-terminal handoff, and `waitpid(WUNTRACED)`:

```rust
use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use nix::sys::signal::{killpg, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{getpgrp, tcsetpgrp, Pid};
use ratatui::backend::Backend;
use ratatui::Terminal;

use super::{restore_terminal, App};

/// `v`'s Neovim handoff state (G5) — stored on `App` (`editor_state`,
/// `mod.rs`) rather than a process-global `static`: `main.rs`
/// constructs exactly one `App` for the process's entire lifetime, and
/// this is a single-threaded event loop, so there is no concurrency to
/// guard against and no risk of losing track of the handoff across
/// `App` instances (see the Goals section G5 "State" note).
pub(crate) enum EditorState {
    NotRunning,
    Suspended { pgid: Pid, socket_path: PathBuf },
}

fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("protolens-nvim-{}.sock", std::process::id()))
}

/// Pure `WaitStatus -> EditorState` transition (G7): a `Stopped` result
/// re-arms `Suspended` with the same `pgid`/`socket_path` (nothing else
/// distinguishes one stop from the next); any other result — `Exited`,
/// `Signaled`, or otherwise — collapses to `NotRunning`. `pgid` is
/// passed in rather than read from `status` because `waitpid` is
/// called directly on the leader `pgid` (see `open_editor` below, not
/// the negated group-wide form), so the caller already knows it, and a
/// `Stopped(pid, _)` result's `pid` is always that same `pgid` by
/// construction — no reconciliation needed. Directly unit-testable
/// with real, publicly-constructible `WaitStatus`/`Pid`/`Signal`
/// values; no mocking required.
fn next_state(pgid: Pid, socket_path: PathBuf, status: WaitStatus) -> EditorState {
    match status {
        WaitStatus::Stopped(..) => EditorState::Suspended { pgid, socket_path },
        _ => EditorState::NotRunning,
    }
}

/// `v`'s Neovim handoff (G5), called by `run_loop` right after the
/// `handle_key` call that armed `app.pending_editor_open`. Mirrors
/// `suspend`'s own shape — leave the terminal exactly as a normal exit
/// would, hand off control, restore raw/alt-screen/mouse-capture on the
/// way back (spec 0113 D31) — generalized to two cases: no Neovim
/// running yet (fork/exec a fresh instance via `--listen`) or one
/// already `Suspended` from an earlier `v` press (send it `--remote-
/// tab`/`--remote-send` requests over its existing `--listen` socket
/// instead of spawning a second instance, then `SIGCONT` it) — G5's
/// "single instance" decision.
///
/// `--remote-tab`/`--remote-send` flags and the `<C-\><C-N>` mode-
/// escape prefix live-verified against a real Neovim 0.11.5 (2026-07-
/// 18 research): a combined single-call `--remote-tab +cmd` does *not*
/// apply `+cmd` to the newly opened tab — two separate calls are
/// required, as below.
pub(crate) fn open_editor<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    req: EditorRequest,
) -> io::Result<()> {
    restore_terminal();
    terminal.show_cursor()?;

    let (pgid, socket_path) = match &app.editor_state {
        EditorState::NotRunning => {
            let socket_path = socket_path();
            let goto = format!("+call cursor({},{})", req.line, req.col);
            let child = Command::new("nvim")
                .arg("--listen")
                .arg(&socket_path)
                .arg(goto)
                .arg(&req.path)
                .process_group(0) // new pgid, equal to the child's own pid
                .spawn()?;
            let pgid = Pid::from_raw(child.id() as i32);
            tcsetpgrp(io::stdin(), pgid).ok();
            (pgid, socket_path)
        }
        EditorState::Suspended { pgid, socket_path } => {
            let goto = format!("cursor({},{})", req.line, req.col);
            let _ = Command::new("nvim")
                .arg("--server")
                .arg(socket_path)
                .arg("--remote-tab")
                .arg(&req.path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("nvim")
                .arg("--server")
                .arg(socket_path)
                .arg("--remote-send")
                .arg(format!("<C-\\><C-N>:call {goto}<CR>"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let pgid = *pgid;
            tcsetpgrp(io::stdin(), pgid).ok();
            killpg(pgid, Signal::SIGCONT)?;
            (pgid, socket_path.clone())
        }
    };

    let status = waitpid(pgid, Some(WaitPidFlag::WUNTRACED))?;
    tcsetpgrp(io::stdin(), getpgrp()).ok();
    let next = next_state(pgid, socket_path.clone(), status);
    if matches!(next, EditorState::NotRunning) {
        let _ = std::fs::remove_file(&socket_path);
        if !matches!(status, WaitStatus::Exited(..) | WaitStatus::Signaled(..)) {
            // No dedicated logging mechanism exists in protolens (no
            // `log`/`tracing` dependency; `eprintln!` is used only
            // pre-TUI in main.rs) — an unexpected `waitpid` result
            // routes through the same auto-dismissing `app.message`
            // notice every other failure in this spec already uses.
            app.message = format!("nvim exited unexpectedly: {status:?}");
        }
    }
    app.editor_state = next;

    crate::tui::enable_raw_mode_and_reenter(terminal)?;
    Ok(())
}
```

`crate::tui::enable_raw_mode_and_reenter` factors the
`enable_raw_mode`/`push_keyboard_enhancement`/`EnterAlternateScreen`/
`EnableMouseCapture`/`terminal.clear()` sequence already duplicated
verbatim at the tail of `suspend()` (mod.rs:1189-1193) into a shared
helper, reused by both `suspend()` and `open_editor()`.

### `nix/rust.nix`

Wraps the existing `protolens` derivation (rust.nix:254-269) itself via
`postInstall` + `pkgs.makeWrapper`, prepending a pinned Neovim and `buf`
(for `buf lsp serve`, G6) onto `PATH` so `open_editor`'s
`Command::new("nvim")` and the bundled Lua config's LSP client always
resolve regardless of the user's own `$PATH`:

```nix
protolensPostInstall = ''
  installShellCompletion --cmd protolens \
    ...  # unchanged
  wrapProgram $out/bin/protolens \
    --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.neovim pkgs.buf ]}
'';
```

`nativeBuildInputs` for the `protolens` derivation gains
`pkgs.makeWrapper` alongside the existing `pkgs.installShellFiles`
(rust.nix:254-262). A minimal bundled Lua config wiring Neovim's LSP
client to `buf lsp serve` (confirmed subcommand, stdio by default — see
G6) is deferred to implementation; G6 only commits to Neovim (and
`buf`) being on `PATH`; go-to-definition inside the handed-off Neovim
beyond simple `cursor()` positioning (e.g. actual LSP jump-to-symbol
across files) is out of this spec's scope (N6).

## Test plan

See G7.
