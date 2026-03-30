<!--
SPDX-FileCopyrightText: 2026 THALES CLOUD SECURISE SAS

SPDX-License-Identifier: MIT
-->

# Contributing guidelines

Thank you for your interest in contributing to `prototools`!

## How to contribute

### Reporting issues

Open an issue on [GitHub](https://github.com/ThalesGroup/prototools/issues).
Please include a minimal reproducer and, for decoding/encoding bugs, the
exact bytes involved (e.g. as a `printf '\xNN...'` one-liner).

### Submitting a pull request

1. Fork the repository and create a branch from `main`.
2. Make your changes.
3. Run `nix-build` before submitting — it runs `cargo fmt --check`,
   `cargo clippy --all-targets`, and the full test suite.  The PR will
   not be merged if any of these fail.
4. Open a pull request against `main` with a clear description of the
   change and its motivation.

### Coding style

- Rust formatting is enforced by `cargo fmt` (rustfmt defaults).
- Clippy warnings are treated as errors (`-D warnings`).
- Keep changes focused — one logical change per PR.

### Testing

```shell
cargo test           # run the test suite
nix-build            # full fmt + clippy + test pipeline
```

New functionality should be accompanied by tests.  The test suite lives
in `prototext/tests/`.

## License

By contributing, you agree that your contributions will be licensed
under the MIT license — see [`LICENSES/MIT.txt`](LICENSES/MIT.txt).
