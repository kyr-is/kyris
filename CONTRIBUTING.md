# Contributing to Kyris

## Contributor License Agreement

All contributors must sign the [Kyris CLA](CLA.md). The CLA bot will prompt you on your first pull request.

## Development

MSRV is 1.95. The toolchain is pinned in `rust-toolchain.toml`.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

See [AGENTS.md](AGENTS.md) for workspace layout, crate descriptions, and architecture details.

## Pull Requests

All PRs must pass CI checks: `fmt`, `clippy`, `test`, `deny`.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
