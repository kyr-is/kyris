# Contributing to Kyris

Thank you for your interest in contributing to Kyris.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
cargo deny check
```

## Pull Requests

All PRs must pass CI checks: `fmt`, `clippy`, `test`, `audit`, `deny`.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
