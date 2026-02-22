# Contributing to SIGIL Protocol

Thank you for your interest in improving SIGIL. Contributions of all kinds are welcome — from bug reports and documentation fixes to new scanner patterns and protocol proposals.

---

## Ways to Contribute

### 1. Report a Bug

Open a [GitHub Issue](https://github.com/sigil-eu/sigil/issues/new?template=bug_report.md) using the **Bug Report** template.

Please include:

- SIGIL crate / SDK version (`cargo pkgid sigil-protocol` or `npm list sigil-protocol`)
- Minimal reproduction (code + input that triggers the bug)
- Expected vs. actual behaviour

### 2. Propose a Feature

Open an Issue using the **Feature Request** template or start a [GitHub Discussion](https://github.com/sigil-eu/sigil/discussions).

For changes to the SIGIL specification, please open a discussion first — spec changes have broader impact than code changes and benefit from community input before implementation.

### 3. Submit a New Scanner Pattern

**Option A — Web form (no code required):**
Visit [registry.sigil-protocol.org](https://registry.sigil-protocol.org) → "Submit a Pattern". You need a `did:sigil:` identity and an Ed25519 key pair.

**Option B — Pull Request:**
Add an entry to `sigil-registry/migrations/` following the existing seed format. Include:

- A test string that the pattern matches
- A test string that the pattern does NOT match (neighbour false-positive check)
- Evidence that the pattern does not exhibit catastrophic backtracking (ReDoS)

### 4. Fix a Bug or Implement a Feature

1. Fork the repository
2. Create a branch: `git checkout -b fix/your-description` or `feat/your-description`
3. Make your changes, run checks (see below)
4. Open a Pull Request against `main`

---

## Development Setup

### Rust crate (`sigil-rs/`)

```bash
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

### TypeScript SDK (`sigil-ts/`)

```bash
npm install && npm run build && npm test
```

### Registry service (`sigil-registry/`)

```bash
docker compose up -d postgres
cargo sqlx migrate run
cargo run
```

---

## Pull Request Requirements

- All tests pass
- `cargo fmt` and `cargo clippy` produce no warnings
- New public API documented with `///` doc comments
- Scanner patterns include at least one match and one non-match example
- PR description explains *why*, not just *what*
- Commit format: `type: short description` (`feat`, `fix`, `docs`, `perf`, `security`, `chore`)

---

## Licence

By contributing, you agree your contribution will be licensed under the same dual licence as SIGIL (EUPL-1.2 / commercial). See [LICENCE](./LICENCE).

Questions? [GitHub Discussions](https://github.com/sigil-eu/sigil/discussions) · [info@sigil-protocol.org](mailto:info@sigil-protocol.org)
