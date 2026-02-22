# Changelog

All notable changes to the SIGIL Protocol ecosystem are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

### Planned

- SIGIL-Audit v0.1 — signed, append-only audit log (metadata-only, no secret values)
- `sigil-inspector` — browser-based audit log viewer
- SIGIL-MCP binding specification finalised

---

## [0.1.5] — 2026-02-22

### Added

- **`RemoteScanner`** — fetches verified patterns from the live community registry at startup; compiles them to regex automata in memory; subsequent scans are purely in-process with zero network calls
- **Community registry** — `registry.sigil-protocol.org` live with 43 verified scanner patterns and 35 security policies across credential, secret, PII, and financial categories
- **TypeScript / Node.js SDK** (`sigil-protocol` on npm) — `RemoteScanner`, `SigilClient`, built-in fallback patterns, zero runtime deps for the scanner path
- **Community submission forms** on `registry.html` — browser-side Ed25519 signing via `SubtleCrypto`; users can submit patterns and policies without tooling
- **GitHub Actions CI/CD** — `.github/workflows/deploy.yml` for `sigil-registry`; auto-deploys to VPS on push to `main`
- **Live status counters** on `registry.html` — fetches current pattern and policy counts from the API on page load

### Changed

- Registry infrastructure migrated from Fly.io to self-hosted VPS (Frankfurt, EU) for full isolation and cost control
- `Cache-Control: public, max-age=3600` added to `/patterns/bundle` endpoint — CDN-cacheable, reduces origin load ~97% under high traffic
- Download counter `UPDATE` is now fire-and-forget (`tokio::spawn`) — no longer blocks the bundle response

### Security

- nginx rate limiting: 20 req/s (reads), 2 req/s (writes), 64KB body cap
- Docker resource limits: registry capped at 256MB RAM / 1 CPU; postgres at 512MB / 1 CPU
- SSH hardened on VPS: key-only auth, `fail2ban` active
- Daily encrypted database backups via `age` — 7-day retention, 02:00 UTC

---

## [0.1.4] — 2026-02-18

### Added

- Extended pattern set: 43 total scanner patterns including EU-specific PII (IBAN, EU VAT, national ID formats), financial instruments (SWIFT/BIC, crypto wallet addresses), and additional cloud provider credentials (GCP, Azure, Stripe, Sendgrid, Twilio)
- `sigil-registry` deployed to Fly.io Frankfurt with PostgreSQL persistence
- SQLx migrations with `ON CONFLICT DO NOTHING` — safely re-runnable seed data

### Changed

- Pattern severity schema: `low` / `medium` / `high` / `critical`
- Vote schema: Ed25519-signed votes, one per DID per pattern

---

## [0.1.3] — 2026-02-16

### Added

- Security policies collection: 35 verified policies for common MCP tools (file ops, shell, browser, database, network)
- `POST /policies` with Ed25519 signature requirement
- `GET /policies/:id/vote` endpoint

---

## [0.1.2] — 2026-02-14

### Added

- `sigil-registry` Rust/Axum service with DID resolution, scanner pattern CRUD, and vote endpoints
- `did:sigil:` identifier scheme; Ed25519-based registration and resolution
- Initial seed: 24 verified scanner patterns (credentials and PII)

### Security

- All write endpoints require Ed25519 signature from a registered `did:sigil:` key
- Regex inputs validated to compile before storage; ReDoS detection planned for v0.2

---

## [0.1.1] — 2026-02-12

### Added

- `Scanner` — local pattern set, in-process scan and redact
- `ScanPattern`, `ScanHit`, `Severity` types
- `sigil-protocol.org` homepage and `registry.html` API documentation

---

## [0.1.0] — 2026-02-10

### Added

- Initial release of `sigil-protocol` Rust crate
- SIGIL specification documents: SIGIL-Core, SIGIL-Guard, SIGIL-MCP, SIGIL-Vault, SIGIL-Audit (v0.1 drafts)
- Basic scanner with built-in patterns: AWS/GCP/Azure keys, GitHub tokens, JWT, generic secrets
- EUPL-1.2 + commercial dual licence

[Unreleased]: https://github.com/sigil-eu/sigil/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/sigil-eu/sigil/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/sigil-eu/sigil/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/sigil-eu/sigil/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/sigil-eu/sigil/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sigil-eu/sigil/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sigil-eu/sigil/releases/tag/v0.1.0
