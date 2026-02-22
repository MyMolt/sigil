# sigil — OpenClaw Skill

> 🔐 **SIGIL** (Sovereign Identity-Gated Interaction Layer) — adds secret
> scanning, policy enforcement, and audit logging to any MCP tool call.

## Install in OpenClaw

Give OpenClaw this URL:

```
https://github.com/sigil-eu/sigil/tree/main/openclaw-skill
```

Or install the CLI directly:

```bash
bash <(curl -fsSL https://sigil-protocol.org/install.sh)
```

## What it does

- **Scans** tool arguments and responses for 43 classes of leaked secrets
  (AWS keys, GCP credentials, private RSA/SSH keys, IBANs…) before they
  reach any backend
- **Blocks** tool calls that match a Critical-severity policy (e.g.
  `DROP TABLE`, `DELETE` without `WHERE`)
- **Logs** every intercepted call to a local append-only JSONL audit file

## Quick test

```bash
sigil-scan check '{"q":"DROP TABLE users"}'
# → BLOCKED: dangerous_sql:sql_drop_table — severity: Critical

sigil-scan check '{"key":"AKIAIOSFODNN7EXAMPLE"}'
# → HIT: credential:aws_access_key_id — severity: Critical
```

## Links

- [sigil-protocol.org](https://sigil-protocol.org) — homepage & quick-start
- [registry.sigil-protocol.org](https://registry.sigil-protocol.org) — live
  pattern & policy registry (43 patterns, 35 policies)
- [github.com/sigil-eu/sigil](https://github.com/sigil-eu/sigil) — source,
  spec, discussions
- [crates.io/crates/sigil-protocol](https://crates.io/crates/sigil-protocol)
  — Rust SDK
