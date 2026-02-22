---
name: sigil
description: >
  SIGIL (Sovereign Identity-Gated Interaction Layer) — the security layer for
  MCP tool calls. Use when you want to scan tool arguments or responses for
  leaked secrets (API keys, credentials, PII), enforce policy rules before a
  tool call executes, or write tamper-evident audit logs of every action.
  Provides RemoteScanner (43 verified patterns, auto-updated from the public
  registry), NullPolicyEnforcer, and FileAuditLogger. All scanning is done
  locally on your machine — no data leaves the agent. Compatible with any MCP
  server backend.
metadata:
  {
    "clawdbot":
      {
        "emoji": "🔐",
        "homepage": "https://sigil-protocol.org",
        "requires": { "bins": ["sigil-scan"] },
      },
  }
---

# SIGIL — Security Layer for MCP Tool Calls

SIGIL wraps MCP tool calls to catch leaked secrets, enforce policies, and
produce a local audit trail — before any data reaches a tool backend.

## What SIGIL Provides

| Layer | What it does |
|---|---|
| **Scanner** | Regex + entropy scan of tool args/responses against 43 verified patterns |
| **Policy** | Block or warn based on risk level and caller trust |
| **Audit** | Append-only JSONL log of every intercepted call |

## Quick Start

### 1. Install the `sigil-scan` CLI

```bash
cargo install sigil-protocol --features=cli
# or download a pre-built binary:
curl -fsSL https://sigil-protocol.org/install.sh | sh
```

### 2. Wrap a tool call

```bash
# Scan tool arguments before calling any MCP backend
sigil-scan check \
  --pattern-source registry \
  '{"tool":"execute_sql","args":{"q":"DROP TABLE users"}}'
# → BLOCKED: policy:execute_sql — risk level: Critical

# Scan a tool response for leaked secrets
sigil-scan check \
  --pattern-source registry \
  '{"AKIAIOSFODNN7EXAMPLE": true}'
# → HIT: aws_access_key_id (Critical)
```

### 3. Tail the audit log

```bash
tail -f ~/.sigil/audit.jsonl | jq .
# → {"ts":"2026-02-22T04:00:00Z","event":"SigilInterception",
#    "actor":"claw","tool":"execute_sql","severity":"Critical",
#    "blocked":true}
```

## Using SIGIL in an OpenClaw Workflow

SIGIL runs as a local scan step. Route tool arguments through it before
submitting to `mcporter`:

```
[LLM decides to call tool] → [SIGIL scans args] → [mcporter calls backend]
                                     ↓
                              [Audit log written]
                              [Policy violations blocked]
```

In your OpenClaw agent prompt or workflow, instruct the Claw to:
> "Before calling any tool, pipe the tool arguments through
> `sigil-scan check --pattern-source registry '<args_json>'`.
> If the output contains `BLOCKED` or `HIT`, do not proceed with the call
> and report the security finding to the user."

## CLI Reference

```
sigil-scan check [OPTIONS] <JSON>
  --pattern-source  registry | local | <path/to/bundle.json>
  --severity        warn | block (default: block for Critical, warn for High)
  --log             path to audit JSONL file (default: ~/.sigil/audit.jsonl)
  --format          text | json (default: text)

sigil-scan patterns list
  List all active patterns from the registry

sigil-scan patterns update
  Force-fetch latest pattern bundle from registry.sigil-protocol.org
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SIGIL_REGISTRY_URL` | `https://registry.sigil-protocol.org` | Pattern registry endpoint |
| `SIGIL_AUDIT_LOG` | `~/.sigil/audit.jsonl` | Audit log path |
| `SIGIL_OFFLINE` | `false` | Use bundled patterns only |
| `SIGIL_MIN_SEVERITY` | `High` | Minimum severity to flag |

## Pattern Categories

SIGIL ships 43 verified patterns across:

- **Credentials**: AWS, GCP, Azure, GitHub, npm, Stripe, Twilio, SendGrid…
- **PII**: Email, phone, IBAN, SSN, EU personal ID formats
- **Keys**: RSA/EC private keys, SSH keys, JWT secrets
- **Dangerous SQL**: DROP, TRUNCATE, DELETE with no WHERE clause
- **Prompt injection**: Known bypass patterns for LLM safety filters

See the full list at [registry.sigil-protocol.org](https://registry.sigil-protocol.org).

## Rust SDK (for skill/tool authors)

If you are building an MCP server or OpenClaw skill in Rust:

```rust
// Cargo.toml
// sigil-protocol = "0.1"

use sigil_protocol::{RemoteScanner, NullAuditLogger, SensitivityScanner};
use std::sync::Arc;

let scanner = Arc::new(RemoteScanner::from_registry().await?);
let hits = scanner.scan(&tool_args_json)?;
for hit in &hits {
    eprintln!("🔐 SIGIL: {} — {:?}", hit.pattern_name, hit.severity);
}
```

## Links

- 🌐 Homepage: [sigil-protocol.org](https://sigil-protocol.org)
- 📦 Rust crate: [crates.io/crates/sigil-protocol](https://crates.io/crates/sigil-protocol)
- 📄 Spec: [github.com/sigil-eu/sigil](https://github.com/sigil-eu/sigil)
- 🗂 Registry: [registry.sigil-protocol.org](https://registry.sigil-protocol.org)
- 💬 Issues / Discussion: [github.com/sigil-eu/sigil/discussions](https://github.com/sigil-eu/sigil/discussions)
