# sigil-zeroclaw

> 🔐 SIGIL security layer plugin for [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) — scans MCP tool calls for leaked secrets, blocks dangerous operations, and writes a tamper-evident audit log.

## Install

```toml
# Cargo.toml
[dependencies]
sigil-zeroclaw = "0.1"
```

## Three ways to use it

### 1. `SigilScanTool` — let the LLM call it explicitly

Register as a ZeroClaw tool. The LLM will call `sigil_scan` before passing sensitive data to any backend.

```rust
use sigil_zeroclaw::SigilScanTool;

let scan_tool = SigilScanTool::from_registry_with_audit("~/.sigil/audit.jsonl").await?;

// agent.add_tool(scan_tool);
```

The LLM receives this description and calls the tool automatically when it decides to pass credentials, PII, or sensitive SQL anywhere:
> *"Scans a JSON payload for leaked secrets... If any findings have severity 'Critical', you MUST NOT proceed with the tool call."*

### 2. `SigilGateTool` — wrap any existing tool

Transparently wraps another tool. Blocks the call silently if SIGIL detects a Critical hit. Zero changes to the wrapped tool.

```rust
use sigil_zeroclaw::{SigilGateTool, MyDatabaseTool};

let db = MyDatabaseTool::new(connection_string);
let secure_db = SigilGateTool::wrap(db, Some("~/.sigil/audit.jsonl".as_ref())).await?;

// agent.add_tool(secure_db); // same interface, SIGIL-gated
```

### 3. `SigilObservability` — automatic audit on every turn

Hooks into every agent turn and tool call without any per-tool setup. Also scans tool *responses* for accidental credential leaks from backends.

```rust
use sigil_zeroclaw::SigilObservability;

let obs = SigilObservability::with_remote_scanner("~/.sigil/audit.jsonl").await?;

// agent.set_observability(obs);
```

## Audit log

Every intercepted call is written as a JSONL line to your audit file:

```jsonl
{"ts":"2026-02-22T05:00:00Z","event":"SigilInterception","actor":"zeroclaw/execute_sql","pattern_name":"sql_drop_table","severity":"Critical","blocked":true}
{"ts":"2026-02-22T05:00:01Z","event":"SigilInterception","actor":"zeroclaw/send_email/response","pattern_name":"aws_access_key_id","severity":"Critical","blocked":false}
```

```bash
# Tail live audit
tail -f ~/.sigil/audit.jsonl | jq .

# Filter blocked calls only
jq 'select(.blocked == true)' ~/.sigil/audit.jsonl
```

## Pattern coverage

43 verified patterns fetched from [registry.sigil-protocol.org](https://registry.sigil-protocol.org):

| Category | Examples |
|---|---|
| Cloud credentials | AWS, GCP, Azure, OpenAI, GitHub, npm, Stripe |
| Cryptographic keys | RSA/EC private keys, SSH keys, JWT secrets |
| PII (EU GDPR) | IBAN, phone, email, SSN |
| Dangerous SQL | DROP TABLE, DELETE without WHERE, TRUNCATE |
| Prompt injection | Jailbreak openers, system prompt leaks |

## Architecture note

This crate includes stub definitions of the ZeroClaw `Tool` and `Observability` traits so it compiles before the upstream `zeroclaw` crate is published. When the crate is available, replace the stubs with the upstream types using the `zeroclaw-native` feature flag:

```toml
sigil-zeroclaw = { version = "0.1", features = ["zeroclaw-native"] }
```

## Links

- 🌐 [sigil-protocol.org](https://sigil-protocol.org)
- 📦 [crates.io/crates/sigil-protocol](https://crates.io/crates/sigil-protocol)
- 🗂 [registry.sigil-protocol.org](https://registry.sigil-protocol.org)
- 📄 [Protocol Spec](https://github.com/sigil-eu/sigil)
