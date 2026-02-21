<p align="center">
  <strong>🔐 SIGIL</strong>
</p>

<h3 align="center">Sovereign Identity-Gated Interaction Layer</h3>
<p align="center">The missing security layer for AI agent-to-tool interactions.</p>

<p align="center">
  <a href="https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12"><img src="https://img.shields.io/badge/license-EUPL%20v1.2-blue.svg" alt="License EUPL-1.2"></a>
  <a href="https://github.com/sigil-eu/sigil/blob/main/LICENSE-COMMERCIAL"><img src="https://img.shields.io/badge/license-Commercial-orange.svg" alt="Commercial License"></a>
  <a href="https://github.com/sigil-eu/sigil/actions"><img src="https://github.com/sigil-eu/sigil/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/sigil-protocol"><img src="https://img.shields.io/crates/v/sigil-protocol.svg" alt="crates.io"></a>
  <a href="https://docs.rs/sigil-protocol"><img src="https://docs.rs/sigil-protocol/badge.svg" alt="docs.rs"></a>
</p>

---

## The Problem

AI agents execute real-world actions — reading emails, querying databases, sending money. The dominant protocol for this (MCP) has **no built-in security layer**:

- ❌ No identity verification for tool calls
- ❌ No content scanning for sensitive data
- ❌ No audit trail
- ❌ No permission gating

**SIGIL fills this gap.**

## What SIGIL Provides

SIGIL defines 5 traits (interfaces) that any agent system can implement:

```
┌─────────────────────────────────────────────────────┐
│                   SIGIL Envelope                     │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ Identity │  │ Scanner  │  │  Policy  │          │
│  │ Provider │  │          │  │          │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│       │              │              │                │
│       ▼              ▼              ▼                │
│  ┌──────────────────────────────────────────┐       │
│  │              Audit Logger                 │       │
│  └──────────────────────────────────────────┘       │
│                      │                               │
│                      ▼                               │
│  ┌──────────────────────────────────────────┐       │
│  │           Vault Provider                  │       │
│  └──────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────┘
```

| Trait | Purpose |
| --- | --- |
| `IdentityProvider` | Bind users to verifiable trust levels (OIDC, eIDAS, SSI) |
| `SensitivityScanner` | Detect secrets, PII, financial data before they reach the LLM |
| `VaultProvider` | Encrypt and store intercepted sensitive content |
| `AuditLogger` | Tamper-evident logging of every security event |
| `SecurityPolicy` | Gate actions by risk level, rate, and authorization |

Plus a **reference MCP server** (`SigilMcpServer`) that wraps any tool set with all five layers.

## Quick Start

```toml
[dependencies]
sigil-protocol = "0.1"
```

### Implement a Scanner

```rust
use sigil_protocol::SensitivityScanner;

struct MyScanner;

impl SensitivityScanner for MyScanner {
    fn scan(&self, text: &str) -> Option<String> {
        if text.contains("sk-") {
            Some("API Key".into())
        } else {
            None
        }
    }
}
```

### Secure an MCP Server (4 lines)

```rust
use sigil_protocol::mcp_server::{SigilMcpServer, ToolDef};
use std::sync::Arc;

let scanner = Arc::new(MyScanner);
let audit = Arc::new(MyAuditLogger::new());
let mut server = SigilMcpServer::new("my-tools", "1.0", scanner, audit);

server.register_tool(ToolDef {
    name: "read_email".into(),
    description: "Read user emails".into(),
    parameters_schema: serde_json::json!({"type": "object"}),
    handler: Box::new(|args| Box::pin(async move {
        // Your tool logic — SIGIL scans input AND output automatically
        Ok(serde_json::json!({"emails": []}))
    })),
});

// Every tool call is now identity-gated, scanned, and audited
let response = server.handle_request(json_rpc_request, caller_trust).await;
```

### Trust-Gate Sensitive Tools

```rust
use sigil_protocol::TrustLevel;

// This tool requires eIDAS-verified identity
server.register_tool_with_trust(banking_tool, TrustLevel::High);

// Low-trust caller tries to use it → DENIED + audit logged
```

## MCP Extension

SIGIL extends MCP JSON-RPC with a `_sigil` metadata field:

```json
{
  "method": "tools/call",
  "params": { "name": "read_email", "arguments": {} },
  "_sigil": {
    "identity": "eidas:DE/123456789",
    "trust_level": "High",
    "policy_approved": true,
    "audit_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

Responses are scanned automatically:

```json
{
  "result": {
    "content": [{ "text": "Email from bank: [SIGIL-VAULT: IBAN — Access Required]" }]
  },
  "_sigil": { "scanned": true, "interceptions": 1 }
}
```

## Conformance Levels

| Level | Requirements | Use Case |
| --- | --- | --- |
| **SIGIL-Core** | Identity + Audit | Minimum — who did what, when |
| **SIGIL-Guard** | Core + Scanner + Vault | Full interception — sensitive data never leaks |
| **SIGIL-MCP** | Guard + MCP Server | Agent tool security — every tool call is gated |

## Adoption

SIGIL integrates with any agent framework:

| Platform | Integration |
| --- | --- |
| **MCP Hosts** (Claude Desktop, Cursor) | Add `_sigil` envelope to tool calls |
| **LangChain / LlamaIndex** | Wrap tool executors with SIGIL policy gate |
| **Enterprise agents** | Enforce eIDAS/LDAP identity before sensitive operations |
| **Banking / Healthcare** | Domain-specific `SensitivityScanner` for PII, PHI |
| **Self-hosted AI** (Ollama, vLLM) | Add audit trails to local LLM tool usage |
| **[MyMolt](https://github.com/beykuet/MyMolt)** | Reference implementation (SIGIL-MCP conformant) |

## Specification

1. [Overview](spec/01-overview.md) — Purpose, architecture, conformance levels
2. [Identity](spec/02-identity.md) — TrustLevel, IdentityBinding, trust gating
3. [Interception](spec/03-interception.md) — Scanner, vault envelope, opaque pointers
4. [Audit](spec/04-audit.md) — Event schema, tamper evidence
5. [MCP Extension](spec/05-mcp-extension.md) — SIGIL as MCP security wrapper
6. [Security Handshake](spec/06-handshake.md) — MCP initialization trust negotiation
7. [Registry](spec/07-registry.md) — Distributed Scanners and Policies ecosystem

## License

SIGIL Protocol is **dual-licensed**:

- **Open Source (EUPL-1.2):** Free for open-source projects and personal use.
  See [`LICENSE`](./LICENSE).
- **Commercial:** Required for proprietary or closed-source applications.
  See [`LICENSE-COMMERCIAL`](./LICENSE-COMMERCIAL) or contact
  [info@sigil-protocol.org](mailto:info@sigil-protocol.org).

> **Note:** Using SIGIL as a library dependency in a proprietary project
> does NOT automatically require a commercial licence, provided you do not
> modify and redistribute SIGIL itself in closed-source form.
