# SIGIL — Sovereign Identity-Gated Interaction Layer

An open protocol for securing AI agent-to-tool interactions with identity binding, content interception, and tamper-evident audit trails.

## Why SIGIL?

AI agents increasingly execute real-world actions — reading emails, accessing databases, managing files. Standard protocols like MCP provide no built-in security layer for these interactions. SIGIL fills this gap.

## What SIGIL Provides

| Component | Purpose |
|-----------|---------|
| **Identity** | Bind users to verifiable trust levels (OIDC, eIDAS, SSI) |
| **Scanner** | Detect sensitive content before it enters agent context |
| **Vault** | Encrypt and store intercepted secrets with opaque pointers |
| **Audit** | Tamper-evident logging of all security events |
| **Policy** | Gate actions by risk level, rate, and authorization |
| **MCP Bridge** | Extend Model Context Protocol with SIGIL security envelope |

## Quick Start

```toml
[dependencies]
sigil = "0.1"
```

```rust
use sigil::{SensitivityScanner, VaultProvider, AuditLogger, IdentityProvider, SecurityPolicy};

// Implement these traits with your own backends
struct MyScanner;
impl SensitivityScanner for MyScanner {
    fn scan(&self, text: &str) -> Option<String> {
        // Your detection logic here
        None
    }
}
```

## Adoption Examples

SIGIL is designed to integrate with any agent framework:

| Platform | How SIGIL Helps |
|----------|----------------|
| **MCP Hosts** (Claude Desktop, Cursor, etc.) | Add `_sigil` envelope to tool calls for identity-gated, audited execution |
| **LangChain / LlamaIndex** | Wrap tool executors with SIGIL scanner + policy gate |
| **Enterprise Agents** | Enforce eIDAS/LDAP identity verification before sensitive operations |
| **Banking / Healthcare** | Define domain-specific `SensitivityScanner` for PII, PHI, financial data |
| **Self-hosted AI** (Ollama, vLLM) | Add SIGIL audit trail to local LLM tool usage |
| **MyMolt** | Reference implementation with full SIGIL stack |

## Conformance Levels

| Level | Requirements | Use Case |
|-------|-------------|----------|
| **SIGIL-Core** | Identity + Audit | Minimum conformance — who did what, when |
| **SIGIL-Guard** | Core + Scanner + Vault | Full interception — sensitive data never leaks |
| **SIGIL-MCP** | Guard + MCP bridge | Agent tool security — every tool call is gated |

## Specification

1. [Overview](spec/01-overview.md) — Purpose, architecture, conformance levels
2. [Identity](spec/02-identity.md) — TrustLevel, IdentityBinding, trust gating
3. [Interception](spec/03-interception.md) — Scanner, vault envelope, opaque pointers
4. [Audit](spec/04-audit.md) — Event schema, tamper evidence
5. [MCP Extension](spec/05-mcp-extension.md) — SIGIL as MCP security wrapper

## License

EUPL-1.2 — [European Union Public Licence v. 1.2](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12)
