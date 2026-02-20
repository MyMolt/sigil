# SIGIL Protocol Specification

## 1. Overview

**SIGIL** — Sovereign Identity-Gated Interaction Layer

### 1.1 Purpose

SIGIL is an open protocol for securing agent-to-tool interactions. As AI agents gain the ability to execute real-world actions (reading files, querying databases, sending emails), a standardized security layer becomes essential.

SIGIL provides a framework for:

1. **Identity** — Binding users to verifiable trust levels
2. **Interception** — Detecting and vaulting sensitive data before it enters agent context
3. **Audit** — Tamper-evident logging of all security-relevant events
4. **Policy** — Gating actions by risk level, rate, and required authorization

SIGIL does NOT prescribe:

- Which patterns are "sensitive" (implementation-specific)
- Which encryption algorithm to use (implementation-specific)
- Which identity providers to support (implementation-specific)

### 1.2 Design Principles

| Principle | Description |
|-----------|-------------|
| **Framework, not Policy** | Define *how* to scan, vault, audit — not *what* to scan |
| **Zero-Trust by Default** | Deny unless explicitly allowed |
| **Local-First** | Sensitive data never leaves the local enclave without cryptographic proof |
| **Composable** | Each component (scanner, vault, audit, policy) can be replaced independently |
| **MCP-Native** | First-class integration with the Model Context Protocol |

### 1.3 Architecture

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

### 1.4 Conformance Levels

| Level | Requirements | Use Case |
|-------|-------------|----------|
| **SIGIL-Core** | Identity + Audit | Minimum — who did what, when |
| **SIGIL-Guard** | Core + Scanner + Vault | Full interception — sensitive data never leaks |
| **SIGIL-MCP** | Guard + MCP bridge | Agent tool security — every tool call is gated |

### 1.5 Integration Examples

SIGIL is designed to integrate with any agent framework or platform:

- **MCP Hosts** (Claude Desktop, Cursor) — Add SIGIL envelope to tool calls
- **Agent Frameworks** (LangChain, LlamaIndex) — Wrap tool executors with SIGIL gate
- **Enterprise Systems** — Enforce LDAP/eIDAS identity before sensitive operations
- **Banking / Healthcare** — Domain-specific SensitivityScanner for PII, PHI, financial data
- **Self-hosted AI** (Ollama, vLLM) — Add audit trails to local LLM tool usage

### 1.6 Rust Crate

```toml
[dependencies]
sigil = "0.1"
```

```rust
use sigil::{SensitivityScanner, VaultProvider, AuditLogger, IdentityProvider, SecurityPolicy};
```
