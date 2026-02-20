# 5. MCP Extension

SIGIL extends the Model Context Protocol (MCP) with identity-bound security.

## 5.1 The Problem

Standard MCP provides no:

- Identity verification for tool calls
- Content scanning for tool results
- Tamper-evident audit trail
- Rate limiting or permission gating

SIGIL-MCP solves this by wrapping MCP with the SIGIL envelope.

## 5.2 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Host (e.g., MyMolt)               │
│                                                          │
│  LLM ──→ Tool Call Request                               │
│              │                                           │
│              ▼                                           │
│  ┌───────────────────────────────┐                       │
│  │      SIGIL Gate (Inbound)     │                       │
│  │  1. Identity check            │                       │
│  │  2. Policy check              │                       │
│  │  3. Audit log                 │                       │
│  └──────────────┬────────────────┘                       │
│                 │ ALLOW                                   │
│                 ▼                                         │
│          MCP Server (child process)                       │
│                 │                                         │
│                 ▼                                         │
│  ┌───────────────────────────────┐                       │
│  │      SIGIL Gate (Outbound)    │                       │
│  │  1. Sensitivity scan          │                       │
│  │  2. Vault interception        │                       │
│  │  3. Audit log                 │                       │
│  └──────────────┬────────────────┘                       │
│                 │                                         │
│                 ▼                                         │
│  LLM ←── Sanitized Tool Result                           │
└─────────────────────────────────────────────────────────┘
```

## 5.3 SIGIL-MCP Headers

SIGIL adds metadata to MCP JSON-RPC messages:

### Request (Inbound Gate)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_email",
    "arguments": { "query": "last 5 emails" }
  },
  "id": 1,
  "_sigil": {
    "identity": "eidas:DE/123456789",
    "trust_level": "High",
    "policy_approved": true,
    "audit_id": "550e8400-e29b-41d4-a716-446655440000",
    "signature": "hmac-sha256:..."
  }
}
```

### Response (Outbound Gate)

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Email from bank: [SIGIL-VAULT: IBAN — Access Required]"
      }
    ]
  },
  "id": 1,
  "_sigil": {
    "scanned": true,
    "interceptions": 1,
    "audit_id": "661f9511-f30c-52e5-b827-557766551111"
  }
}
```

## 5.4 `_sigil` Object Fields

### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity` | string | Yes | `{provider}:{id}` of the requesting user |
| `trust_level` | string | Yes | `Low` or `High` |
| `policy_approved` | bool | Yes | Whether SecurityPolicy allowed this call |
| `audit_id` | string | Yes | UUID linking to the AuditEvent |
| `signature` | string | No | HMAC signature of the request |

### Response Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scanned` | bool | Yes | Whether the response was scanned |
| `interceptions` | int | Yes | Number of sensitive items vaulted |
| `audit_id` | string | Yes | UUID linking to the AuditEvent |

## 5.5 MCP Server Trust Requirements

SIGIL-MCP servers MAY declare a minimum trust level:

```json
{
  "name": "banking-tools",
  "sigil_trust_required": "High",
  "description": "Banking operations requiring eIDAS verification"
}
```

The SIGIL gate MUST deny tool calls when `IdentityProvider.max_trust_level() < sigil_trust_required`.

## 5.6 Process Lifecycle

MCP servers run as child processes. SIGIL requires:

1. **Supervised execution** — MCP server processes MUST be monitored
2. **Clean shutdown** — On host termination, all child processes MUST be killed
3. **Resource isolation** — MCP servers SHOULD NOT share memory with the host
4. **Audit on lifecycle events** — Start, stop, and crash events MUST be logged

## 5.7 Compatibility

SIGIL-MCP is backward-compatible with standard MCP:

- The `_sigil` field is ignored by non-SIGIL MCP servers
- Non-SIGIL responses are scanned by the outbound gate anyway
- SIGIL adds security ON TOP of MCP, never restricts MCP capabilities
