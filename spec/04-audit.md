# 4. Audit

SIGIL audit provides tamper-evident logging of all security-relevant events.

## 4.1 Event Schema

Every SIGIL event conforms to this schema:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-20T12:00:00.000Z",
  "event_type": "sigil_interception",
  "actor": {
    "channel": "cli",
    "user_id": "user@example.com",
    "username": "Alice"
  },
  "action": {
    "description": "Redacted IBAN from user message",
    "risk_level": "high",
    "approved": true,
    "allowed": true
  },
  "result": {
    "success": true,
    "exit_code": null,
    "duration_ms": 12,
    "error": null
  },
  "signature": "hmac-sha256:abc123..."
}
```

## 4.2 Event Types

| Type | When Logged |
|------|------------|
| `command_execution` | Agent executes a tool or shell command |
| `file_access` | File read/write operation |
| `config_change` | Security configuration modified |
| `auth_success` | Identity verification succeeded |
| `auth_failure` | Identity verification failed |
| `policy_violation` | Action denied by SecurityPolicy |
| `security_event` | General security event |
| `sigil_interception` | SensitivityScanner detected and vaulted content |
| `mcp_tool_gated` | MCP tool call passed through SIGIL gate |

## 4.3 AuditLogger Trait

```rust
pub trait AuditLogger: Send + Sync {
    fn log(&self, event: &AuditEvent) -> Result<()>;
}
```

### Requirements

1. Events MUST be persisted durably (survive process crashes)
2. Events MUST include a unique `id` (UUID v4) and ISO 8601 `timestamp`
3. Events SHOULD be append-only (no modification or deletion)
4. Events SHOULD be serialized as JSON (one event per line)

## 4.4 Tamper Evidence

SIGIL recommends (but does not require) HMAC signing for tamper evidence:

```
signature = HMAC-SHA256(key, event_json_without_signature)
```

When `signature` is present:

- Verifiers MUST check the HMAC before trusting the event
- A failed HMAC check indicates the event was tampered with
- The HMAC key SHOULD be derived from the identity provider's credentials

## 4.5 Log Rotation

Implementations SHOULD support log rotation:

- Rotate when log exceeds a configurable size limit
- Rotated logs MUST preserve HMAC signatures
- Rotation MUST be atomic (no events lost during rotation)
