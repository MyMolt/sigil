# 2. Identity

The SIGIL identity model binds users to trust levels through verified identity providers.

## 2.1 Trust Levels

SIGIL defines two trust tiers for inter-system compatibility:

| Level | Value | Verification | Examples |
|-------|-------|-------------|----------|
| **Low** | 1 | Basic verification | Email/OIDC (Google, Apple), social login |
| **High** | 3 | Strong verification | eIDAS, government ID, hardware key, DID |

Implementations MAY define additional internal granularity but MUST map to these two tiers when communicating with other SIGIL systems.

## 2.2 Identity Binding

An identity binding records the association between a user and an identity provider:

```json
{
  "provider": "eidas",
  "id": "DE/123456789",
  "trust_level": "High",
  "bound_at": "2026-02-20T12:00:00Z"
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Identity provider name (lowercase, no spaces) |
| `id` | string | Provider-specific user identifier |
| `trust_level` | enum | `Low` or `High` |
| `bound_at` | string | ISO 8601 timestamp |

### Provider Naming Convention

| Provider | `provider` value |
|----------|-----------------|
| Google OIDC | `google` |
| Apple Sign-In | `apple` |
| eIDAS | `eidas` |
| DID:key | `did:key` |
| DID:web | `did:web` |
| Internal system | `{system-name}` (e.g., `hoodik`) |

## 2.3 IdentityProvider Trait

```rust
pub trait IdentityProvider: Send + Sync {
    fn bindings(&self) -> Vec<IdentityBinding>;
    fn add_binding(&mut self, provider: &str, id: &str, level: TrustLevel) -> Result<()>;
    fn max_trust_level(&self) -> TrustLevel;
    fn has_binding(&self, provider: &str) -> bool;
}
```

### Behavioral Requirements

1. **Duplicate prevention**: Adding an identical `(provider, id)` pair MUST be a no-op
2. **Persistence**: Bindings MUST survive process restarts
3. **Max trust**: `max_trust_level()` returns the highest trust level across all bindings
4. **Provider lookup**: `has_binding()` checks if ANY binding exists for the provider

## 2.4 Trust Gating

SIGIL components MAY require a minimum trust level for operations:

```
Operation requires TrustLevel::High
  → Check IdentityProvider.max_trust_level()
  → If < High → DENY + log AuditEvent(PolicyViolation)
  → If >= High → ALLOW + log AuditEvent(AuthSuccess)
```

This enables scenarios like:

- MCP servers requiring eIDAS verification for financial data
- Vault decryption requiring hardware key authentication
- Administrative operations restricting to High-trust identities
