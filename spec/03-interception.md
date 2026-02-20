# 3. Interception

The SIGIL interception pipeline detects sensitive content and vaults it before it enters agent context.

## 3.1 Pipeline

```
Input Text → SensitivityScanner → Detected?
                                    │
                    ┌───────────────┴───────────────┐
                    ▼ No                            ▼ Yes
              Pass through                    VaultProvider.encrypt()
                                                    │
                                              Store VaultEntry
                                                    │
                                              Replace with Opaque Pointer
                                                    │
                                              AuditLogger.log(SigilInterception)
```

## 3.2 SensitivityScanner

```rust
pub trait SensitivityScanner: Send + Sync {
    fn scan(&self, text: &str) -> Option<String>;
}
```

### Return Value

- `None` — text is safe, pass through unchanged
- `Some(category)` — sensitive content detected; `category` is a human-readable label (e.g., `"IBAN"`, `"API Key"`)

### Requirements

1. Scanners MUST be stateless (no side effects from scanning)
2. Scanners MUST be thread-safe (`Send + Sync`)
3. The category string MUST be suitable for audit logs and vault metadata
4. Scanners SHOULD process text in under 1ms for interactive use

### Non-Requirements

The protocol does NOT specify:

- What patterns to detect (implementation-specific)
- Detection method (regex, ML, dictionary — all valid)
- False positive handling (implementation policy)

## 3.3 Vault Envelope

### VaultEntry

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "ciphertext": "<base64-encoded bytes>",
  "description": "Vaulted IBAN from user message",
  "created_at": "2026-02-20T12:00:00Z",
  "tags": ["iban", "vault"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID v4, unique per entry |
| `ciphertext` | bytes | Encrypted payload (format is provider-specific) |
| `description` | string | Human-readable context for audit trail |
| `created_at` | string | ISO 8601 timestamp |
| `tags` | string[] | Categorization labels |

### VaultProvider Trait

```rust
pub trait VaultProvider: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], description: &str) -> Result<VaultEntry>;
    fn decrypt(&self, id: &str) -> Result<Vec<u8>>;
    fn exists(&self, id: &str) -> bool;
}
```

### Encryption Requirements

1. At-rest encryption MUST be used (plaintext MUST NOT be written to disk)
2. After encryption, the plaintext buffer SHOULD be zeroed in memory
3. The ciphertext format is provider-specific (RSA, AES-GCM, HSM, etc.)
4. Decryption MUST require authentication (key, HSM token, etc.)

## 3.4 Opaque Pointers

When content is vaulted, the original text is replaced with an opaque pointer:

```
[SIGIL-VAULT: {category} — Access Required]
```

Example:

```
Original:  "My IBAN is DE89 3704 0044 0532 0130 00"
Stored:    "[SIGIL-VAULT: IBAN — Access Required]"
```

The pointer format is standardized so SIGIL-aware systems can recognize vaulted content across implementations.
