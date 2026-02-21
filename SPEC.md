# SIGIL Protocol — Formal Technical Specification

**Version:** 1.0.0-draft
**Date:** 2026-02-21
**Status:** Public Disclosure Draft (Prior Art)
**Authors:** SIGIL Protocol — sigil-protocol.org
**Licence:** EUPL-1.2 + Commercial (see LICENSE-COMMERCIAL)

---

## Abstract

SIGIL (Sovereign Identity-Gated Interaction Layer) is an open protocol that adds a
cryptographically verifiable, per-message security envelope to the Model Context
Protocol (MCP) JSON-RPC 2.0 message stream. Each individual tool call carries an
embedded `_sigil` object containing a Decentralised Identifier (DID) as the caller's
identity, a real-time policy verdict from a gateway engine, and an Ed25519 digital
signature over a canonical form of the request.

This document is a formal technical specification intended to serve as a precise,
unambiguous reference for implementors, auditors, and patent practitioners.

---

## 1. Problem Statement

The Model Context Protocol (MCP), as defined by the MCP specification (versions up to
and including 2025-06-18), provides no mechanism by which:

1. The identity of the AI agent issuing a tool call is cryptographically asserted
   within the tool call's payload.
2. A security policy decision (allow / block / scan) is communicated as a first-class
   field attached to the individual JSON-RPC message.
3. The combination of caller identity, policy verdict, and message content is
   non-repudiably signed in a way that can be independently verified by a
   downstream recipient without access to a centralised authority.

Existing solutions (OAuth 2.0, OIDC, JWT session tokens) operate at the transport or
session layer. They prove who a session belongs to — they do not prove who signed
this individual message, nor embed the policy verdict inside the message itself.

SIGIL solves these three gaps simultaneously with a single extensible object.

---

## 2. Core Concepts

### 2.1 The `_sigil` Envelope

The `_sigil` envelope is a JSON object embedded as a reserved field within the `params`
object of a JSON-RPC 2.0 request. It is defined as follows:

```
_sigil := {
  identity   : DID,          // REQUIRED. Decentralised Identifier of the caller.
  verdict    : Verdict,      // REQUIRED. Real-time policy decision.
  timestamp  : ISO8601,      // REQUIRED. Signing time (UTC, millisecond precision).
  nonce      : HexString,    // REQUIRED. 16-byte cryptographically random value.
  signature  : Base64,       // REQUIRED. Ed25519 signature over the canonical form.
  reason     : string,       // OPTIONAL. Present when verdict = "blocked" or "scanned".
}
```

### 2.2 Decentralised Identifier (DID)

SIGIL uses DIDs as defined in the W3C Decentralised Identifiers specification
(W3C DID Core 1.0, 2022). The DID format used by SIGIL is:

```
did:sigil:{namespace}_{identifier}
```

Examples:

- `did:sigil:parent_01` — a parent agent in a household namespace
- `did:sigil:enterprise_gateway_prod` — an enterprise gateway

The DID resolves to a DID Document (via the SIGIL Registry, see §7) which contains:

- The agent's Ed25519 public key (in JWK or multibase format)
- Metadata: creation time, last-updated, status (active / revoked)

### 2.3 Policy Verdict

The `verdict` field encodes the real-time decision of the SIGIL gateway for this
specific tool call. It is an enumeration of exactly three values:

| Value | Meaning |
| --------- | ------------------------------------------------------- |
| `allowed` | The gateway verified the identity and permitted the call. |
| `blocked` | The gateway denied the call. `reason` MUST be present. |
| `scanned` | The call is permitted but the payload was inspected (e.g., for PII). `reason` SHOULD be present. |

No other values are valid. Implementations MUST reject envelopes with unknown verdicts.

### 2.4 Signing Algorithm

SIGIL mandates **Ed25519** (RFC 8032) for all signatures. Rationale:

- 64-byte compact signatures
- Fast constant-time verification
- Resistant to side-channel attacks
- No parameter choices that could be misconfigured (unlike ECDSA)

The signature is computed over the **canonical form** of the envelope (see §3).

---

## 3. Canonical Form and Signing Procedure

### 3.1 Canonical Form

To produce a deterministic byte string for signing, the `_sigil` object must be
serialised in canonical form before signing. The canonical form is defined as:

1. Start with an empty JSON object `{}`.
2. Insert the following fields **in lexicographic key order**:
   - `identity` (string)
   - `nonce` (string)
   - `timestamp` (string)
   - `verdict` (string)
3. Serialise to UTF-8 JSON with **no whitespace** (compact encoding).
4. The `signature` field is NOT included in the canonical form (it is the output).
5. The `reason` field is NOT included in the canonical form.

**Example canonical form:**

```json
{"identity":"did:sigil:parent_01","nonce":"a3f82c1d9b7e04f5","timestamp":"2026-02-21T17:54:44.123Z","verdict":"allowed"}
```

### 3.2 Signing Procedure

```
canonical_bytes := utf8(canonical_json(_sigil))
signature       := Ed25519Sign(private_key, canonical_bytes)
_sigil.signature := base64url_nopad(signature)
```

### 3.3 Verification Procedure

A receiver wishing to verify a `_sigil` envelope MUST:

1. Extract `identity` from the envelope.
2. Resolve the DID to its DID Document (via SIGIL Registry or local cache).
3. Extract the Ed25519 public key from the DID Document.
4. Reconstruct the canonical form from the received envelope (excluding `signature` and `reason`).
5. Decode `signature` from base64url.
6. Verify: `Ed25519Verify(public_key, canonical_bytes, signature)`.
7. If verification fails → reject the message and log an audit event.
8. Check `timestamp` is within an acceptable clock skew window (RECOMMENDED: ±30 seconds).
9. Check `nonce` has not been seen before within the clock skew window (replay prevention).

---

## 4. Wire Format

### 4.1 Placement in JSON-RPC 2.0

The `_sigil` object MUST be placed as a top-level field within the `params` object of
a JSON-RPC 2.0 request. It MUST NOT be placed at the root level of the JSON-RPC message.

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "tools/call",
  "params": {
    "name": "read_vault_file",
    "arguments": {
      "path": "/vault/budget_2025.xlsx"
    },
    "_sigil": {
      "identity": "did:sigil:parent_01",
      "verdict": "allowed",
      "timestamp": "2026-02-21T17:54:44.123Z",
      "nonce": "a3f82c1d9b7e04f5",
      "signature": "base64url-encoded-ed25519-signature"
    }
  }
}
```

### 4.2 Blocked Request Example

```json
{
  "jsonrpc": "2.0",
  "id": 99,
  "method": "tools/call",
  "params": {
    "name": "execute_shell",
    "arguments": { "cmd": "rm -rf /" },
    "_sigil": {
      "identity": "did:sigil:child_02",
      "verdict": "blocked",
      "timestamp": "2026-02-21T10:45:12.000Z",
      "nonce": "3b9ac2e1f8d070a4",
      "signature": "base64url-encoded-ed25519-signature",
      "reason": "Role 'child_02' lacks permission for destructive system tools."
    }
  }
}
```

### 4.3 Backward Compatibility

The `_sigil` field MUST be treated as an opaque extension by non-SIGIL-aware MCP servers.
The MCP specification (§5.7) states that unknown fields in `params` MUST be ignored.
A SIGIL envelope therefore adds zero-friction to existing MCP deployments.

---

## 5. Identity System

### 5.1 Trust Levels

SIGIL defines two interoperable trust tiers:

| Level | Verification Method | Examples |
| ----- | ------------------- | ------- |
| `Low` | Basic (email, OIDC) | Google, Apple Sign-In |
| `High` | Strong (cryptographic) | eIDAS, hardware key, DID |

### 5.2 Identity Binding Schema

```json
{
  "did": "did:sigil:parent_01",
  "provider": "eidas",
  "provider_id": "DE/123456789",
  "trust_level": "High",
  "bound_at": "2026-02-20T12:00:00Z",
  "public_key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "base64url-encoded-public-key"
  }
}
```

### 5.3 `IdentityProvider` Interface

```rust
pub trait IdentityProvider: Send + Sync {
    /// Returns all registered identity bindings for this agent.
    fn bindings(&self) -> Vec<IdentityBinding>;

    /// Registers a new identity binding.
    fn add_binding(&mut self, provider: &str, id: &str, level: TrustLevel) -> Result<()>;

    /// Returns the highest trust level across all bindings.
    fn max_trust_level(&self) -> TrustLevel;

    /// Returns true if any binding exists for the given provider.
    fn has_binding(&self, provider: &str) -> bool;

    /// Returns the Ed25519 signing key pair for this agent, if available.
    fn signing_keypair(&self) -> Option<Ed25519KeyPair>;
}
```

---

## 6. Security Policy Engine

### 6.1 Policy Evaluation

Before signing and attaching a `_sigil` envelope, the SIGIL gateway MUST evaluate the
request against the active `SecurityPolicy`. The evaluation produces exactly one verdict.

```
evaluate(request, identity) -> Verdict:
  if not identity.is_allowed_method(request.method):
    return Verdict::Blocked("Method not permitted for this role")
  if identity.trust_level < policy.required_trust(request.method):
    return Verdict::Blocked("Insufficient trust level")
  if policy.requires_scan(request.method):
    return Verdict::Scanned
  return Verdict::Allowed
```

### 6.2 `SecurityPolicy` Interface

```rust
pub trait SecurityPolicy: Send + Sync {
    /// Returns the verdict for a given request and identity binding.
    fn evaluate(&self, request: &JsonRpcRequest, identity: &IdentityBinding) -> Verdict;
}
```

### 6.3 Verdict State Machine

```
         ┌──────────────────┐
         │    Evaluating     │
         └────────┬─────────┘
                  │
      ┌───────────┼───────────┐
      ▼           ▼           ▼
  Allowed      Blocked     Scanned
      │           │           │
      │       (+ reason)  (+ reason)
      ▼           ▼           ▼
   Sign &       Sign &      Sign &
   Forward      Reject      Inspect
                           & Forward
```

---

## 7. SIGIL Registry

### 7.1 Purpose

The SIGIL Registry is a distributed service that resolves `did:sigil:` identifiers to
DID Documents. It provides the public key material required for signature verification
in §3.3.

### 7.2 Resolution Protocol

```
GET /resolve/{did}
```

Response:

```json
{
  "did": "did:sigil:parent_01",
  "status": "active",
  "public_key": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "base64url-encoded-32-byte-public-key"
  },
  "created_at": "2026-02-01T00:00:00Z",
  "updated_at": "2026-02-21T00:00:00Z"
}
```

### 7.3 Registry Requirements

1. Resolution MUST be available over HTTPS with TLS 1.3.
2. Responses MUST be cacheable (Cache-Control header MUST be present).
3. Revoked DIDs MUST return `"status": "revoked"` — verifiers MUST reject envelopes
   signed by revoked identities.
4. The registry itself SHOULD be distributed to avoid single points of failure.

---

## 8. Audit Trail

### 8.1 Audit Event Schema

Every SIGIL gate evaluation MUST produce a corresponding audit event:

```json
{
  "id": "uuid-v4",
  "timestamp": "ISO8601-milliseconds",
  "event_type": "mcp_tool_gated",
  "caller_did": "did:sigil:parent_01",
  "method": "tools/call",
  "tool_name": "read_vault_file",
  "verdict": "allowed",
  "reason": null,
  "nonce": "a3f82c1d9b7e04f5",
  "request_signature": "base64url-signature",
  "audit_signature": "ed25519-over-this-event"
}
```

### 8.2 Tamper Evidence

Each audit event is itself signed with the gateway's Ed25519 key (`audit_signature`).
This provides a chain of evidence: the agent signs the request, the gateway signs
the audit record of its policy decision.

### 8.3 Append-Only Requirement

Audit logs MUST be append-only. No deletion or modification of logged events is
permitted. Implementations SHOULD use an append-only data store (PostgreSQL with
row-level security, FoundationDB, or similar).

---

## 9. Sensitivity Scanner and Vault

### 9.1 Outbound Gate

After a tool call executes, the SIGIL outbound gate scans the tool's response for
sensitive content:

```
response_text → SensitivityScanner → detected?
                                         │
                   ┌─────────────────────┤
                   ▼ No                  ▼ Yes
             Pass through         VaultProvider.encrypt()
                                         │
                                    Replace with:
                               [SIGIL-VAULT: {category} — Access Required]
                                         │
                                    AuditLogger.log()
```

### 9.2 `SensitivityScanner` Interface

```rust
pub trait SensitivityScanner: Send + Sync {
    /// Returns Some(category) if sensitive content is detected, None otherwise.
    /// Must be stateless and complete in under 1ms for interactive use.
    fn scan(&self, text: &str) -> Option<String>;
}
```

### 9.3 Opaque Pointer Format

The standard replacement token is:

```
[SIGIL-VAULT: {category} — Access Required]
```

This format is standardised so any SIGIL-aware system can recognise vaulted content
across implementations without requiring knowledge of the vault's internals.

---

## 10. Conformance Levels

| Level | Required Components | Use Case |
| ----- | ------------------ | -------- |
| **SIGIL-Core** | Identity + Audit | Minimal — who did what, when |
| **SIGIL-Guard** | Core + Scanner + Vault | Full interception — no data leaks |
| **SIGIL-MCP** | Guard + MCP envelope + Ed25519 signing | Full agent tool security |
| **SIGIL-Registry** | SIGIL-MCP + Registry resolution | Production DID-based deployment |

---

## 11. Security Considerations

### 11.1 Replay Prevention

The `nonce` field (§2.1) combined with the `timestamp` field prevents replay attacks.
Implementations MUST maintain a short-lived nonce cache (TTL = 2× clock skew window)
to detect duplicate envelopes.

### 11.2 Clock Skew

SIGIL gateways SHOULD reject envelopes where `abs(now - timestamp) > 30 seconds`.

### 11.3 Key Rotation

DID Documents SHOULD include a key rotation mechanism. When a key is rotated, the old
key MUST remain in the DID Document with a `revoked_at` timestamp for a transition
period of at least 24 hours.

### 11.4 Private Key Storage

Agent private keys MUST be stored in a secure enclave, HSM, or OS keychain. Keys
MUST NOT be written in plaintext to disk or transmitted over the network.

---

## 12. Relation to Existing Standards

| Standard | Relation |
| -------- | -------- |
| MCP (Anthropic/AAIF) | SIGIL extends MCP at the message layer without modifying the transport |
| W3C DID Core 1.0 | SIGIL uses DIDs as identity primitives |
| RFC 8032 (Ed25519) | SIGIL mandates Ed25519 for all signatures |
| OAuth 2.0 / OIDC | SIGIL complements OAuth — session auth is compatible alongside per-message signing |
| eIDAS 2.0 | SIGIL's `High` trust level maps to eIDAS substantial/high assurance |

---

## 13. Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT",
"RECOMMENDED", and "MAY" in this document are to be interpreted as described in
RFC 2119.

---

## 14. Change Log

| Version | Date | Change |
| ------- | ---- | ------ |
| 1.0.0-draft | 2026-02-21 | Initial public disclosure draft |

---

*This document constitutes a public disclosure of the SIGIL Protocol method as of
2026-02-21T20:30:00Z. All implementations, forks, and derivative works are subject
to the EUPL-1.2 licence and/or the SIGIL Commercial Licence.*
