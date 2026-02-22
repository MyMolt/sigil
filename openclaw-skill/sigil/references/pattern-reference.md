# SIGIL Pattern Reference

All patterns are fetched live from [registry.sigil-protocol.org/patterns/bundle](https://registry.sigil-protocol.org/patterns/bundle).

## Pattern Format

Each entry in the registry bundle is:

```json
{
  "id": "aws_access_key_id",
  "category": "credential",
  "severity": "Critical",
  "description": "AWS Access Key ID",
  "regex": "(?i)(AKIA[0-9A-Z]{16})",
  "entropy_threshold": null,
  "verified": true,
  "added": "2026-01-10"
}
```

## Categories

### `credential` — Cloud & Service Keys

| Pattern ID | Severity | Example match |
|---|---|---|
| `aws_access_key_id` | Critical | `AKIAIOSFODNN7EXAMPLE` |
| `aws_secret_access_key` | Critical | 40-char base62 adjacent to `aws_secret` |
| `gcp_service_account_key` | Critical | JSON blob with `"private_key_id"` |
| `github_personal_access_token` | Critical | `ghp_...` / `github_pat_...` |
| `npm_access_token` | High | `npm_...` |
| `stripe_secret_key` | Critical | `sk_live_...` |
| `sendgrid_api_key` | High | `SG.` prefix |
| `twilio_auth_token` | High | 32-char hex next to `auth_token` |
| `openai_api_key` | Critical | `sk-proj-...` |

### `pii` — Personal Data (EU GDPR scope)

| Pattern ID | Severity | Notes |
|---|---|---|
| `email_address` | Medium | RFC 5321 |
| `eu_iban` | High | DE, AT, CH, FR, ES formats |
| `eu_phone` | Medium | E.164 with EU country codes |
| `ssn_us` | High | `NNN-NN-NNNN` |

### `key` — Cryptographic Material

| Pattern ID | Severity | Notes |
|---|---|---|
| `rsa_private_key` | Critical | `-----BEGIN RSA PRIVATE KEY-----` |
| `ec_private_key` | Critical | `-----BEGIN EC PRIVATE KEY-----` |
| `ssh_private_key` | Critical | OpenSSH format |
| `jwt_secret` | High | High-entropy string adjacent to `jwt_secret` |

### `dangerous_sql` — Destructive Queries

| Pattern ID | Severity | Notes |
|---|---|---|
| `sql_drop_table` | Critical | `DROP TABLE` with any table name |
| `sql_truncate` | High | `TRUNCATE` statement |
| `sql_delete_no_where` | High | `DELETE FROM` without `WHERE` |

### `prompt_injection` — LLM Safety

| Pattern ID | Severity | Notes |
|---|---|---|
| `ignore_previous_instructions` | High | Classic jailbreak opener |
| `system_prompt_leak` | High | Attempts to reveal system prompt |
| `role_override` | Medium | `You are now...` / `Act as...` |

## Fetching Patterns Offline

For air-gapped or offline environments:

```bash
# Download the full bundle once
sigil-scan patterns update --output ~/.sigil/bundle.json

# Use it offline
sigil-scan check --pattern-source ~/.sigil/bundle.json '<json>'

# Or set env var
export SIGIL_OFFLINE=true
```
