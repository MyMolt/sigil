# sigil-protocol (npm)

> Node.js / TypeScript SDK for the [SIGIL Protocol](https://sigil-protocol.org) — crowdsourced scanner patterns and security policies for AI agents and MCP tools.

## Install

```bash
npm install sigil-protocol
```

For pattern/policy *submission* (write operations), also install the Ed25519 signer:

```bash
npm install @noble/ed25519
```

## Quick Start

### Scan text for sensitive content

```ts
import { RemoteScanner } from 'sigil-protocol';

// Fetches 43+ verified patterns at startup, falls back to built-ins if offline
const scanner = await RemoteScanner.fromRegistry();

console.log(`Loaded ${scanner.ruleCount} rules from: ${scanner.source}`);

const hit = scanner.scan('Authorization: Bearer sk-abc123...');
if (hit) {
  console.log(`Sensitive: ${hit.name} (${hit.severity})`);
  // → { name: 'openai_api_key', category: 'credential', severity: 'critical', hint: '[SIGIL-VAULT: OPENAI_KEY]' }
}
```

### Redact sensitive content

```ts
const clean = scanner.redact(`
  export OPENAI_API_KEY=sk-abc123...
  export DB_URL=postgres://user:pass@host/db
`);
// → All matches replaced with their vault hints
```

### Self-hosted or local dev

```ts
const scanner = await RemoteScanner.fromUrl('http://localhost:3100/patterns/bundle');
```

### Submit a pattern (requires did:sigil: key)

```ts
import { SigilClient } from 'sigil-protocol';
import { etc } from '@noble/ed25519';

const privateKey = etc.randomPrivateKey(); // or load from secure store
const client = new SigilClient();

await client.submitPattern({
  name: 'my_api_key',
  description: 'My service API key (msk_ prefix)',
  category: 'credential',
  pattern: 'msk_[a-zA-Z0-9]{32}',
  severity: 'high',
  authorDid: 'did:sigil:my_namespace_01',
  privateKey,
});
```

## API

### `RemoteScanner`

| Method / Property | Description |
|---|---|
| `RemoteScanner.fromRegistry()` | Static async constructor — fetches from `registry.sigil-protocol.org` |
| `RemoteScanner.fromUrl(url)` | Static async constructor — fetches from a custom URL |
| `.scan(text)` | Returns `ScanHit \| null` |
| `.redact(text)` | Returns text with all matches replaced by vault hints |
| `.ruleCount` | Number of compiled rules loaded |
| `.source` | `'registry'` or `'fallback'` |

### `ScanHit`

```ts
interface ScanHit {
  name: string;      // e.g. "aws_access_key_id"
  category: string;  // e.g. "credential"
  hint: string;      // e.g. "[SIGIL-VAULT: AWS_KEY_ID]"
  severity: string;  // "low" | "medium" | "high" | "critical"
}
```

### `SigilClient`

| Method | Description |
|---|---|
| `new SigilClient(base?)` | Optionally point at a custom registry base URL |
| `.submitPattern(opts)` | POST a new scanner pattern (requires Ed25519 private key) |
| `.submitPolicy(opts)` | POST a new security policy (requires Ed25519 private key) |
| `SigilClient.signMessage(key, msg)` | Static signing helper using `@noble/ed25519` |

## Registry

Live API: [registry.sigil-protocol.org](https://registry.sigil-protocol.org)  
API Docs: [sigil-protocol.org/registry.html](https://sigil-protocol.org/registry.html)  
Rust crate: [crates.io/crates/sigil-protocol](https://crates.io/crates/sigil-protocol)

## License

MIT
