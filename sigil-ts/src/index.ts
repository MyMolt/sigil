/**
 * sigil-protocol — Node.js / TypeScript SDK
 *
 * Provides `RemoteScanner` for fetching verified scanner patterns from the
 * SIGIL Registry and scanning text for sensitive content at runtime.
 * Also exports `SigilClient` with helpers for DID signing and pattern/policy submission.
 */

const REGISTRY_BASE = 'https://registry.sigil-protocol.org';
const BUNDLE_URL = `${REGISTRY_BASE}/patterns/bundle`;
const FETCH_TIMEOUT_MS = 5_000;

// ── Types ────────────────────────────────────────────────────────────────────

export interface ScannerPattern {
    id: string;
    name: string;
    description: string;
    category: string;
    pattern: string;
    replacement_hint: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    verified: boolean;
    vote_score: number;
}

export interface PatternBundle {
    count: number;
    patterns: ScannerPattern[];
    downloaded_at: string;
}

export interface ScanHit {
    /** Pattern name (e.g. "aws_access_key_id") */
    name: string;
    /** Category (e.g. "credential") */
    category: string;
    /** The vault replacement hint (e.g. "[SIGIL-VAULT: AWS_KEY_ID]") */
    hint: string;
    /** Severity of the matched pattern */
    severity: string;
}

export type PatternSource = 'registry' | 'fallback';

// ── Built-in fallback patterns ────────────────────────────────────────────────
// A minimal set of patterns used if the registry is unreachable.

const FALLBACK_PATTERNS: ScannerPattern[] = [
    {
        id: 'builtin-1', name: 'aws_access_key_id', category: 'credential',
        pattern: '(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
        replacement_hint: '[SIGIL-VAULT: AWS_KEY_ID]', severity: 'critical',
        verified: true, vote_score: 0, description: 'AWS Access Key ID',
    },
    {
        id: 'builtin-2', name: 'openai_api_key', category: 'credential',
        pattern: 'sk-[a-zA-Z0-9]{48,}',
        replacement_hint: '[SIGIL-VAULT: OPENAI_KEY]', severity: 'critical',
        verified: true, vote_score: 0, description: 'OpenAI API key',
    },
    {
        id: 'builtin-3', name: 'github_pat', category: 'credential',
        pattern: 'gh[pousr]_[A-Za-z0-9_]{36,}',
        replacement_hint: '[SIGIL-VAULT: GITHUB_PAT]', severity: 'critical',
        verified: true, vote_score: 0, description: 'GitHub Personal Access Token',
    },
    {
        id: 'builtin-4', name: 'private_key_pem', category: 'secret',
        pattern: '-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----',
        replacement_hint: '[SIGIL-VAULT: PRIVATE_KEY]', severity: 'critical',
        verified: true, vote_score: 0, description: 'PEM private key block',
    },
];

// ── CompiledRule ──────────────────────────────────────────────────────────────

interface CompiledRule {
    pattern: ScannerPattern;
    regex: RegExp;
}

function compilePatterns(patterns: ScannerPattern[]): CompiledRule[] {
    const compiled: CompiledRule[] = [];
    for (const p of patterns) {
        try {
            compiled.push({ pattern: p, regex: new RegExp(p.pattern) });
        } catch (e) {
            // Skip patterns with invalid regex rather than crashing
            console.warn(`[sigil] Invalid regex for pattern "${p.name}" — skipped`);
        }
    }
    return compiled;
}

// ── RemoteScanner ─────────────────────────────────────────────────────────────

/**
 * Downloads verified scanner patterns from the SIGIL Registry at construction
 * time, compiles them into RegExp objects, and exposes a `.scan()` method.
 *
 * Falls back to built-in patterns if the registry is unreachable.
 *
 * @example
 * ```ts
 * const scanner = await RemoteScanner.fromRegistry();
 * const hit = scanner.scan('Authorization: Bearer sk-abc...');
 * if (hit) console.log(`Sensitive: ${hit.name} (${hit.severity})`);
 * ```
 */
export class RemoteScanner {
    private readonly rules: CompiledRule[];
    private readonly _source: PatternSource;

    private constructor(rules: CompiledRule[], source: PatternSource) {
        this.rules = rules;
        this._source = source;
    }

    /** Number of compiled rules loaded. */
    get ruleCount(): number { return this.rules.length; }

    /** Whether patterns came from the live registry or the built-in fallback. */
    get source(): PatternSource { return this._source; }

    /**
     * Build a `RemoteScanner` by fetching the verified bundle from
     * `https://registry.sigil-protocol.org/patterns/bundle`.
     */
    static async fromRegistry(): Promise<RemoteScanner> {
        return RemoteScanner.fromUrl(BUNDLE_URL);
    }

    /**
     * Build a `RemoteScanner` from a custom bundle URL (e.g. local dev registry).
     */
    static async fromUrl(url: string): Promise<RemoteScanner> {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
            const res = await fetch(url, { signal: controller.signal });
            clearTimeout(timer);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const bundle: PatternBundle = await res.json();
            const rules = compilePatterns(bundle.patterns);
            return new RemoteScanner(rules, 'registry');
        } catch (err) {
            console.warn(`[sigil] Registry unreachable (${(err as Error).message}), using built-in fallback`);
            return new RemoteScanner(compilePatterns(FALLBACK_PATTERNS), 'fallback');
        }
    }

    /**
     * Scan text for sensitive content.
     *
     * Returns the first `ScanHit` if sensitive content is detected, or `null`.
     */
    scan(text: string): ScanHit | null {
        for (const { pattern, regex } of this.rules) {
            if (regex.test(text)) {
                return {
                    name: pattern.name,
                    category: pattern.category,
                    hint: pattern.replacement_hint,
                    severity: pattern.severity,
                };
            }
        }
        return null;
    }

    /**
     * Redact all sensitive patterns in the text, replacing matches with vault hints.
     */
    redact(text: string): string {
        let result = text;
        for (const { pattern, regex } of this.rules) {
            result = result.replace(new RegExp(regex.source, 'g'), pattern.replacement_hint);
        }
        return result;
    }
}

// ── SigilClient ───────────────────────────────────────────────────────────────

export interface SubmitPatternOptions {
    name: string;
    description: string;
    category: 'credential' | 'secret' | 'pii' | 'financial';
    pattern: string;
    replacementHint?: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    /** Your did:sigil: identifier */
    authorDid: string;
    /** Raw 32-byte Ed25519 private key as Uint8Array */
    privateKey: Uint8Array;
}

export interface SubmitPolicyOptions {
    toolName: string;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    requiresTrust: 'Low' | 'Medium' | 'High';
    requiresConfirmation: boolean;
    rationale: string;
    authorDid: string;
    privateKey: Uint8Array;
}

/**
 * SIGIL Registry client for submitting patterns and policies using
 * Ed25519-authenticated requests.
 *
 * @example
 * ```ts
 * const client = new SigilClient();
 * await client.submitPattern({
 *   name: 'my_api_key',
 *   description: 'My service API key',
 *   category: 'credential',
 *   pattern: 'msk_[a-zA-Z0-9]{32}',
 *   severity: 'high',
 *   authorDid: 'did:sigil:my_ns_01',
 *   privateKey: myPrivKeyBytes,
 * });
 * ```
 */
export class SigilClient {
    private readonly base: string;

    constructor(registryBase = REGISTRY_BASE) {
        this.base = registryBase;
    }

    private async sign(privateKey: Uint8Array, message: string): Promise<string> {
        // Use Node.js crypto (available in Node 20+)
        const { createSign } = await import('node:crypto');
        const key = {
            key: privateKey,
            format: 'raw' as const,
            type: 'private' as const,
            // Ed25519 key from raw 32-byte seed
        };
        throw new Error(
            'Ed25519 signing via Node.js crypto requires a KeyObject. ' +
            'Pass a pre-computed base64url signature via the low-level `post()` method, ' +
            'or use the `@noble/ed25519` package to compute `sig`.'
        );
    }

    /**
     * Low-level helper: sign a message using @noble/ed25519 and return base64url signature.
     * Requires `npm install @noble/ed25519`.
     */
    static async signMessage(privateKey: Uint8Array, message: string): Promise<string> {
        const { sign } = await import('@noble/ed25519' as any).catch(() => {
            throw new Error('Install @noble/ed25519: npm install @noble/ed25519');
        });
        const msgBytes = new TextEncoder().encode(message);
        const sigBytes: Uint8Array = await sign(msgBytes, privateKey);
        return Buffer.from(sigBytes).toString('base64url');
    }

    /** Submit a new scanner pattern to the registry. */
    async submitPattern(opts: SubmitPatternOptions): Promise<unknown> {
        const msg = `sigil-registry:pattern:${opts.name}:${opts.category}:${opts.pattern}:${opts.authorDid}`;
        const signature = await SigilClient.signMessage(opts.privateKey, msg);
        const res = await fetch(`${this.base}/patterns`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: opts.name,
                description: opts.description,
                category: opts.category,
                pattern: opts.pattern,
                replacement_hint: opts.replacementHint ?? `[SIGIL-VAULT: ${opts.name.toUpperCase()}]`,
                severity: opts.severity,
                author_did: opts.authorDid,
                signature,
            }),
        });
        if (!res.ok) throw new Error(`Submit failed: HTTP ${res.status}`);
        return res.json();
    }

    /** Submit a new security policy to the registry. */
    async submitPolicy(opts: SubmitPolicyOptions): Promise<unknown> {
        const msg = `sigil-registry:policy:${opts.toolName}:${opts.riskLevel}:${opts.requiresTrust}:${opts.authorDid}`;
        const signature = await SigilClient.signMessage(opts.privateKey, msg);
        const res = await fetch(`${this.base}/policies`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tool_name: opts.toolName,
                risk_level: opts.riskLevel,
                requires_trust: opts.requiresTrust,
                requires_confirmation: opts.requiresConfirmation,
                rationale: opts.rationale,
                author_did: opts.authorDid,
                signature,
            }),
        });
        if (!res.ok) throw new Error(`Submit failed: HTTP ${res.status}`);
        return res.json();
    }
}

// ── Re-exports ────────────────────────────────────────────────────────────────

export { REGISTRY_BASE, BUNDLE_URL };
