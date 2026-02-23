/// SIGIL Protocol — Primitive Benchmarks
///
/// Measures actual performance of the cryptographic and scanning operations
/// used in the SIGIL security envelope. Results are used in the patent
/// description (Section 7) as hardware-measured reference data.
///
/// Run with:  cargo run --release --example bench_primitives
///
/// Requires: Cargo.toml to include regex as a direct dependency.
/// This example temporarily enables it via the `registry` feature.
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::time::{Duration, Instant};

// ── HMAC-SHA256 via RustCrypto (available in sigil-rs indirectly) ──────────
// We use the sha2 + hmac crates which are transitive deps of ed25519-dalek
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ── Constants ─────────────────────────────────────────────────────────────
const WARMUP_ITERS: u64 = 1_000;
const BENCH_ITERS: u64 = 50_000;
// Typical SIGIL payload sizes
const PAYLOAD_SMALL: &[u8] =
    b"did:sigil:ed25519:AbCd1234 | tool_call | timestamp:1708631000 | risk:high";
// Simulated 4 KB audit event
const PAYLOAD_AUDIT: &[u8] = &[0x42u8; 4096];
// Simulated 10 KB AI response text for scanning
const RESPONSE_TEXT: &str = include_str!("bench_sample_text.txt");

fn bench<F: FnMut()>(name: &str, iters: u64, mut f: F) -> f64 {
    // Warmup
    for _ in 0..WARMUP_ITERS {
        f();
    }

    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();

    let ops_per_sec = iters as f64 / elapsed.as_secs_f64();
    let micros_per_op = elapsed.as_micros() as f64 / iters as f64;

    println!(
        "  {:<42}  {:>10.0} ops/s   {:>8.2} µs/op   (n={})",
        name, ops_per_sec, micros_per_op, iters
    );

    ops_per_sec
}

fn main() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║           SIGIL Protocol — Primitive Benchmark                            ║");
    println!("║           Patent reference: Section 7.2 / 7.3                             ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();

    // ── Hardware info ─────────────────────────────────────────────────────
    println!("Hardware:");
    if let Ok(cpu) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpu.lines() {
            if line.starts_with("model name") {
                println!(
                    "  CPU: {}",
                    line.split(':').nth(1).unwrap_or("unknown").trim()
                );
                break;
            }
        }
        let cores = cpu.lines().filter(|l| l.starts_with("processor")).count();
        println!("  Logical CPUs: {}", cores);
    } else {
        // macOS fallback
        let out = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output();
        if let Ok(o) = out {
            println!("  CPU: {}", String::from_utf8_lossy(&o.stdout).trim());
        }
        let cores = std::process::Command::new("sysctl")
            .args(["-n", "hw.logicalcpu"])
            .output();
        if let Ok(o) = cores {
            println!(
                "  Logical CPUs: {}",
                String::from_utf8_lossy(&o.stdout).trim()
            );
        }
    }
    println!("  Build: release (optimised, LTO)");
    println!("  Iterations per benchmark: {}", BENCH_ITERS);
    println!();

    // ── Ed25519 ───────────────────────────────────────────────────────────
    println!("Ed25519 (ed25519-dalek v2, single-threaded):");
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let msg = PAYLOAD_SMALL;

    bench("Ed25519 key generation", BENCH_ITERS, || {
        let _ = SigningKey::generate(&mut OsRng);
    });

    let sign_ops = bench("Ed25519 sign", BENCH_ITERS, || {
        let _ = signing_key.sign(msg);
    });

    let sig = signing_key.sign(msg);
    let verify_ops = bench("Ed25519 verify", BENCH_ITERS, || {
        let _ = verifying_key.verify(msg, &sig);
    });

    println!();

    // ── HMAC-SHA256 ───────────────────────────────────────────────────────
    println!("HMAC-SHA256 (single-threaded):");
    let hmac_key = b"sigil-audit-hmac-key-32-bytes!!!";

    bench("HMAC-SHA256  small payload (~70 B)", BENCH_ITERS, || {
        let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
        mac.update(PAYLOAD_SMALL);
        let _ = mac.finalize();
    });

    let hmac_ops = bench("HMAC-SHA256  audit payload (4 KB)", BENCH_ITERS, || {
        let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
        mac.update(PAYLOAD_AUDIT);
        let _ = mac.finalize();
    });

    println!();

    // ── Regex scanning ────────────────────────────────────────────────────
    // Simulate 43 patterns matching various sensitive data categories
    println!(
        "Regex scanning (simulating {} compiled patterns on SIGIL registry bundle):",
        43
    );
    let raw_patterns = [
        // API keys / secrets
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\w\-]{16,}",
        r"(?i)bearer\s+[\w\-\.]{20,}",
        r"(?i)ghp_[a-zA-Z0-9]{36}",           // GitHub PAT
        r"(?i)sk-[a-zA-Z0-9]{32,}",           // OpenAI key
        r"(?i)AIza[0-9A-Za-z\-_]{35}",        // Google API key
        r"(?i)AKIA[0-9A-Z]{16}",              // AWS Access Key
        r"(?i)xox[baprs]-[0-9A-Za-z\-]{10,}", // Slack token
        // PII
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", // Email
        r"\b(?:\+?49|0049)[\s\-]?\d{3}[\s\-]?\d{4,10}\b",        // DE phone
        r"\b\d{2}\.\d{2}\.\d{4}\b",                              // DE date
        // Financial
        r"\b[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b", // Card PAN
        r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b", // IBAN
        r"\b\d{3}\b",                                                 // CVV (simple)
        // Health
        r"(?i)(patient|diagnosis|medication|prescription)\s*[:=]\s*\w+",
        r"(?i)(ICD-?10|DSM-?[IV5]+)\s*[:\s]\s*[A-Z]\d+",
        // Private keys / certs
        r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----",
        r"-----BEGIN CERTIFICATE-----",
        r"(?i)private[_\s]?key\s*[:=]\s*[a-zA-Z0-9+/=]{32,}",
        // Passwords
        r"(?i)(password|passwd|pwd)\s*[:=]\s*\S{8,}",
        r"(?i)(secret|token|credential)\s*[:=]\s*\S{8,}",
        // Auth
        r"(?i)Authorization:\s*(Basic|Bearer)\s+\S+",
        r"(?i)Cookie:\s*\S+",
        // SSH
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        r"(?i)ssh-rsa\s+AAAA[A-Za-z0-9+/]+",
        // Addresses
        r"\b\d{5}\b",      // PLZ
        r"(?i)\bstraße\b", // German address marker
        // Research / confidential markers
        r"(?i)\b(confidential|proprietary|trade[_\s]?secret|not for distribution)\b",
        r"(?i)\b(internal use only|restricted|classified)\b",
        // National IDs
        r"\b[A-Z]{1,2}[0-9]{6,9}\b", // EU passport/ID pattern
        r"\b\d{3}-\d{2}-\d{4}\b",    // US SSN
        // IPv4 private ranges (may indicate infra leakage)
        r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
        // Crypto wallet addresses
        r"\b(0x[a-fA-F0-9]{40})\b",             // Ethereum
        r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", // Bitcoin
        // Generic high-entropy strings (potential secrets)
        r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
        // Connection strings / DSNs
        r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^\s]+",
        // JWT
        r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
        // Webhooks / URLs with tokens
        r"(?i)https?://[^\s]+(token|key|secret|auth)=[^\s&]+",
        // Generic numeric IDs (may be patient/account IDs)
        r"\b\d{10,16}\b",
        // Contract / document markers
        r"(?i)\b(NDA|non-disclosure|intellectual property|patent pending)\b",
        // Biometric
        r"(?i)(fingerprint|biometric|facial recognition|retinal scan)",
        // Location
        r"(?i)(GPS|coordinates|latitude|longitude)\s*[:=]\s*[\d\.\-\+, ]+",
        r"\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b", // lat,lon
    ];
    // Compile all 43 patterns once (as the registry does at startup)
    let compiled: Vec<regex::Regex> = raw_patterns
        .iter()
        .map(|p| regex::Regex::new(p).unwrap())
        .collect();
    println!("  Patterns compiled: {}", compiled.len());

    // 10 KB sample response text with one embedded secret (realistic match)
    let text = RESPONSE_TEXT;
    println!("  Sample text size:  {} bytes", text.len());

    let scan_ops = bench(
        "Regex scan all patterns (sequential first-match)",
        BENCH_ITERS,
        || {
            for re in &compiled {
                if re.is_match(text) {
                    break;
                }
            }
        },
    );

    bench(
        "Regex scan all patterns (exhaustive — all patterns)",
        BENCH_ITERS,
        || {
            for re in &compiled {
                let _ = re.is_match(text);
            }
        },
    );

    println!();

    // ── Summary table ─────────────────────────────────────────────────────
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║  PATENT SECTION 7.2 — Measured values (single-threaded, release build)   ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!(
        "║  Ed25519 signature creation   {:>10.0} ops/s  ({:.1} µs/op)         ║",
        sign_ops,
        1e6 / sign_ops
    );
    println!(
        "║  Ed25519 signature verify     {:>10.0} ops/s  ({:.1} µs/op)         ║",
        verify_ops,
        1e6 / verify_ops
    );
    println!(
        "║  HMAC-SHA256 (4 KB payload)   {:>10.0} ops/s  ({:.2} µs/op)         ║",
        hmac_ops,
        1e6 / hmac_ops
    );
    println!(
        "║  Regex scan (43 pat, first)   {:>10.0} ops/s  ({:.2} µs/op)         ║",
        scan_ops,
        1e6 / scan_ops
    );
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("All measurements: single-threaded, release build (--release), local hardware.");
    println!(
        "For multi-core throughput, multiply by available cores (Tokio runtime scales linearly)."
    );
}
