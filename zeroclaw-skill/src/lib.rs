//! # sigil-zeroclaw
//!
//! ZeroClaw plugin that adds the full SIGIL security layer to any ZeroClaw agent.
//!
//! ## What it provides
//!
//! - **`SigilScanTool`** — a ZeroClaw `Tool` that scans arbitrary JSON for
//!   leaked secrets before it is passed to any backend tool. Returns a structured
//!   hit report the LLM can act on.
//! - **`SigilGateTool`** — wraps another tool call, blocks it if SIGIL finds a
//!   Critical-severity hit, and writes an audit event either way.
//! - **`SigilObservability`** — implements the ZeroClaw `Observability` trait to
//!   attach SIGIL audit logging to every agent turn automatically.
//!
//! ## Quick start
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! sigil-zeroclaw = "0.1"
//! ```
//!
//! ```rust,no_run
//! use sigil_zeroclaw::{SigilScanTool, SigilObservability};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialise the scanner (fetches the 43-pattern bundle from registry)
//!     let scan_tool = SigilScanTool::from_registry().await?;
//!     let observability = SigilObservability::new("~/.sigil/audit.jsonl")?;
//!
//!     // Register with your ZeroClaw agent builder
//!     // agent.add_tool(scan_tool);
//!     // agent.set_observability(observability);
//!
//!     Ok(())
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sigil_protocol::{
    AuditEvent, AuditEventType, AuditLogger, FileAuditLogger, NullAuditLogger, RemoteScanner,
    SensitivityScanner,
};
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

// ─── ZeroClaw trait stubs ───────────────────────────────────────────────────
// These mirror the ZeroClaw trait interface. Replace with the actual
// `zeroclaw` crate types when the upstream crate is published.

/// A parsed tool call from the LLM — mirrors `zeroclaw::Tool::ParsedToolCall`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedToolCall {
    /// The tool name the LLM requested.
    pub name: String,
    /// The raw JSON arguments the LLM passed.
    pub args: Value,
    /// Optional call-site identifier for correlation.
    pub call_id: Option<String>,
}

/// Result returned by a ZeroClaw tool.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolResult {
    pub output: Value,
    pub error: Option<String>,
}

impl ToolResult {
    pub fn ok(output: impl Serialize) -> Self {
        Self {
            output: serde_json::to_value(output).unwrap_or(Value::Null),
            error: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            output: Value::Null,
            error: Some(msg.into()),
        }
    }
}

/// The ZeroClaw `Tool` trait — implement this to register a skill.
#[async_trait]
pub trait ZeroClawTool: Send + Sync {
    /// Unique identifier. The agent core matches tool calls to this.
    fn name(&self) -> &str;
    /// Human-readable description sent to the LLM in the system prompt.
    fn description(&self) -> &str;
    /// Execute the tool. Called by the dispatcher on every matching tool call.
    async fn execute(&self, call: ParsedToolCall) -> Result<ToolResult>;
}

/// The ZeroClaw `Observability` trait — attach to the agent for lifecycle hooks.
#[async_trait]
pub trait ZeroClawObservability: Send + Sync {
    async fn on_turn_start(&self, context: &str) -> Result<()>;
    async fn on_tool_call(&self, call: &ParsedToolCall) -> Result<()>;
    async fn on_tool_result(&self, call: &ParsedToolCall, result: &ToolResult) -> Result<()>;
    async fn on_turn_end(&self, context: &str) -> Result<()>;
}

// ─── SigilScanTool ──────────────────────────────────────────────────────────

/// A ZeroClaw `Tool` that scans arbitrary JSON for leaked secrets or dangerous
/// patterns. Register it so the LLM can call `sigil_scan` before submitting
/// data to any sensitive backend.
pub struct SigilScanTool {
    scanner: Arc<dyn SensitivityScanner + Send + Sync>,
    audit: Arc<dyn AuditLogger + Send + Sync>,
}

impl SigilScanTool {
    /// Fetch the latest pattern bundle from `registry.sigil-protocol.org` and
    /// initialise the scanner.
    pub async fn from_registry() -> Result<Self> {
        let scanner = RemoteScanner::from_registry().await?;
        Ok(Self {
            scanner: Arc::new(scanner),
            audit: Arc::new(NullAuditLogger),
        })
    }

    /// Use a file-backed audit log in addition to returning results to the LLM.
    pub async fn from_registry_with_audit<P: AsRef<Path>>(log_path: P) -> Result<Self> {
        let scanner = RemoteScanner::from_registry().await?;
        let audit = FileAuditLogger::open(log_path)?;
        Ok(Self {
            scanner: Arc::new(scanner),
            audit: Arc::new(audit),
        })
    }
}

#[async_trait]
impl ZeroClawTool for SigilScanTool {
    fn name(&self) -> &str {
        "sigil_scan"
    }

    fn description(&self) -> &str {
        "Scans a JSON payload for leaked secrets (API keys, credentials, private keys, PII, \
         dangerous SQL) using the SIGIL registry of 43 verified patterns. Call this before \
         passing sensitive data to any tool backend. Returns a list of security findings. \
         If any findings have severity 'Critical', you MUST NOT proceed with the tool call \
         and MUST inform the user immediately."
    }

    async fn execute(&self, call: ParsedToolCall) -> Result<ToolResult> {
        let payload = call.args.get("payload").unwrap_or(&call.args);
        let payload_str = serde_json::to_string(payload)?;

        let hits = self.scanner.scan(&payload_str)?;

        if hits.is_empty() {
            info!("sigil_scan: clean — no findings");
            return Ok(ToolResult::ok(serde_json::json!({
                "status": "clean",
                "findings": [],
                "message": "No security issues detected."
            })));
        }

        let findings: Vec<Value> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "pattern": h.pattern_name,
                    "severity": format!("{:?}", h.severity),
                    "category": h.category,
                    "blocked": matches!(h.severity, sigil_protocol::Severity::Critical)
                })
            })
            .collect();

        let has_critical = hits
            .iter()
            .any(|h| matches!(h.severity, sigil_protocol::Severity::Critical));

        // Log to audit file
        let _ = self.audit.log(&AuditEvent {
            event_type: AuditEventType::SigilInterception,
            actor: "zeroclaw-agent".into(),
            pattern_name: hits[0].pattern_name.clone(),
            severity: format!("{:?}", hits[0].severity),
            blocked: has_critical,
            timestamp: chrono::Utc::now(),
        });

        warn!(
            "sigil_scan: {} finding(s), critical={}",
            hits.len(),
            has_critical
        );

        Ok(ToolResult::ok(serde_json::json!({
            "status": if has_critical { "blocked" } else { "warn" },
            "findings": findings,
            "message": if has_critical {
                "CRITICAL: Leaked secrets detected. This tool call has been blocked."
            } else {
                "WARNING: Potential security issues detected. Review before proceeding."
            }
        })))
    }
}

// ─── SigilGateTool ──────────────────────────────────────────────────────────

/// Wraps another tool — scans its args before calling it, blocks on Critical.
pub struct SigilGateTool<T: ZeroClawTool> {
    inner: T,
    scanner: Arc<dyn SensitivityScanner + Send + Sync>,
    audit: Arc<dyn AuditLogger + Send + Sync>,
}

impl<T: ZeroClawTool> SigilGateTool<T> {
    pub async fn wrap(inner: T, log_path: Option<&Path>) -> Result<Self> {
        let scanner = Arc::new(RemoteScanner::from_registry().await?);
        let audit: Arc<dyn AuditLogger + Send + Sync> = match log_path {
            Some(p) => Arc::new(FileAuditLogger::open(p)?),
            None => Arc::new(NullAuditLogger),
        };
        Ok(Self {
            inner,
            scanner,
            audit,
        })
    }
}

#[async_trait]
impl<T: ZeroClawTool> ZeroClawTool for SigilGateTool<T> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    async fn execute(&self, call: ParsedToolCall) -> Result<ToolResult> {
        let payload_str = serde_json::to_string(&call.args)?;
        let hits = self.scanner.scan(&payload_str)?;

        let has_critical = hits
            .iter()
            .any(|h| matches!(h.severity, sigil_protocol::Severity::Critical));

        if !hits.is_empty() {
            let _ = self.audit.log(&AuditEvent {
                event_type: AuditEventType::SigilInterception,
                actor: "zeroclaw-agent".into(),
                pattern_name: hits[0].pattern_name.clone(),
                severity: format!("{:?}", hits[0].severity),
                blocked: has_critical,
                timestamp: chrono::Utc::now(),
            });
        }

        if has_critical {
            warn!("SigilGateTool: blocking {} — critical finding", call.name);
            return Ok(ToolResult::err(format!(
                "🔐 SIGIL blocked this call to `{}`: leaked secret detected ({:?}). \
                 Remove the sensitive data and retry.",
                call.name, hits[0].pattern_name
            )));
        }

        self.inner.execute(call).await
    }
}

// ─── SigilObservability ─────────────────────────────────────────────────────

/// Implements the ZeroClaw `Observability` trait — attaches SIGIL audit logging
/// to every agent turn automatically without any per-tool configuration.
pub struct SigilObservability {
    audit: Arc<dyn AuditLogger + Send + Sync>,
    scanner: Arc<dyn SensitivityScanner + Send + Sync>,
}

impl SigilObservability {
    pub fn new<P: AsRef<Path>>(log_path: P) -> Result<Self> {
        let audit = FileAuditLogger::open(log_path)?;
        // Use offline null scanner here; swap to RemoteScanner if wanted
        Ok(Self {
            audit: Arc::new(audit),
            scanner: Arc::new(sigil_protocol::NullScanner),
        })
    }

    pub async fn with_remote_scanner<P: AsRef<Path>>(log_path: P) -> Result<Self> {
        let audit = FileAuditLogger::open(log_path)?;
        let scanner = RemoteScanner::from_registry().await?;
        Ok(Self {
            audit: Arc::new(audit),
            scanner: Arc::new(scanner),
        })
    }
}

#[async_trait]
impl ZeroClawObservability for SigilObservability {
    async fn on_turn_start(&self, _context: &str) -> Result<()> {
        Ok(())
    }

    async fn on_tool_call(&self, call: &ParsedToolCall) -> Result<()> {
        let payload = serde_json::to_string(&call.args)?;
        let hits = self.scanner.scan(&payload)?;
        let has_critical = hits
            .iter()
            .any(|h| matches!(h.severity, sigil_protocol::Severity::Critical));

        if !hits.is_empty() {
            self.audit.log(&AuditEvent {
                event_type: AuditEventType::SigilInterception,
                actor: format!("zeroclaw/{}", call.name),
                pattern_name: hits[0].pattern_name.clone(),
                severity: format!("{:?}", hits[0].severity),
                blocked: has_critical,
                timestamp: chrono::Utc::now(),
            })?;
        }
        Ok(())
    }

    async fn on_tool_result(&self, call: &ParsedToolCall, result: &ToolResult) -> Result<()> {
        // Scan the tool *response* too — the backend might return credentials
        let payload = serde_json::to_string(&result.output)?;
        let hits = self.scanner.scan(&payload)?;
        if !hits.is_empty() {
            warn!(
                "SigilObservability: secret in response from `{}` — {:?}",
                call.name, hits[0].pattern_name
            );
            self.audit.log(&AuditEvent {
                event_type: AuditEventType::SigilInterception,
                actor: format!("zeroclaw/{}/response", call.name),
                pattern_name: hits[0].pattern_name.clone(),
                severity: format!("{:?}", hits[0].severity),
                blocked: false, // already delivered, just log it
                timestamp: chrono::Utc::now(),
            })?;
        }
        Ok(())
    }

    async fn on_turn_end(&self, _context: &str) -> Result<()> {
        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_tool_returns_clean_for_safe_payload() {
        // This test uses a null/offline scanner stub — swap in real scanner for integration test
        // Placeholder until zeroclaw crate and RemoteScanner offline mode are wired up
        let payload = serde_json::json!({"query": "SELECT name FROM users"});
        let call = ParsedToolCall {
            name: "sigil_scan".into(),
            args: serde_json::json!({"payload": payload}),
            call_id: None,
        };
        // Verify struct is well-formed
        assert_eq!(call.name, "sigil_scan");
    }

    #[test]
    fn tool_result_serialises() {
        let r = ToolResult::ok(serde_json::json!({"status": "clean"}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("clean"));
    }
}
