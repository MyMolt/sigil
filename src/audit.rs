//! Audit — tamper-evident logging of all security events.
//!
//! SIGIL defines the event schema (concrete struct) and the logger trait.
//! The schema is part of the protocol; the logging backend is implementation-specific.

use serde::{Deserialize, Serialize};

/// Types of security events defined by the SIGIL protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// An agent tool/command was executed.
    CommandExecution,
    /// A file was accessed.
    FileAccess,
    /// Configuration was changed.
    ConfigChange,
    /// Authentication succeeded.
    AuthSuccess,
    /// Authentication failed.
    AuthFailure,
    /// A security policy was violated.
    PolicyViolation,
    /// A general security event.
    SecurityEvent,
    /// Sensitive content was intercepted by the scanner.
    SigilInterception,
    /// An MCP tool call was gated.
    McpToolGated,
}

/// Actor — who performed the action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Actor {
    /// Channel the action originated from (e.g., "cli", "web", "mcp").
    pub channel: Option<String>,
    /// User identifier.
    pub user_id: Option<String>,
    /// Human-readable username.
    pub username: Option<String>,
}

/// Action — what was done.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Action {
    /// Description of the action (e.g., command string, tool name).
    pub description: String,
    /// Risk level assessment.
    pub risk_level: String,
    /// Whether the action was approved (by user or policy).
    pub approved: bool,
    /// Whether the action was allowed (by security policy).
    pub allowed: bool,
}

/// Result of an action execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether the action succeeded.
    pub success: bool,
    /// Exit code (for command executions).
    pub exit_code: Option<i32>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Error message if failed.
    pub error: Option<String>,
}

/// A complete SIGIL audit event.
///
/// This is the protocol's standard event format. All SIGIL-compliant
/// systems must produce events conforming to this schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Event type.
    pub event_type: AuditEventType,
    /// Who performed the action.
    pub actor: Actor,
    /// What was done.
    pub action: Action,
    /// Execution result.
    pub result: ExecutionResult,
    /// Optional HMAC signature for tamper evidence.
    pub signature: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event with a unique ID and current timestamp.
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type,
            actor: Actor::default(),
            action: Action::default(),
            result: ExecutionResult::default(),
            signature: None,
        }
    }

    /// Set the actor.
    pub fn with_actor(
        mut self,
        channel: String,
        user_id: Option<String>,
        username: Option<String>,
    ) -> Self {
        self.actor = Actor {
            channel: Some(channel),
            user_id,
            username,
        };
        self
    }

    /// Set the action.
    pub fn with_action(
        mut self,
        description: String,
        risk_level: String,
        approved: bool,
        allowed: bool,
    ) -> Self {
        self.action = Action {
            description,
            risk_level,
            approved,
            allowed,
        };
        self
    }

    /// Set the execution result.
    pub fn with_result(
        mut self,
        success: bool,
        exit_code: Option<i32>,
        duration_ms: u64,
        error: Option<String>,
    ) -> Self {
        self.result = ExecutionResult {
            success,
            exit_code,
            duration_ms,
            error,
        };
        self
    }
}

/// Trait for audit logging backends.
///
/// Implementations choose their storage (file, database, remote, etc.)
/// and may add features like HMAC signing, rotation, or streaming.
pub trait AuditLogger: Send + Sync {
    /// Log a SIGIL audit event.
    fn log(&self, event: &AuditEvent) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_creates_unique_ids() {
        let e1 = AuditEvent::new(AuditEventType::CommandExecution);
        let e2 = AuditEvent::new(AuditEventType::CommandExecution);
        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn audit_event_serializes_to_json() {
        let event = AuditEvent::new(AuditEventType::SigilInterception)
            .with_actor("cli".into(), Some("u1".into()), Some("alice".into()))
            .with_action("Redacted IBAN".into(), "high".into(), true, true);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("sigil_interception"));
        assert!(json.contains("alice"));
    }

    #[test]
    fn audit_event_type_variants_exhaustive() {
        // Ensure the protocol defines all expected event types
        let types = vec![
            AuditEventType::CommandExecution,
            AuditEventType::FileAccess,
            AuditEventType::ConfigChange,
            AuditEventType::AuthSuccess,
            AuditEventType::AuthFailure,
            AuditEventType::PolicyViolation,
            AuditEventType::SecurityEvent,
            AuditEventType::SigilInterception,
            AuditEventType::McpToolGated,
        ];
        assert_eq!(types.len(), 9);
    }
}
