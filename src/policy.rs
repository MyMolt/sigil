//! Policy — permission and rate-limiting enforcement.
//!
//! SIGIL defines the risk model and policy trait.
//! Implementations configure their own rules (allowlists, rate limits,
//! confirmation requirements, etc.).

use serde::{Deserialize, Serialize};

/// Risk level classification for actions.
///
/// Every action in a SIGIL-protected system is classified into one
/// of these three levels. The policy then decides what to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Safe actions (read-only, within workspace).
    Low,
    /// Actions that modify state but are recoverable.
    Medium,
    /// Destructive, external, or irreversible actions.
    High,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
        }
    }
}

/// Trait for security policy enforcement.
///
/// Implementations define their own rules for what actions are allowed,
/// what requires confirmation, and how rate limiting works.
///
/// # Protocol Requirements
///
/// A conforming implementation MUST:
/// 1. Classify all actions by `RiskLevel`
/// 2. Enforce rate limiting via `record_action()`
/// 3. Gate high-risk actions through `requires_confirmation()`
///
/// # Example
///
/// ```rust,no_run
/// use sigil::{SecurityPolicy, RiskLevel};
///
/// struct StrictPolicy;
///
/// impl SecurityPolicy for StrictPolicy {
///     fn is_action_allowed(&self, action: &str) -> bool { false }
///     fn risk_level(&self, action: &str) -> RiskLevel { RiskLevel::High }
///     fn requires_confirmation(&self, action: &str) -> bool { true }
///     fn record_action(&self) -> bool { true }
///     fn is_rate_limited(&self) -> bool { false }
/// }
/// ```
pub trait SecurityPolicy: Send + Sync {
    /// Check if an action (tool/command name) is allowed to execute.
    fn is_action_allowed(&self, action: &str) -> bool;

    /// Classify the risk level of an action.
    fn risk_level(&self, action: &str) -> RiskLevel;

    /// Check if an action requires explicit user confirmation.
    fn requires_confirmation(&self, action: &str) -> bool;

    /// Record an action execution for rate limiting.
    /// Returns `true` if the action is within rate limits, `false` if exceeded.
    fn record_action(&self) -> bool;

    /// Check if the rate limit would be exceeded (without recording).
    fn is_rate_limited(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Low), "low");
        assert_eq!(format!("{}", RiskLevel::Medium), "medium");
        assert_eq!(format!("{}", RiskLevel::High), "high");
    }

    #[test]
    fn risk_level_serializes() {
        let json = serde_json::to_string(&RiskLevel::High).unwrap();
        let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, RiskLevel::High);
    }
}
