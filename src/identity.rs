//! Identity — binding users to trust levels.
//!
//! SIGIL defines a standard identity model with trust levels and bindings.
//! Implementations choose their identity storage and provider integration
//! (SOUL.md, OIDC, SSI wallets, LDAP, etc.).

use serde::{Deserialize, Serialize};

/// Trust level for identity bindings.
///
/// The SIGIL protocol defines two tiers:
/// - `Low` — basic verification (email, OIDC, social login)
/// - `High` — strong verification (eIDAS, government ID, hardware key)
///
/// Implementations may map these to more granular levels internally,
/// but inter-system communication uses these two tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Basic verification (email, OIDC, social login).
    Low = 1,
    /// Strong verification (eIDAS, government ID, hardware key).
    High = 3,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Low
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustLevel::Low => write!(f, "Low (Level 1)"),
            TrustLevel::High => write!(f, "High (Level 3)"),
        }
    }
}

/// A SIGIL identity binding record.
///
/// Binds a user to an identity provider with a trust level.
/// Multiple bindings can exist for the same user (e.g., Google + eIDAS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityBinding {
    /// Identity provider name (e.g., "google", "eidas", "did:key", "hoodik").
    pub provider: String,
    /// Provider-specific user identifier.
    pub id: String,
    /// Trust level of this binding.
    pub trust_level: TrustLevel,
    /// ISO 8601 timestamp of when the binding was created.
    pub bound_at: String,
}

/// Trait for identity management.
///
/// Implementations manage identity storage, provider integration,
/// and trust level computation.
///
/// # Example
///
/// ```rust,no_run
/// use sigil::{IdentityProvider, IdentityBinding, TrustLevel};
///
/// struct LdapIdentity { /* ... */ }
///
/// impl IdentityProvider for LdapIdentity {
///     fn bindings(&self) -> Vec<IdentityBinding> { vec![] }
///     fn add_binding(&mut self, provider: &str, id: &str, level: TrustLevel) -> anyhow::Result<()> {
///         todo!()
///     }
///     fn max_trust_level(&self) -> TrustLevel { TrustLevel::Low }
///     fn has_binding(&self, provider: &str) -> bool { false }
/// }
/// ```
pub trait IdentityProvider: Send + Sync {
    /// List all identity bindings.
    fn bindings(&self) -> Vec<IdentityBinding>;

    /// Add a new identity binding.
    fn add_binding(&mut self, provider: &str, id: &str, level: TrustLevel) -> anyhow::Result<()>;

    /// Compute the maximum trust level across all bindings.
    fn max_trust_level(&self) -> TrustLevel;

    /// Check if a binding exists for the given provider.
    fn has_binding(&self, provider: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_level_ordering() {
        assert_eq!(TrustLevel::Low as u8, 1);
        assert_eq!(TrustLevel::High as u8, 3);
    }

    #[test]
    fn trust_level_display() {
        assert_eq!(format!("{}", TrustLevel::Low), "Low (Level 1)");
        assert_eq!(format!("{}", TrustLevel::High), "High (Level 3)");
    }

    #[test]
    fn identity_binding_serializes() {
        let binding = IdentityBinding {
            provider: "google".to_string(),
            id: "user@gmail.com".to_string(),
            trust_level: TrustLevel::Low,
            bound_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&binding).unwrap();
        let parsed: IdentityBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.provider, "google");
        assert_eq!(parsed.trust_level, TrustLevel::Low);
    }

    #[test]
    fn default_trust_level_is_low() {
        assert_eq!(TrustLevel::default(), TrustLevel::Low);
    }
}
