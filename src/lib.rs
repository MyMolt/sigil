//! # SIGIL — Sovereign Identity-Gated Interaction Layer
//!
//! An open protocol for securing AI agent-to-tool interactions.
//!
//! SIGIL defines **traits** (interfaces) for:
//! - **Identity** — binding users to trust levels
//! - **Scanning** — detecting sensitive content before it enters agent context
//! - **Vault** — encrypted storage for intercepted secrets
//! - **Audit** — tamper-evident logging of all security events
//! - **Policy** — permission and rate-limiting enforcement
//!
//! Implement these traits with your own backends (regex, HSM, LDAP, etc.)
//! to add SIGIL-compliant security to any agent system.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use sigil_protocol::{SensitivityScanner, AuditLogger, IdentityProvider, SecurityPolicy};
//! // Implement these traits with your own backends
//! ```

pub mod audit;
pub mod identity;
pub mod mcp_server;
pub mod policy;
pub mod registry;
pub mod scanner;
pub mod sigil_envelope;
pub mod vault;

// Re-export core types
pub use audit::{AuditEvent, AuditEventType, AuditLogger, FileAuditLogger, NullAuditLogger};
pub use identity::{IdentityBinding, IdentityProvider, TrustLevel};
pub use policy::{RiskLevel, SecurityPolicy};
pub use scanner::SensitivityScanner;
pub use sigil_envelope::{SigilEnvelope, SigilKeypair, Verdict};
pub use vault::{VaultEntry, VaultProvider};

// Re-export registry types (only when the `registry` feature is enabled)
#[cfg(feature = "registry")]
pub use registry::RemoteScanner;
