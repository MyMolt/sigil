//! Vault — encrypted storage for intercepted secrets.
//!
//! SIGIL defines the envelope format and provider trait.
//! Implementations choose their own encryption backend
//! (RSA+ChaCha20, AES-GCM, HSM, etc.).

use serde::{Deserialize, Serialize};

/// A sealed vault entry — the SIGIL envelope format.
///
/// This is the standard format that all SIGIL-compliant vaults produce.
/// The `ciphertext` field is opaque to the protocol; only the vault
/// provider knows how to decrypt it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier for this vault entry.
    pub id: String,
    /// Encrypted data (format determined by VaultProvider implementation).
    pub ciphertext: Vec<u8>,
    /// Human-readable description for the audit trail.
    pub description: String,
    /// ISO 8601 timestamp of when the entry was created.
    pub created_at: String,
    /// Tags for categorization (e.g., "api-key", "iban", "pin").
    pub tags: Vec<String>,
}

/// Trait for encrypted vault storage backends.
///
/// Implementors provide their own encryption scheme.
/// The protocol only requires encrypt/decrypt/exists operations.
///
/// # Example
///
/// ```rust,no_run
/// use sigil::{VaultProvider, VaultEntry};
///
/// struct HsmVault { /* HSM connection */ }
///
/// impl VaultProvider for HsmVault {
///     fn encrypt(&self, plaintext: &[u8], description: &str) -> anyhow::Result<VaultEntry> {
///         // Encrypt via HSM and return sealed entry
///         todo!()
///     }
///     fn decrypt(&self, id: &str) -> anyhow::Result<Vec<u8>> {
///         // Decrypt via HSM
///         todo!()
///     }
///     fn exists(&self, id: &str) -> bool { false }
/// }
/// ```
pub trait VaultProvider: Send + Sync {
    /// Encrypt plaintext and store as a sealed vault entry.
    ///
    /// Returns the `VaultEntry` with metadata. The ciphertext format
    /// is implementation-specific.
    fn encrypt(&self, plaintext: &[u8], description: &str) -> anyhow::Result<VaultEntry>;

    /// Decrypt a vault entry by its ID.
    ///
    /// Returns the original plaintext bytes.
    fn decrypt(&self, id: &str) -> anyhow::Result<Vec<u8>>;

    /// Check if a vault entry exists.
    fn exists(&self, id: &str) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_entry_serializes() {
        let entry = VaultEntry {
            id: "test-123".to_string(),
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            description: "Test secret".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            tags: vec!["test".to_string()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: VaultEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test-123");
        assert_eq!(parsed.ciphertext, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
