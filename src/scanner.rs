//! Sensitivity scanning — detect sensitive content before it enters agent context.
//!
//! SIGIL defines the trait; implementations choose their detection strategy
//! (regex, ML-based, dictionary lookup, etc.).

/// Trait for detecting sensitive content in text.
///
/// Implementors define their own patterns and detection logic.
/// The protocol requires only that detected content is categorized
/// by a human-readable name (e.g., "API Key", "IBAN", "Bank PIN").
///
/// # Example
///
/// ```rust
/// use sigil::SensitivityScanner;
///
/// struct RegexScanner { /* ... */ }
///
/// impl SensitivityScanner for RegexScanner {
///     fn scan(&self, text: &str) -> Option<String> {
///         if text.contains("sk-") {
///             Some("API Key".to_string())
///         } else {
///             None
///         }
///     }
/// }
/// ```
pub trait SensitivityScanner: Send + Sync {
    /// Scan text for sensitive content.
    ///
    /// Returns `Some(category_name)` if sensitive content is detected,
    /// or `None` if the text is safe.
    ///
    /// The category name is used in audit logs and vault metadata.
    fn scan(&self, text: &str) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockScanner;

    impl SensitivityScanner for MockScanner {
        fn scan(&self, text: &str) -> Option<String> {
            if text.contains("SECRET") {
                Some("Test Secret".to_string())
            } else {
                None
            }
        }
    }

    #[test]
    fn scanner_detects_sensitive_content() {
        let scanner = MockScanner;
        assert_eq!(
            scanner.scan("Contains SECRET data"),
            Some("Test Secret".to_string())
        );
    }

    #[test]
    fn scanner_passes_safe_content() {
        let scanner = MockScanner;
        assert!(scanner.scan("This is totally safe").is_none());
    }
}
