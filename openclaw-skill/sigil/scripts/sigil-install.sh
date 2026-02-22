#!/usr/bin/env bash
# sigil-install.sh — Install the sigil-scan CLI binary
# Run: bash sigil-install.sh

set -e

BINARY="sigil-scan"
INSTALL_DIR="${SIGIL_INSTALL_DIR:-$HOME/.local/bin}"
REGISTRY="${SIGIL_REGISTRY_URL:-https://registry.sigil-protocol.org}"
AUDIT_LOG="${SIGIL_AUDIT_LOG:-$HOME/.sigil/audit.jsonl}"

echo "🔐 SIGIL installer"
echo "  Binary: $INSTALL_DIR/$BINARY"
echo "  Registry: $REGISTRY"
echo ""

# Check if cargo is available (Rust installation)
if command -v cargo &>/dev/null; then
    echo "→ Installing via cargo..."
    cargo install sigil-protocol --features=cli --bin sigil-scan
    echo "✅ sigil-scan installed (cargo)"
else
    # Fallback: pre-built binary from GitHub releases
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="x86_64" ;;
        arm64|aarch64) ARCH="aarch64" ;;
        *) echo "❌ Unsupported architecture: $ARCH" && exit 1 ;;
    esac

    RELEASE_URL="https://github.com/sigil-eu/sigil/releases/latest/download/sigil-scan-${OS}-${ARCH}.tar.gz"
    echo "→ Downloading pre-built binary: $RELEASE_URL"
    mkdir -p "$INSTALL_DIR"
    curl -fsSL "$RELEASE_URL" | tar -xz -C "$INSTALL_DIR" "$BINARY"
    chmod +x "$INSTALL_DIR/$BINARY"
    echo "✅ sigil-scan installed at $INSTALL_DIR/$BINARY"
fi

# Create default config dir
mkdir -p "$(dirname "$AUDIT_LOG")"
touch "$AUDIT_LOG"

echo ""
echo "→ Verifying install..."
if command -v sigil-scan &>/dev/null; then
    sigil-scan --version
    echo ""
    echo "→ Fetching latest pattern bundle (43 patterns)..."
    sigil-scan patterns update
    echo ""
    echo "✅ SIGIL is ready. Quick test:"
    echo '   sigil-scan check '"'"'{"key":"AKIAIOSFODNN7EXAMPLE"}'"'"''
else
    echo "⚠️  sigil-scan not in PATH. Add $INSTALL_DIR to your PATH:"
    echo "   export PATH=\"\$PATH:$INSTALL_DIR\""
fi

echo ""
echo "📄 Audit log: $AUDIT_LOG"
echo "🌐 Registry: $REGISTRY"
echo "📖 Docs: https://sigil-protocol.org"
