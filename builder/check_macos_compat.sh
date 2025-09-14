#!/usr/bin/env bash

# macOS compatibility check script for eCapture Android cross-compilation

set -e

echo "eCapture macOS Compatibility Checker"
echo "====================================="
echo ""

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "❌ Error: This system is not macOS"
    echo "   Detected: $(uname)"
    exit 1
fi

echo "✅ Running on macOS"

# Check macOS version
MACOS_VERSION=$(sw_vers -productVersion)
MACOS_MAJOR=$(echo $MACOS_VERSION | cut -d. -f1)
MACOS_MINOR=$(echo $MACOS_VERSION | cut -d. -f2)

echo "📱 macOS Version: $MACOS_VERSION"

if [ "$MACOS_MAJOR" -lt 11 ]; then
    echo "⚠️  Warning: macOS 11.0+ recommended for best compatibility"
    echo "   Current version: $MACOS_VERSION"
fi

# Check architecture
ARCH=$(uname -m)
echo "🏗️  Architecture: $ARCH"

if [[ "$ARCH" == "arm64" ]]; then
    echo "✅ Apple Silicon detected - optimal for cross-compilation"
elif [[ "$ARCH" == "x86_64" ]]; then
    echo "✅ Intel Mac detected - compatible"
else
    echo "⚠️  Warning: Unknown architecture: $ARCH"
fi

# Check Homebrew
if command -v brew >/dev/null 2>&1; then
    BREW_VERSION=$(brew --version | head -1)
    echo "✅ Homebrew installed: $BREW_VERSION"
else
    echo "❌ Homebrew not found"
    echo "   Install from: https://brew.sh/"
    exit 1
fi

# Check Xcode Command Line Tools
if xcode-select --print-path >/dev/null 2>&1; then
    echo "✅ Xcode Command Line Tools installed"
else
    echo "❌ Xcode Command Line Tools not found"
    echo "   Install with: xcode-select --install"
    exit 1
fi

# Check required tools
echo ""
echo "Checking required tools..."

check_tool() {
    local tool=$1
    local package=$2

    if command -v $tool >/dev/null 2>&1; then
        local version=$($tool --version 2>&1 | head -1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1 || echo "unknown")
        echo "✅ $tool: $version"
        return 0
    else
        echo "❌ $tool not found"
        if [ -n "$package" ]; then
            echo "   Install with: brew install $package"
        fi
        return 1
    fi
}

MISSING_TOOLS=0

check_tool "clang" "llvm" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "go" "golang" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "cmake" "cmake" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "pkg-config" "pkgconfig" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "git" "git" || MISSING_TOOLS=$((MISSING_TOOLS + 1))

# Check specific version requirements
if command -v clang >/dev/null 2>&1; then
    CLANG_VERSION=$(clang --version | head -1 | grep -o '[0-9]\+' | head -1)
    if [ "$CLANG_VERSION" -lt 9 ]; then
        echo "⚠️  Warning: Clang $CLANG_VERSION < 9.0 (recommended minimum)"
        MISSING_TOOLS=$((MISSING_TOOLS + 1))
    fi
fi

if command -v go >/dev/null 2>&1; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//g')
    GO_MAJOR=$(echo $GO_VERSION | cut -d. -f1)
    GO_MINOR=$(echo $GO_VERSION | cut -d. -f2)
    if [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 21 ]; then
        echo "⚠️  Warning: Go $GO_VERSION < 1.21 (recommended minimum)"
        MISSING_TOOLS=$((MISSING_TOOLS + 1))
    fi
fi

echo ""

# Check disk space
AVAILABLE_SPACE=$(df -h . | awk 'NR==2 {print $4}' | sed 's/G.*//')
if [ "$AVAILABLE_SPACE" -lt 8 ]; then
    echo "⚠️  Warning: Low disk space ($AVAILABLE_SPACE GB available, 8GB recommended)"
fi

# Summary
echo "Summary:"
echo "======="

if [ $MISSING_TOOLS -eq 0 ]; then
    echo "✅ System is ready for eCapture Android cross-compilation"
    echo ""
    echo "Next steps:"
    echo "1. Run: make macos-setup"
    echo "2. Run: source android_build_env.sh"
    echo "3. Run: make android"
    exit 0
else
    echo "❌ $MISSING_TOOLS issues found - please resolve before proceeding"
    echo ""
    echo "To install all dependencies at once:"
    echo "brew install llvm clang cmake golang pkgconfig libelf curl wget git"
    exit 1
fi