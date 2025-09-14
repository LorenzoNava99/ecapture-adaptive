#!/usr/bin/env bash

# macOS development environment initialization script for eCapture Android cross-compilation
# Usage: /bin/bash builder/init_macos_env.sh

set -e

echo "Welcome to eCapture project macOS development environment initialization script."
echo "This script will set up cross-compilation environment for Android ARM64 targets."
echo "Home page: https://ecapture.cc"
echo "Github: https://github.com/gojue/ecapture"
echo ""

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: This script is designed for macOS only."
    exit 1
fi

# Check if running on Apple Silicon
UNAME_M=$(uname -m)
if [[ "${UNAME_M}" != "arm64" ]]; then
    echo "Warning: This script is optimized for Apple Silicon Macs (arm64). Detected: ${UNAME_M}"
fi

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "Error: Homebrew is required but not installed."
    echo "Please install Homebrew first: https://brew.sh/"
    exit 1
fi

echo "Detected macOS $(sw_vers -productVersion) on ${UNAME_M}"

# Install required packages via Homebrew
echo "Installing required packages via Homebrew..."
# Note: clang comes with Xcode Command Line Tools, libelf not available on macOS
brew install llvm cmake golang pkgconfig curl wget git || {
    echo "Error: Failed to install required packages via Homebrew"
    exit 1
}

# Check LLVM/Clang version
CLANG_VERSION=$(clang --version | head -1 | grep -o '[0-9]\+' | head -1)
if [ "${CLANG_VERSION}" -lt 9 ]; then
    echo "Error: Clang version 9 or newer is required. Found: ${CLANG_VERSION}"
    exit 1
fi
echo "Clang version: ${CLANG_VERSION}"

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//g')
GO_VERSION_MAJ=$(echo ${GO_VERSION} | cut -d'.' -f1)
GO_VERSION_MIN=$(echo ${GO_VERSION} | cut -d'.' -f2)
if [ ${GO_VERSION_MAJ} -eq 1 ] && [ ${GO_VERSION_MIN} -lt 21 ]; then
    echo "Error: Go version 1.21 or newer is required. Found: ${GO_VERSION}"
    exit 1
fi
echo "Go version: ${GO_VERSION}"

# Set up Android NDK for cross-compilation
NDK_VERSION="27.2.12479018"
ANDROID_NDK_ROOT="${HOME}/android-ndk"
ANDROID_NDK_PATH="${ANDROID_NDK_ROOT}/android-ndk-r27c"

echo "Setting up Android NDK for cross-compilation..."
if [ ! -d "${ANDROID_NDK_PATH}" ]; then
    echo "Downloading Android NDK ${NDK_VERSION}..."
    mkdir -p "${ANDROID_NDK_ROOT}"
    cd "${ANDROID_NDK_ROOT}"

    # Download NDK for macOS
    NDK_ZIP="android-ndk-r27c-darwin.zip"
    wget "https://dl.google.com/android/repository/${NDK_ZIP}" || {
        echo "Error: Failed to download Android NDK"
        exit 1
    }

    echo "Extracting Android NDK..."
    unzip -q "${NDK_ZIP}" || {
        echo "Error: Failed to extract Android NDK"
        exit 1
    }

    rm "${NDK_ZIP}"
    echo "Android NDK installed to: ${ANDROID_NDK_PATH}"
else
    echo "Android NDK already exists at: ${ANDROID_NDK_PATH}"
fi

# Set up Linux kernel headers for Android cross-compilation
KERNEL_HEADERS_DIR="${HOME}/android-kernel-headers"
echo "Setting up kernel headers..."

if [ ! -d "${KERNEL_HEADERS_DIR}" ]; then
    echo "Cloning Android kernel headers..."
    git clone --depth=1 -b android-mainline https://android.googlesource.com/kernel/prebuilts/kernel-headers "${KERNEL_HEADERS_DIR}" || {
        echo "Warning: Failed to clone kernel headers from AOSP. Using generic headers."
        mkdir -p "${KERNEL_HEADERS_DIR}"

        # Create minimal kernel headers structure for eBPF compilation
        mkdir -p "${KERNEL_HEADERS_DIR}/include/linux"
        mkdir -p "${KERNEL_HEADERS_DIR}/include/asm"
        mkdir -p "${KERNEL_HEADERS_DIR}/include/uapi/linux"

        echo "Created minimal kernel headers structure"
    }
else
    echo "Kernel headers already exist at: ${KERNEL_HEADERS_DIR}"
fi

# Set up libpcap for static linking
LIBPCAP_DIR="${HOME}/libpcap-android"
echo "Setting up libpcap for Android..."

if [ ! -d "${LIBPCAP_DIR}" ]; then
    echo "Downloading and building libpcap for Android..."
    git clone https://github.com/the-tcpdump-group/libpcap.git "${LIBPCAP_DIR}" || {
        echo "Error: Failed to clone libpcap repository"
        exit 1
    }
else
    echo "libpcap directory already exists at: ${LIBPCAP_DIR}"
fi

# Create environment setup script
ENV_SCRIPT="${PWD}/android_build_env.sh"
cat > "${ENV_SCRIPT}" << 'EOF'
#!/bin/bash
# Android cross-compilation environment for eCapture

# Android NDK settings
export ANDROID_NDK_ROOT="${HOME}/android-ndk/android-ndk-r27c"
export ANDROID_API_LEVEL=29
export ANDROID_ARCH=aarch64
export ANDROID_TARGET=aarch64-linux-android

# Toolchain paths
export CC="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${ANDROID_TARGET}${ANDROID_API_LEVEL}-clang"
export CXX="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/bin/${ANDROID_TARGET}${ANDROID_API_LEVEL}-clang++"
export AR="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
export STRIP="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-strip"
export RANLIB="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ranlib"
export LD="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/darwin-x86_64/bin/ld"

# Build flags
export CFLAGS="-I${ANDROID_NDK_ROOT}/sysroot/usr/include -I${ANDROID_NDK_ROOT}/sysroot/usr/include/${ANDROID_TARGET}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="-L${ANDROID_NDK_ROOT}/platforms/android-${ANDROID_API_LEVEL}/arch-arm64/usr/lib"

# Kernel headers
export KERN_HEADERS="${HOME}/android-kernel-headers"
export ANDROID=1
export CROSS_ARCH=arm64
export TARGET_ARCH=aarch64
export GOARCH=arm64
export GOOS=android
export CGO_ENABLED=1

echo "Android cross-compilation environment loaded"
echo "CC: ${CC}"
echo "Target: ${ANDROID_TARGET}${ANDROID_API_LEVEL}"
echo "Arch: ${TARGET_ARCH}"
EOF

chmod +x "${ENV_SCRIPT}"

echo ""
echo "=========================================="
echo "macOS development environment setup completed!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Source the environment: source android_build_env.sh"
echo "2. Build libpcap for Android: make android-libpcap"
echo "3. Build eCapture for Android: make android"
echo ""
echo "Environment script created at: ${ENV_SCRIPT}"
echo ""
echo "To build for Android:"
echo "  source ${ENV_SCRIPT}"
echo "  make android"
echo ""
echo "Enjoy developing eCapture on macOS!"