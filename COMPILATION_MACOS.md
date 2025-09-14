# eCapture macOS Cross-compilation for Android

This document describes how to build eCapture on macOS for Android targets.

## Prerequisites

### System Requirements

- macOS 11.0 or later (Apple Silicon Mac recommended)
- Homebrew package manager
- Xcode Command Line Tools
- At least 8GB of free disk space

### Required Software

The setup script will install these automatically via Homebrew:

- LLVM/Clang 9.0 or newer
- Go 1.21 or newer
- CMake 3.18.4 or newer
- pkg-config
- libelf
- git, curl, wget

## Quick Start

### 1. Initial Setup

Run the macOS environment setup script:

```bash
make macos-setup
```

This will:
- Install required tools via Homebrew
- Download and setup Android NDK
- Clone Android kernel headers
- Prepare libpcap for cross-compilation
- Create build environment script

### 2. Load Build Environment

```bash
source android_build_env.sh
```

This sets up all necessary environment variables for cross-compilation.

### 3. Build for Android

```bash
make android
```

This will:
- Build libpcap for Android ARM64
- Compile eBPF programs for Android
- Build the eCapture binary for Android
- Output: `bin/ecapture-android`

## Manual Setup (Alternative)

If you prefer to set up manually:

### 1. Install Dependencies

```bash
brew install llvm clang cmake golang pkgconfig libelf curl wget git
```

### 2. Setup Android NDK

```bash
# Download Android NDK
export ANDROID_NDK_ROOT="$HOME/android-ndk/android-ndk-r27c"
mkdir -p "$HOME/android-ndk"
cd "$HOME/android-ndk"
wget https://dl.google.com/android/repository/android-ndk-r27c-darwin.zip
unzip android-ndk-r27c-darwin.zip
```

### 3. Setup Kernel Headers

```bash
# Clone Android kernel headers
git clone --depth=1 -b android-mainline \
  https://android.googlesource.com/kernel/prebuilts/kernel-headers \
  "$HOME/android-kernel-headers"
```

### 4. Set Environment Variables

```bash
export ANDROID_NDK_ROOT="$HOME/android-ndk/android-ndk-r27c"
export ANDROID_API_LEVEL=29
export ANDROID_TARGET=aarch64-linux-android
export KERN_HEADERS="$HOME/android-kernel-headers"
export ANDROID=1
export CROSS_ARCH=arm64
export TARGET_ARCH=aarch64
export GOARCH=arm64
export GOOS=android
export CGO_ENABLED=1
```

## Build Targets

### Available Targets

- `make macos-setup` - Setup macOS development environment
- `make android-libpcap` - Build libpcap for Android
- `make android` - Full Android build (recommended)
- `make build_android` - Build Android binary only
- `make clean-android` - Clean Android build artifacts
- `make help-android` - Show Android-specific help

### Build Configuration

The build system automatically detects macOS and configures:

- Cross-compilation toolchain from Android NDK
- Proper library paths and flags
- Android-specific eBPF compilation
- Static linking for Android deployment

## Deployment

### Transfer to Android Device

```bash
# Enable ADB and root access on your Android device
adb push bin/ecapture-android /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ecapture-android
```

### Running on Android

```bash
# Connect to device
adb shell
su  # Requires root access

# Run eCapture
cd /data/local/tmp
./ecapture-android --help
```

## Troubleshooting

### Common Issues

1. **Homebrew Installation Fails**
   ```bash
   # Install Homebrew first
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Android NDK Download Fails**
   - Check internet connection
   - Try downloading manually from https://developer.android.com/ndk/downloads

3. **Kernel Headers Not Found**
   ```bash
   export KERN_HEADERS="/path/to/your/kernel/headers"
   ```

4. **CGO Compilation Errors**
   - Ensure Android NDK is properly installed
   - Verify `android_build_env.sh` is sourced
   - Check that all paths in environment variables exist

5. **Permission Issues on Android**
   - Ensure device is rooted
   - Grant proper permissions: `chmod 755 ecapture-android`
   - Run with sufficient privileges

### Debug Information

Check your build environment:

```bash
make env
```

This will show all relevant variables and paths.

## Architecture Support

Currently supported for cross-compilation from macOS:

- **Host**: macOS (Darwin) ARM64 or x86_64
- **Target**: Android ARM64 (aarch64)
- **Android API**: Level 29+
- **Kernel**: Android GKI 5.5+

## Performance Notes

- Build time: ~10-15 minutes on Apple Silicon
- Binary size: ~15MB (statically linked)
- Runtime requirements: Android 10+ with root access

## Contributing

When contributing macOS-specific changes:

1. Test on both Apple Silicon and Intel Macs if possible
2. Ensure compatibility with multiple Homebrew versions
3. Verify Android NDK version compatibility
4. Update documentation for any new requirements

For issues specific to macOS builds, please include:

- macOS version (`sw_vers`)
- Xcode version (`xcode-select --version`)
- Homebrew version (`brew --version`)
- Build environment output (`make env`)