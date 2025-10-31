## RAOP player and library (AirPlay)

Modified version of cliraop/raop-play for Music Assistant.

Based on libraop by philippe44 (all rights reserved). See upstream repo for more info.

## Building

**IMPORTANT:** Always use `STATIC=1` to statically link OpenSSL from crosstools. This ensures the binary is self-contained and doesn't depend on system OpenSSL libraries.

```sh
apt-get update
apt-get install -y build-essential cmake  libssl-dev
git clone https://github.com/music-assistant/libraop.git
cd libraop
git submodule update --init

# Build for Linux aarch64 (ALWAYS use STATIC=1!)
make HOST=linux PLATFORM=aarch64 STATIC=1 -j4

# Build for macOS ARM64 (ALWAYS use STATIC=1!)
make HOST=macos PLATFORM=arm64 STATIC=1 -j4
```

### Development Workflow

When working on the code and testing changes:

```sh
# Clean previous build
make clean

# Rebuild with static OpenSSL (REQUIRED)
make HOST=macos PLATFORM=arm64 STATIC=1 -j4

# Test the binary
./bin/cliraop-macos-arm64 -pair <device_ip>
```

**Common Mistakes:**
- ❌ `make` without `STATIC=1` - will link against system OpenSSL (broken)
- ❌ `CC=cc make HOST=macos PLATFORM=arm64` - will link against system OpenSSL (broken)
- ✅ `make HOST=macos PLATFORM=arm64 STATIC=1` - correct way with static OpenSSL
