## RAOP player and library (AirPlay)

Modified version of cliraop/raop-play for Music Assistant.

Based on libraop by philippe44 (all rights reserved). See upstream repo for more info.

## Building

```sh
apt-get update
apt-get install -y build-essential cmake  libssl-dev
git clone https://github.com/music-assistant/libraop.git
cd libraop
git submodule update --init

# Build project for linux with static OpenSSL
make HOST=linux PLATFORM=aarch64 STATIC=1

# Build project for macOS with static OpenSSL
make HOST=macos PLATFORM=arm64 STATIC=1
```

**IMPORTANT:** Always use `STATIC=1` to statically link OpenSSL from crosstools. This ensures the binary is self-contained and doesn't depend on system OpenSSL libraries.
