# RAOP-Player

RAOP player and library (AirPlay)

This is a RAOP (airplay) player and library for the v2 protocol (with synchro). It works for Windows, OSX, Linux x86 and ARM.
There is a small player can can play raw pcm form any file or stdin (useful for use pipes with a decoder like lame, flac or ffmpeg)

The player is just and example how to use the library, but it has a few interesting options:

```text
usage: ./build/raop_play <options> <server_ip> <filename ('-' for stdin)>
	[-ntp <file>] write current NTP in <file> and exit
	[-p <port number>]
	[-v <volume> (0-100)]
	[-l <latency> (frames]
	[-w <wait>]  (start after <wait> milliseconds)
	[-n <start>] (start at NTP <start> + <wait>)
	[-nf <start>] (start at NTP in <file> + <wait>)
	[-e] (encrypt)
	[-s <secret>] (valid secret for AppleTV)
	[-d <debug level>] (0 = silent)
	[-i] (interactive commands: 'p'=pause, 'r'=(re)start, 's'=stop, 'q'=exit, ' '=block)
```

It's possible to send synchronous audio to multiple players by using the NTP options (optionally combined with the wait option).
Either get the NTP of the master machine from any application and then fork multiple instances of raop_play with that NTP and
the same audio file, or use the -ntp option to get NTP to be written to a file and re-use that file when calling the instances of
raop_play

## Building using CMake

```sh
# Fetch all dependencies
git submodule update --init

# Build OpenSSL (if openssl version != 1.0)
cd vendor/openssl
./conf
make

# Create build directory
mkdir build
cd build

# Build project
cmake ..
# or cmake -DOPENSSL_ROOT_DIR=`pwd`/../vendor/openssl -DOPENSSL_INCLUDE_DIR=`pwd`/../vendor/openssl/include -DOPENSSL_LIBRARIES=`pwd`/../vendor/openssl ..

make
```

## Building using Make

Makefiles are provided for OSX, Linux (x86 and ARM). Under Windows, I use Embarcadero C++, so I don't use makefile. You need some libraires:

- ALAC codec: https://github.com/macosforge/alac and

- Curve25519 crypto: https://github.com/msotoodeh/curve25519

You need pthread for Windows to recompile the player / use the library here: https://www.sourceware.org/pthreads-win32

It's largely inspired from https://github.com/chevil/raop2_play but limit the playback to pcm as it focuses on creating a library and optimizing AirPlay synchronization

Since iOS 10.2, pairing is required with AppleTV. Here is a description of the protocol https://htmlpreview.github.io/?https://github.com/philippe44/RAOP-Player/blob/master/doc/auth_protocol.html
