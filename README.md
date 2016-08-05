# RAOP-Player
RAOP player and library (AirPlay)

This is a RAOP (airplay) player and library for the v2 protocol (with synchro). It works for Windows, OSX, Linux x86 and ARM. 
There is a small player can can play raw pcm form any file or stdin (useful for use pipes with a decoder like lame, flac or ffmpeg)
The player is just and example, the rest is a library that can be integrated in any application
Makesfiles are provided for OSX, Linux (x86 and ARM). Under Windows, I use Embarcadero C++, so I don't use makefile
You need pthread for Windows to recompile the player / use the library
It's largely inspired from https://github.com/chevil/raop2_play but limit the playback to pcm as it focuse on creating a library and optimizing AirPlay synchronization 
