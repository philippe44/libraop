#!/bin/bash

list="x86_64-linux-gnu-gcc x86-linux-gnu-gcc arm-linux-gnueabi-gcc aarch64-linux-gnu-gcc sparc64-linux-gnu-gcc mips-linux-gnu-gcc powerpc-linux-gnu-gcc x86_64-macos-darwin-gcc"
declare -A alias=( [x86-linux-gnu-gcc]=i686-linux-gnu-gcc [x86_64-macos-darwin-gcc]=x86_64-apple-darwin19-gcc )
declare -A cflags=( [sparc64-linux-gnu-gcc]="-mcpu=v7" [mips-linux-gnu-gcc]="-march=mips32" [powerpc-linux-gnu-gcc]="-m32")
declare -a compilers

IFS= read -ra candidates <<< "$list"

# do we have "clean" somewhere in parameters (assuming no compiler has "clean" in it...
if [[ $@[*]} =~ clean ]]; then
	clean="clean"
fi	

# first select platforms/compilers
for cc in ${candidates[@]}
do
	# check compiler first
	if ! command -v ${alias[$cc]:-$cc} &> /dev/null; then
		continue
	fi
	
	if [[ $# == 0 || ($# == 1 && -n $clean) ]]; then
		compilers+=($cc)
		continue
	fi

	for arg in $@
	do
		if [[ $cc =~ $arg ]]; then 
			compilers+=($cc)
		fi
	done
done

# do we want library only (can be used to rebuild as a submodule and not mess us bin/ directory)
if [[ $@[*]} =~ --libonly ]]; then
	if [[ -n $clean ]]; then
		action="cleanlib"
	else
		action="lib"	
	fi	
else
	action=$clean	
fi	

item=raop

# then iterate selected platforms/compilers
for cc in ${compilers[@]}
do
	IFS=- read -r platform host dummy <<< $cc
	
	export CFLAGS=${cflags[$cc]}
	CC=${alias[$cc]:-$cc}
	
	target=targets/$host/$platform	
	mkdir -p targets/include	
	mkdir -p $target
	pwd=$(pwd)
	
	make AR=${CC%-*}-ar CC=$CC STATIC=1 PLATFORM=$platform HOST=$host $action

	if [[ -z $clean ]]; then
		cp lib/$host/$platform/lib$item.a $target		
		cp -u src/raop_client.h targets/include
		cp -u src/raop_server.h targets/include
		cp -u src/raop_streamer.h targets/include
	else	
		rm -f $target/lib$item.a
	fi	
done
