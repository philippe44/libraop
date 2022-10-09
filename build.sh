#!/bin/bash

list="x86_64-linux-gnu-gcc x86-linux-gnu-gcc arm-linux-gnueabi-gcc aarch64-linux-gnu-gcc sparc64-linux-gnu-gcc mips-linux-gnu-gcc powerpc-linux-gnu-gcc"
declare -A alias=( [x86-linux-gnu-gcc]=i686-linux-gnu-gcc )
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

if [[ -n $clean ]]; then
	action="cleanlib"
else
	action="lib"	
fi

item = raop
declare -a headers=( raop_client.h )

# then iterate selected platforms/compilers
for cc in ${compilers[@]}
do
	IFS=- read -r platform host dummy <<< $cc
	
	export CFLAGS=${cflags[$cc]}
	
	target=targets/$host/$platform	
	mkdir -p targets/include	
	mkdir -p $target
	pwd=$(pwd)
	
	make CC=${alias[$cc]:-$cc} PLATFORM=$platform $action

	if [[ -z $clean ]]; then
		cp lib/$host/$platform/lib$item.a $target		
		cp -u src/raop_client.h targets/include
			rm -f $target/lib$item.a
		fi	
	done	
done
