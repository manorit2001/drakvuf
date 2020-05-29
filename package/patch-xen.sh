#!/bin/bash

grep -q 'source/configure --enable-xen --target-list=i386-softmmu' 'tools/Makefile'

if [ $? -ne 0 ]
then
    echo 'Failed to patch Xen tools/Makefile'
    exit 1
fi

echo 'Patched qemu to include --disable-sdl option'
sed -i 's#source/configure --enable-xen --target-list=i386-softmmu#source/configure --enable-xen --target-list=i386-softmmu --disable-sdl#g' tools/Makefile

DISTRIBUTION=$(lsb_release -cs)

if [ "$DISTRIBUTION" = "focal" ]
then
    # until we bump Xen, we need to avoid -Werror in qemu
    echo 'Patching tools/Makefile to add --disable-werror'
    sed -i 's#--disable-guest-agent #--disable-guest-agent --disable-werror #g' tools/Makefile

    if [ $? -ne 0 ]
    then
        echo 'Failed to patch tools/Makefile to add --disable-werror'
        exit 1
    fi
fi

