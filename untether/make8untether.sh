#!/bin/bash

set -x

sudo rm BUILD/daibutsu

gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS9.2.sdk -arch armv7 sock_port_2_legacy/*.c untether32.c -o untether32 -framework IOKit -std=gnu99 -fno-stack-protector -Os

strip untether32
ldid -Sent.xml untether32
sudo cp -a untether32 BUILD/daibutsu
sudo chown 0:0 BUILD/daibutsu
