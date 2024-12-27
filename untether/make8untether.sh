#!/bin/sh
#sudo rm BUILD/daibutsu

gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS9.2.sdk -DUNTETHER -arch armv7 untether32.c patchfinder.c sock_port_2_legacy/*.c -o everuntether -framework IOKit -std=gnu99 -fno-stack-protector -Os

strip everuntether
ldid -Sent.xml everuntether
#sudo cp -a everuntether BUILD/daibutsu
#sudo chown 0:0 BUILD/daibutsu
