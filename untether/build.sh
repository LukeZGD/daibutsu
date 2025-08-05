#!/bin/sh

rm -rf output
mkdir output

gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk -DUNTETHER -arch armv7 daibutsu/*.c oob_entry/*.c -o everuntether -framework IOKit -framework CoreFoundation -std=gnu99 -fno-stack-protector -Os

strip everuntether
ldid -Sent.xml everuntether
cp everuntether output

cp -R BUILD tmp
sudo tar -xvf template.tar -C tmp
sudo rm -rf .DS_Store
sudo rm -rf */.DS_Store
sudo rm -rf */*/.DS_Store
sudo rm -rf */*/*/.DS_Store
sudo rm -rf */*/*/*/.DS_Store
sudo rm -rf */*/*/*/*/.DS_Store
sudo rm -rf */*/*/*/*/*/.DS_Store
sudo mv everuntether tmp
sudo chown 0:0 tmp/everuntether
dpkg-deb --build -Zgzip tmp everuntether.deb
sudo rm -rf tmp/DEBIAN
cp everuntether.deb output
sudo mkdir -p tmp/private/var/root/Media/Cydia/AutoInstall
sudo mv tmp/etc tmp/private
sudo mv everuntether.deb tmp/private/var/root/Media/Cydia/AutoInstall
tar -cvf output/everuntether.tar -C tmp .

sudo rm -r tmp
