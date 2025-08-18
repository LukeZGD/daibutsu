#!/bin/bash

#if [[ -z 1 ]]; then
rm -rf output
mkdir output

gcc -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk -DUNTETHER -arch armv7 daibutsu/*.c oob_entry/*.c -o everuntether -framework IOKit -framework CoreFoundation -std=gnu99 -fno-stack-protector -Os

strip everuntether
ldid -Sent.xml everuntether
mv everuntether output
#fi

rm -f output/everuntether*.deb output/*untether.tar

mkdir -p tmp/DEBIAN tmp/var
cp control tmp/DEBIAN
cp BUILD/DEBIAN/prerm tmp/DEBIAN
printf '#!/bin/bash\n[[ $1 != "abort"* ]] && rm -f /everuntether && mv /var/everuntether /' > tmp/DEBIAN/postinst
chmod +x tmp/DEBIAN/postinst
cp output/everuntether tmp/var
sudo chown -R 0:0 tmp
dpkg-deb --build -Zgzip tmp everuntether-bin.deb
mv everuntether-bin.deb output
sudo rm -r tmp

cp -R BUILD tmp
sudo tar -xvf template.tar -C tmp
sudo rm -rf .DS_Store
sudo rm -rf */.DS_Store
sudo rm -rf */*/.DS_Store
sudo rm -rf */*/*/.DS_Store
sudo rm -rf */*/*/*/.DS_Store
sudo rm -rf */*/*/*/*/.DS_Store
sudo rm -rf */*/*/*/*/*/.DS_Store
dpkg-deb --build -Zgzip tmp everuntether.deb
mv everuntether.deb output
sudo rm -rf tmp/DEBIAN
sudo mkdir -p tmp/private/var/root/Media/Cydia/AutoInstall
sudo mv tmp/etc tmp/private
sudo cp output/everuntether*.deb tmp/private/var/root/Media/Cydia/AutoInstall
sudo cp output/everuntether tmp/everuntether
tar -cvf output/everuntether.tar -C tmp .
sudo rm -r tmp

cp -R BUILD2 tmp
sudo chown -R 0:0 tmp
sudo mkdir -p tmp/private/var/root/Media/Cydia/AutoInstall tmp/private/var/tmp tmp/taig
sudo touch tmp/taig/taig
sudo chmod 777 tmp/private
sudo chmod 777 tmp/private/var
sudo chmod 1777 tmp/private/var/tmp
sudo cp postinst tmp/private/var/tmp
sudo cp output/everuntether-bin.deb tmp/private/var/root/Media/Cydia/AutoInstall
sudo cp output/everuntether tmp/everuntether
sudo ln -s /everuntether tmp/usr/libexec/CrashHousekeeping
tar -cvf output/untether.tar -C tmp .
sudo rm -r tmp
