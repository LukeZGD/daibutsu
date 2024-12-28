#!/bin/sh
./make.sh
cp -R BUILD tmp
sudo tar -xvf everuntether.tar -C tmp
sudo rm -r .DS_Store
sudo rm -r */.DS_Store
sudo rm -r */*/.DS_Store
sudo rm -r */*/*/.DS_Store
sudo rm -r */*/*/*/.DS_Store
sudo rm -r */*/*/*/*/.DS_Store
sudo rm -r */*/*/*/*/*/.DS_Store
sudo cp everuntether tmp
sudo chown 0:0 tmp/everuntether
dpkg-deb --build -Zgzip tmp everuntether.deb
sudo rm -r everuntether tmp
