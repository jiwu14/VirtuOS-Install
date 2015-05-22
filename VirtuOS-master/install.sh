#!/bin/bash
# Author: Benjamin James Wright <bwright@cse.unsw.edu.au>
# Description: This will build the VirtuOS operating system from scratch.
# This is a bit of a lengthy build process, it involves a patched linux kernel,
# a patched hypervisor, and a patch uclib. However this should all work. This
# assumes you are running alpine linux (latest version) and should
# theoretically be architecture independent.

# Create the Alpine Package Building System
echo "[VirtuOS] - Installing the required packages"
apk update
apk add alpine-sdk git gcc make curl

echo "[VirtuOS] - Creating a builder user to build the required packages"
adduser builder
echo "builder ALL=(ALL) ALL" >> /etc/sudoers

echo "[VirtuOS] - Assigning Privillages to the builder user"
su builder
sudo mkdir -p /var/cache/distfiles
sudo chmod a+w /var/cache/distfiles

echo "[VirtuOS] - Downloading github.com/bwright/VirtuOS.git"
curl -L --insecure https://github.com/bwright/VirtuOS/archive/master.zip > master.zip
unzip master.zip

# Set Virtuous home directory
VIRTUOS_HOME=$(pwd)/VirtuOS
cd $VIRTOUS_HOME

#####################################################################
# Installing the Virtuos Headers
echo "[VirtuOS] - Installing VirtuOS Patched Linux Headers 3.2.30"
cd packages/virtuos-linux-headers ; abuild -r; cd $VIRTUOS_HOME
#####################################################################
# Installing the Virtuos Kernel
echo "[VirtuOS] - Installing VirtuOS Patched Linux Kernel 3.2.30"
cd packages/virtuos-linux; abuild -r; cd $VIRTUOS_HOME
#####################################################################
# Installing the Virtuos Xen Hypervisor
echo "[VirtuOS] - Installing the VirtuOS Patched Xen Hypervisor Xen 4.2.0"
cd packages/virtuos-xen; abuild -r; cd $VIRTOUS_HOME
#####################################################################
# Installing the VirtOS Xen Drivers
echo "[VirtuOS] - Installing the VirtuOS Frontend Driver"
cd source/syscall-frontend; make; cd $VIRTOUS_HOME

echo "[VirtuOS] - Installing the VirtuOS Backend Network Driver"
cd source/syscall-backend/network; make; cd $VIRTOUS_HOME

echo "[VirtuOS] - Installing the VirtuOS Backend Storage Driver"
cd source/syscall-backend/storage; make; cd $VIRTOUS_HOME
#####################################################################
# Mounting the additional Components
echo "[VirtuOS] - mount --bind /* to /usr/sclib/* "
mount --bind /dev /usr/sclib/dev
mount --bind /home /usr/sclib/home
mount --bind /root /usr/sclib/root
mount --bind /run /usr/sclib/run
mount --bind /tmp /usr/sclib/tmp
mount --bind /media /usr/sclib/media
mount --bind /sys /usr/sclib/sys
mount --bind /proc /usr/sclib/proc
mount --bind /var /usr/sclib/var
#####################################################################
# Installing the uclib
echo "[VirtuOS] - Compiling and Installing Patched uclib"
cd source/virtous-uclib
make menuconfig; make; sudo make PREFIX=/usr/sclib install
cd $VIRTOUS_HOME
#####################################################################
# Installing libaio
echo "[VirtuOS] - Compiling and Installing Patched libaio"
cd source/virtous-libaio
make; sudo make PREFIX=/usr/sclib/usr install
cd $VIRTOUS_HOME
#####################################################################
# Installing Syscall utilities
echo "[VirtuOS] - Compiling and Installing System Call Utilities"
cd source/syscall-utils/storage; make; sudo make install; cd $VIRTOUS_HOME
#####################################################################
