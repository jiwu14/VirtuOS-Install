#!/bin/bash
# Author: Benjamin James Wright <bwright@cse.unsw.edu.au>
# Description: This will build the VirtuOS operating system from scratch.
# This is a bit of a lengthy build process, it involves a patched linux kernel,
# a patched hypervisor, and a patch uclib. However this should all work. This
# assumes you are running alpine linux (latest version) and should
# theoretically be architecture independent.

# Create the Alpine Package Building System
echo "[VirtuOS] - Installing the required packages"
sudo apk update
sudo apk add alpine-sdk git gcc make curl

sudo mkdir -p /var/cache/distfiles
sudo chmod a+w /var/cache/distfiles

#echo "[VirtuOS] - Downloading github.com/bwright/VirtuOS.git"
#curl -L --insecure https://github.com/bwright/VirtuOS/archive/master.zip > master.zip
#unzip master.zip

ORIG_HOME=$PWD

# Set Virtuous home directory
VIRTUOS_HOME=$PWD/VirtuOS-master
echo $VIRTUOS_HOME
cd $VIRTUOS_HOME

#####################################################################
# Installing yajl (Xen build depends on this)
echo "Installing yajl (xen dependency)"
cd packages/yajl; abuild -r
cd $ORIG_HOME; sh updateFromRepo.sh yajl yajl-dev yajl-tools
cd $VIRTUOS_HOME
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
cd packages/virtuos-xen; abuild -r; cd $VIRTUOS_HOME


