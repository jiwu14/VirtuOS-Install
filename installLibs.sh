# Set Virtuous home directory
VIRTUOS_HOME=$PWD/VirtuOS-master
echo $VIRTUOS_HOME
cd $VIRTUOS_HOME

# Ensure copies made for /usr/sclib
sudo mkdir -p /usr/sclib
sudo mkdir -p /usr/sclib/dev
sudo mkdir -p /usr/sclib/home
sudo mkdir -p /usr/sclib/root
sudo mkdir -p /usr/sclib/run
sudo mkdir -p /usr/sclib/tmp
sudo mkdir -p /usr/sclib/media
sudo mkdir -p /usr/sclib/sys
sudo mkdir -p /usr/sclib/proc
sudo mkdir -p /usr/sclib/var
sudo mkdir -p /usr/sclib/usr
sudo cp -r /bin /usr/sclib/bin
sudo cp -r /lib /usr/sclib/lib
sudo cp -r /etc /usr/sclib/etc
sudo cp -r /sbin /usr/sclib/sbin
sudo cp -r /usr/bin /usr/sclib/usr
sudo cp -r /usr/etc /usr/sclib/usr
sudo cp -r /usr/include /usr/sclib/usr
sudo cp -r /usr/info /usr/sclib/usr
sudo cp -r /usr/lib /usr/sclib/usr
sudo cp -r /usr/local /usr/sclib/usr
sudo cp -r /usr/man /usr/sclib/usr
sudo cp -r /usr/sbin /usr/sclib/usr
sudo cp -r /usr/share /usr/sclib/usr
sudo cp -r /usr/src /usr/sclib/usr
sudo cp -r /usr/var /usr/sclib/usr
sudo cp -r /usr/x86_64-alpine-linux-uclibc /usr/sclib/usr

#####################################################################
# Installing the uclib
echo "[VirtuOS] - Compiling and Installing Patched uclib"
cd source/virtuos-uclibc
make menuconfig; make; sudo make CC="gcc -fno-pic -fno-pie" PREFIX=/usr/sclib install
cd $VIRTUOS_HOME
#####################################################################
# Installing libaio
echo "[VirtuOS] - Compiling and Installing Patched libaio"
cd source/virtuos-libaio
make; sudo make PREFIX=/usr/sclib/usr install
cd $VIRTUOS_HOME
#####################################################################
# Installing Syscall utilities
echo "[VirtuOS] - Compiling and Installing System Call Utilities"
cd source/syscall-utils; make; sudo make install; cd $VIRTUOS_HOME
#####################################################################
