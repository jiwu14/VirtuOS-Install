# Set Virtuous home directory
VIRTUOS_HOME=$PWD/VirtuOS-master
echo $VIRTUOS_HOME
cd $VIRTUOS_HOME

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
