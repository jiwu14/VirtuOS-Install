# Set Virtuous home directory
VIRTUOS_HOME=$PWD/VirtuOS-master
echo $VIRTUOS_HOME
cd $VIRTUOS_HOME

#####################################################################
# Installing the uclib
echo "[VirtuOS] - Compiling and Installing Patched uclib"
cd source/virtuos-uclibc
make menuconfig; make clean; make; sudo make PREFIX=/usr/sclib install
cd $VIRTUOS_HOME
#####################################################################
# Installing libaio
echo "[VirtuOS] - Compiling and Installing Patched libaio"
cd source/virtuos-libaio
make clean; make; sudo make PREFIX=/usr/sclib install
cd $VIRTUOS_HOME
#####################################################################
# Installing Syscall utilities
echo "[VirtuOS] - Compiling and Installing System Call Utilities"
cd source/syscall-utils; make clean; make; sudo make install; cd $VIRTUOS_HOME
#####################################################################
