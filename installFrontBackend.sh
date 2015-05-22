#####################################################################
# Set Virtuous home directory
VIRTUOS_HOME=$PWD/VirtuOS-master
echo $VIRTUOS_HOME
cd $VIRTUOS_HOME
# Installing the VirtOS Xen Drivers
echo "[VirtuOS] - Installing the VirtuOS Frontend Driver"
cd source/syscall-frontend; make CC="gcc -fno-pic -fno-pie"; cd $VIRTUOS_HOME

echo "[VirtuOS] - Installing the VirtuOS Backend Network Driver"
cd source/syscall-backend/network; make CC="gcc -fno-pic -fno-pie"; cd $VIRTUOS_HOME

echo "[VirtuOS] - Installing the VirtuOS Backend Storage Driver"
cd source/syscall-backend/storage; make CC="gcc -fno-pic -fno-pie"; cd $VIRTUOS_HOME

