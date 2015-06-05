IMG_PATH=/home/$USER

echo "Creating disk image for domains..."
dd if=/dev/zero of=$IMG_PATH/StorageDomain.img bs=1024k seek=5120 count=0
mkfs.ext4 $IMG_PATH/StorageDomain.img
mkdir /tmp/loop
sudo mount -o loop $IMG_PATH/StorageDomain.img /tmp/loop
sudo cp -a /bin /tmp/loop
sudo cp -a /dev /tmp/loop
sudo cp -a /etc /tmp/loop
sudo cp -a /lib /tmp/loop
sudo cp -a /root /tmp/loop
sudo cp -a /sbin /tmp/loop
sudo cp -a /usr /tmp/loop
sudo cp -a /var /tmp/loop
sudo cp -a /home /tmp/loop
mkdir /tmp/loop/proc
mkdir /tmp/loop/opt
mkdir /tmp/loop/sys
mkdir /tmp/loop/tmp
sudo chmod 777 /tmp/loop/tmp
cp hvmFstab /tmp/loop/etc/fstab
sudo unmount /tmp/loop
cp $IMG_PATH/StorageDomain.img $IMG_PATH/NetworkDomain.img
echo "Domain disk images stored at $IMG_PATH"
echo "Please change the HVM configuration files with the appropriate path to the images before continuing..."
read -p "Press any key to continue..."
