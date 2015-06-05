dd if=/dev/zero of=/usr/StorageDomain.img bs=1024k seek=5120 count=0
mkfs.ext4 /usr/StorageDomain.img
mkdir /tmp/loop
sudo mount -o loop /usr/StorageDomain.img /tmp/loop
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
cp /usr/StorageDomain.img /usr/NetworkDomain.img
