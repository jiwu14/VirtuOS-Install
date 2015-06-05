IMG_PATH=/home/$USER
DOMAINS="StorageDomain NetworkDomain"

for domain in $DOMAINS
do
	echo
	echo "Creating disk image for $domain at /tmp..."
	dd if=/dev/zero of=/tmp/$domain.img bs=1024k seek=5120 count=0
	mkfs.ext4 /tmp/$domain.img
	mkdir -p /tmp/loop
	echo
	echo "Mounting $domain disk image..."
	sudo mount -o loop /tmp/$domain.img /tmp/loop
	echo
	echo "Copying host disk into $domain disk image..."
	sudo cp -a /bin /tmp/loop
	sudo cp -a /dev /tmp/loop
	sudo cp -a /etc /tmp/loop
	sudo cp -a /lib /tmp/loop
	sudo cp -a /root /tmp/loop
	sudo cp -a /sbin /tmp/loop
	sudo mkdir -p /tmp/loop/usr
	sudo cp -a /usr/bin /tmp/loop/usr
	sudo cp -a /usr/etc /tmp/loop/usr
	sudo cp -a /usr/include /tmp/loop/usr
	sudo cp -a /usr/info /tmp/loop/usr
	sudo cp -a /usr/lib /tmp/loop/usr
	sudo cp -a /usr/local /tmp/loop/usr
	sudo cp -a /usr/man /tmp/loop/usr
	sudo cp -a /usr/sbin /tmp/loop/usr
	sudo cp -a /usr/share /tmp/loop/usr
	sudo cp -a /usr/src /tmp/loop/usr
	sudo cp -a /usr/var /tmp/loop/usr
	sudo cp -a /usr/x86_64-alpine-linux-uclibc /tmp/loop/usr
	sudo cp -a /var /tmp/loop
	sudo cp -a /home /tmp/loop
	sudo mkdir /tmp/loop/proc
	sudo mkdir /tmp/loop/opt
	sudo mkdir /tmp/loop/sys
	sudo mkdir /tmp/loop/tmp
	sudo chmod 777 /tmp/loop/tmp
	echo
	echo "Copying custom fstab file into $domain disk image..."
	sudo cp hvmFstab /tmp/loop/etc/fstab
	echo
	echo "Unmounting $domain disk image..."
	sudo umount /tmp/loop
done
for domain in $DOMAINS
do
	echo
	echo "Moving $domain disk image to $IMG_PATH..."
	mv /tmp/$domain.img $IMG_PATH
done
echo
echo "Domain disk images stored at $IMG_PATH"
echo "Please change the HVM configuration files with the appropriate path to the images before continuing..."
read -p "Press enter to continue..."
