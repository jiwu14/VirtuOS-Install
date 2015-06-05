#run this script to setup Xen modules to autostart
#after all installation scripts
sudo sh -c "echo 'xen_netback' >> /etc/modules"
sudo sh -c "echo 'xen_blkback' >> /etc/modules"
sudo sh -c "echo 'tun' >> /etc/modules"

sudo rc-update add udev sysinit
sudo rc-update add udev-postmount
sudo rc-update add xend

echo
echo "dom0_mem=2048M"
echo "gnttab_max_nr_frames=8192"
read -p "Please edit /boot/extlinux.conf with the Xen options above after 'xen.gz'.\nPress any key to continue..."
read -p "Press any key to reboot..."

sudo reboot
