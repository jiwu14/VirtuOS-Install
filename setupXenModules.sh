#run this script to setup Xen modules to autostart
#after all installation scripts
sudo sh -c "echo 'xen_netback' >> /etc/modules"
sudo sh -c "echo 'xen_blkback' >> /etc/modules"
sudo sh -c "echo 'tun' >> /etc/modules"

sudo rc-update add udev sysinit
sudo rc-update add udev-postmount
sudo rc-update add xend
sudo reboot
