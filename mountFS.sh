#####################################################################
# Mounting the additional Components
echo "[VirtuOS] - mount --bind /* to /usr/sclib/* "
sudo mount --bind /dev /usr/sclib/dev
sudo mount --bind /home /usr/sclib/home
sudo mount --bind /root /usr/sclib/root
sudo mount --bind /run /usr/sclib/run
sudo mount --bind /tmp /usr/sclib/tmp
sudo mount --bind /media /usr/sclib/media
sudo mount --bind /sys /usr/sclib/sys
sudo mount --bind /proc /usr/sclib/proc
sudo mount --bind /var /usr/sclib/var

