# Set Virtuous home directory
VIRTUOS_HOME=$PWD/VirtuOS-master
YAJL_HOME=$PWD/yajl
echo $VIRTUOS_HOME
cd $VIRTUOS_HOME
# Create/update repo with APK's
# Please make sure /repo/ is added in
# /etc/apk/repositories
sudo mkdir -p /repo
sudo mkdir -p /repo/x86_64
sudo cp $YAJL_HOME/*.apk /repo/x86_64
sudo cp $VIRTUOS_HOME/packages/*/*.apk /repo/x86_64
sudo apk index -o /repo/x86_64/APKINDEX.untrusted.tar.gz /repo/x86_64/*.apk
sudo cp /repo/x86_64/APKINDEX.untrusted.tar.gz /repo/x86_64/APKINDEX.tar.gz
sudo apk update --allow-untrusted
sudo apk add $@ --allow-untrusted
