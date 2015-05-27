#Eric Johnson, Sam Wu

#building requirements
sudo apk add alpine-sdk make
sudo abuild-keygen -ai

#local repo location
REPO_ADDED=`grep '^/repo/$' /etc/apk/repositories`
if [ -z $REPO_ADDED ];
then
   sudo sh -c "echo '' >> /etc/apk/repositories"
   sudo sh -c "echo '/repo/' >> /etc/apk/repositories"
fi

#test if we already wrapped gcc
if [ ! -f /usr/bin/gcc_original ];
then
   sudo mv /usr/bin/gcc /usr/bin/gcc_original;
   printf "#!/bin/sh\nexec /usr/bin/gcc_original '\$@' '-mno-tls-direct-seg-refs'" | sudo tee /usr/bin/gcc > /dev/null
   sudo chmod +x /usr/bin/gcc;
fi
