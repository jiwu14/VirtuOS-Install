#Eric Johnson, Sam Wu

#building requirements
sudo apk add alpine-sdk make
sudo abuild-keygen -ai

#local repo location
REPO_ADDED=`grep '^/repo/$' /etc/apk/repositories`
if [ -z $REPO_ADDED ];
then
   sudo echo "/repo/" >> /etc/apk/repositories
fi
