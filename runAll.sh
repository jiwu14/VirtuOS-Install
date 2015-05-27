#Eric Johnson, Sam Wu

sh runOnceFirst.sh
sh installAPKS.sh
sh updateFromRepo.sh linux-vanilla=3.2.30-r0 linux-vanilla-dev=3.2.30-r0 linux-headers=3.2.30-r0 xen=4.2.0-r1 xen-dev=4.2.0-r1
sh makeFS.sh
sh installLibs.sh
sh installFrontBackend.sh
sh setupXenModules.sh
