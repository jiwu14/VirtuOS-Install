# VirtuOS-Install
Sources required to build [VirtuOS](http://people.cs.vt.edu/~rnikola/?page_id=260) on Alpine Linux 2.3.6

The scripts assume that the user has already installed the <b>alpine-desktop</b> package, setup a regular user account with <b>sudo</b> privileges, and executes the scripts in their location.

All of the scripts except the creation of disk images are wrapped by a <b>runAll.sh</b> script for ease of execution. This will bring the user up to the point of calling the disk image script and creating Xen guests after rebooting the machine.
