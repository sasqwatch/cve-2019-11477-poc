# building a vulnerable kernel w/ debug info

```
$ # build dependencies
# apt-get install kernel-package flex libssl-dev libncurses5-dev fakeroot
$ # clone the linux kernel
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
$ cd linux/
$ git checkout v4.4.181 && git branch sack && git checkout sack
$ # apply patch
$ git apply sack-debug.diff
$ # configure the kernel as needed
$ make menuconfig
$ # build, adjust -j2 to match number of CPUs
$ fakeroot make-kpkg -j2 --initrd --revision 1.0.sack kernel_images
$ # install kernel
$ cd ../
# sudo dpkg -i linux-image-*.deb
$ reboot # select the 4.4.181 kernel when booting
``
