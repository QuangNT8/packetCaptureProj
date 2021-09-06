Prerequisites
-------------

DPDK <= 19
~~~~~~~~~~

You need to install and compile DPDK in your HOME directory as explained in
See http://core.dpdk.org/doc/quick-start/ for DPDK installation and setup

Once DPDK is built make sure to create a symbolic link:

$ cd ~ && ln -s dpdk-21.05 DPDK

so the build process will use the DPDK directory letting you have multiple
DPDK versions available on your system

DPDK >= 20
~~~~~~~~~~

Download dpdk:

$ tar xJf dpdk-<version>.tar.xz
$ cd dpdk-<version>

Build dpdk:

$ meson build
$ cd build
$ ninja

Install dpdk:

$ sudo ninja install
$ sudo ldconfig

Build goblin_dpdk:
    * for Centos : 
        * export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig
$ make

Run Application 
   
---------------
Supposing to capture packets from device enp7s0,wlp8s0 and generate the pcap file you can start the
Run on local
    $sudo ./build/testpcap -l 0-7 -n 8 -- --stats-perio=1 --i=wlp8s0,enp7s0
