
1. [Required Tools and Libraries.](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#compilation-of-the-dpdk)
===============================
* General development tools including a supported C compiler such as gcc (version 4.9+) or clang (version 3.4+).
    * For RHEL/Fedora systems these can be installed using.
        * $dnf groupinstall "Development Tools"
    * For Ubuntu/Debian systems these can be installed using
            $apt install build-essential
    * For Alpine Linux,
        * &apk add gcc libc-dev bsd-compat-headers libexecinfo-dev
* Python 3.5 or later.
    * Meson (version 0.49.2+) and ninja
        * $meson & ninja-build packages in most Linux distributions
    * If the packaged version is below the minimum version, the latest versions can be installed from Python’s “pip” repository: 
        * $pip3 install meson ninja
* pyelftools (version 0.22+)
    * For Fedora systems it can be installed using 
        * $dnf install python-pyelftools
    * For RHEL/CentOS systems it can be installed using 
        * $pip3 install pyelftools
    * For Ubuntu/Debian it can be installed using 
        * &apt install python3-pyelftools
    * For Alpine Linux, 
        * &apk add py3-elftools
* Library for handling NUMA (Non Uniform Memory Access).
    * numactl-devel in RHEL/Fedora;
    * libnuma-dev in Debian/Ubuntu;
    * numactl-dev in Alpine Linux;
2. Build libraries, drivers and test applications. [refer to](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html)
==================================================
    * $meson build
    * $cd build
    * $ninja
    * $ninja install
    * $ldconfig 

    To include the examples as part of the build, replace the meson command with:
    * $meson -Dexamples=all build
    * rebuild the library
        * $meson build --wipe

* Issue was facing
    * could not run the cmd $sudo ninja -C build install
    * solution : $sudo cp /home/quangnt/.local/bin/ninja /usr/bin/

* Example Bind a nic card to 201 server using the dpdk-devbind tool. [refer to](http://doc.dpdk.org/guides/linux_gsg/linux_drivers.html)
    * Load uio_pci_generic
        * $sudo modprobe uio_pci_generic
    * List all of nic cards
        * $./dpdk-devbind.py --status
    * bind 0000:06:00.0 to DPDK
        * $./dpdk-devbind.py --bind=uio_pci_generic 0000:06:00.0
     * bind 0000:06:00.1 to DPDK
        * $./dpdk-devbind.py --bind=uio_pci_generic 0000:06:00.1

* Configuration the Hugepage using the dpdk-hugpages.py tool [refer to](http://doc.dpdk.org/guides/tools/hugepages.html)
    * To display current huge page settings:
        * $./dpdk-hugpages.py -s
    * To a complete setup of with 2 Gigabyte of 1G huge pages:
        * $./dpdk-hugpages.py -p 1G --setup 2G

* link for application sample - [click here](https://github.com/czivar/ruru)
    * [link1](https://docs.openvswitch.org/en/latest/intro/install/dpdk/)
    * [link2](https://docs.openvswitch.org/en/latest/topics/dpdk/phy/)
        * $driverctl set-override 0000:03:00.3 uio_pci_generic
        * $sudo ./dpdk-devbind.py --bind=uio_pci_generic 0000:03:00.3

* [Installing DPDK Using the meson build system](https://doc.dpdk.org/guides/prog_guide/build-sdk-meson.html)
* [Running the Application](https://doc.dpdk.org/guides/testpmd_app_ug/run_app.html)
* [Testpmd Runtime Functions](https://doc.dpdk.org/guides/testpmd_app_ug/testpmd_funcs.html) [Doc](https://www.intel.com/content/dam/www/public/us/en/documents/guides/dpdk-testpmd-application-user-guide.pdf)