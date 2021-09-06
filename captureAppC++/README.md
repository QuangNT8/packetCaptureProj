DPDK capture packet application
===============================

This application demonstrates PcapPlusPlus DPDK APIs. 

It listens to one or more DPDK Virtual Device (a.k.a DPDK devices), captures all traffic and matches packets by user-defined matching criteria such as source/dest IP, source/dest TCP/UDP port and more. 
Matched packets can be send to another DPDK port and/or be saved to a pcap file. 

In addition the application collects statistics on received and matched packets (such as number of packets per protocol, number of matched flows and number of matched packets).
Matching is done per flow, meaning the first packet received on a flow is matched against the matching criteria and if it's matched then all packets of the same flow will be matched too.


The application uses the concept of worker threads. Number of cores can be set by the user or set to default (default is all machine cores minus one management core). 
Each core is assigned with one worker thread. The application divides the DPDK ports and RX queues equally between worker threads.
For example: if there are 2 DPDK ports to listen to, each one with 6 RX queues and there are 3 worker threads, then worker #1 will get RX queues 1-4 of port 1, worker #2 will get RX queues 5-6 of port 1 
and RX queues 1-2 of port 2, and worker #3 will get RX queues 3-6 of port 2.

Each worker thread does exactly the same work: receiving packets, collecting packet statistics, matching flows and sending/saving matched packets.

Important: 
----------
- This application runs only on Linux (DPDK is not supported on Windows and Mac OS X)
- This application (like all applications using DPDK) should be run as 'sudo'


Using the utility
-----------------
	Basic usage: 
		FilterTraffic [-hl] [-s PORT] [-f FILENAME] [-p FILEPATH] [-r file_name] [-c CORE_MASK] [-m POOL_SIZE] -d ens785f0,ens785f1,...,ens785fn\n
	Options:
		"    -h|--help                                  : Displays this help message and exits\n"
		"    -v|--version                               : Displays the current version and exits\n"
		"    -l|--list                                  : Print the list of DPDK ports and exists\n"
		"    -d|--virtual-dev ens785f0,ens785f1,.,ens785fn : A comma-separated list of DPDK port numbers to receive packets from.\n"
		"    -s|--send-matched-packets PORT             : DPDK port to send matched packets to\n"
		"    -t|--set Threshole of Time                 : Default is 20s (second), this is threshold of time to changes pcapfile name automatically \n"
		"    -p|--save-matched-packets FILEPATH         : Save matched packets to pcap files under FILEPATH. Packets matched by core X will be saved under 'FILEPATH/CoreX_tv_nsec.tv_sec.pcap'\n"
		"    -a|--PcapFile-analyse-mode                 : run Application as Pcap file searching packet\n"
		"    -b|--begin time                            : Begin time on which packets will be selected\n"
		"    -e|--end time                              : Endtime on which packets will be selected\n"
		"    -o|--pcap file                             : Pcap file or directory where matched packets will be saved\n"
		"    -f|--search_criteria                       : Criteria to search in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html)\n"
		"    -r|--file_name                             : Write a detailed search report to a file\n"
		"    -c|--core-mask            CORE_MASK        : Core mask of cores to use. For example: use 7 (binary 0111) to use cores 0,1,2.\n",

pcap file name format : CoreX_tv_nsec.tv_sec.pcap
-------------------------------------------------
	 - EX: Core1_512.1629080972.pcap

default filepath : ../pcapfies_sample/
--------------------------------------
 - EX for capture packet mode: 
  	- This Example will capture packet from 2 interfaces wlp8s0, enp7s0 (the interfaces of the laptop acer Nitro 5) and then save to pcap file, the pcap file will changes the name with stamptime after defaut threshold (20s) automatically, can be changed the Default Threshole by the way set param input (-t).
		- $sudo ./build/testpcap -d wlp8s0,enp7s0

Analyse pcapfile
----------------
 	- This Example will read all of pcap files in the folder "../pcapfies_sample", then search the packet that match to input parameter
		- $sudo ./build/testpcap -a -f  "ip src 192.168.1.12 && ip dst 104.17.137.178 && port 443" -b "2021-08-16 09:32:21" -e "2021-08-16 09:32:21"