
#include "AppWorkerThread.h"
#include "Common.h"
#include "Fileextract.h"

#include "DpdkDeviceList.h"

#include "ZmqDevives.h"

#include "IPv4Layer.h"
#include "PcapPlusPlusVersion.h"
#include "SystemUtils.h"
#include "TablePrinter.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <signal.h>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <vector>

#include <zmqpp/zmqpp.hpp>

using namespace pcpp;
using namespace std;
#define COLLECT_STATS_EVERY_SEC 1
#define DEFAULT_MBUF_POOL_SIZE 4095
#define DEFAULT_QUEUE_QUANTITY 1

static struct option AppOptions[] =
    {
        {"dpdk-ports", required_argument, 0, 'd'},
        {"send-matched-packets", optional_argument, 0, 's'},
        {"save-matched-packets", optional_argument, 0, 'f'},
        {"match-source-ip", optional_argument, 0, 'i'},
        {"match-dest-ip", optional_argument, 0, 'I'},
        {"match-source-port", optional_argument, 0, 'p'},
        {"match-dest-port", optional_argument, 0, 'P'},
        {"match-protocol", optional_argument, 0, 'r'},
        {"core-mask", optional_argument, 0, 'c'},
        {"mbuf-pool-size", optional_argument, 0, 'm'},
        {"help", optional_argument, 0, 'h'},
        {"version", optional_argument, 0, 'v'},
        {"list", optional_argument, 0, 'l'},
        {0, 0, 0, 0}};

/**
 * Print application usage
 */
void printUsage()
{
    printf("\nUsage:\n"
           "------\n"
           "%s [-hvl] [-s PORT] [-f FILENAME] [-p FILEPATH] [-r file_name]\n"
           "                     [-c CORE_MASK] [-m POOL_SIZE] -d ens785f0,ens785f1,...,ens785fn\n"
           "\nOptions:\n\n"
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
           AppName::get().c_str());
}

/**
 * Print application version
 */
void printAppVersion()
{
    printf("%s %s\n", AppName::get().c_str(), getPcapPlusPlusVersionFull().c_str());
    printf("Built: %s\n", getBuildDateTime().c_str());
    printf("Built from: %s\n", getGitInfo().c_str());
    exit(0);
}

/**
 * Print to console all available DPDK ports. Used by the -l switch
 */
void listDpdkPorts()
{
    CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

    // initialize DPDK
    if (!DpdkDeviceList::initDpdk(coreMaskToUse, DEFAULT_MBUF_POOL_SIZE))
    {
        EXIT_WITH_ERROR("couldn't initialize DPDK");
    }

    printf("DPDK port list:\n");

    // go over all available DPDK devices and print info for each one
    vector<DpdkDevice *> deviceList = DpdkDeviceList::getInstance().getDpdkDeviceList();
    for (vector<DpdkDevice *>::iterator iter = deviceList.begin(); iter != deviceList.end(); iter++)
    {
        DpdkDevice *dev = *iter;
        printf("    Port #%d: MAC address='%s'; PCI address='%s'; PMD='%s'; Queues='%d/%d'\n",
               dev->getDeviceId(),
               dev->getMacAddress().toString().c_str(),
               dev->getPciAddress().c_str(),
               dev->getPMDName().c_str(),
               dev->getTotalNumOfRxQueues(),
               dev->getTotalNumOfTxQueues());
    }
}

struct DpdkBridgeArgs
{
    bool shouldStop;
    std::vector<DpdkWorkerThread *> *workerThreadsVector;

    DpdkBridgeArgs() : shouldStop(false), workerThreadsVector(NULL) {}
    ZmqDevices zmq_device;
};

/**
 * The callback to be called when application is terminated by ctrl-c. Do cleanup and print summary stats
 */
void onApplicationInterrupted(void *cookie)
{
    DpdkBridgeArgs *args = (DpdkBridgeArgs *)cookie;

    printf("\n\nApplication stopped\n");

    // stop worker threads
    DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

    // create table printer
    // std::vector<std::string> columnNames;
    // std::vector<int> columnWidths;
    // PacketStats::getStatsColumns(columnNames, columnWidths);
    // TablePrinter printer(columnNames, columnWidths);

    // // print final stats for every worker thread plus sum of all threads and free worker threads memory
    // PacketStats aggregatedStats;
    for (std::vector<DpdkWorkerThread *>::iterator iter = args->workerThreadsVector->begin(); iter != args->workerThreadsVector->end(); iter++)
    {
        AppWorkerThread *thread = (AppWorkerThread *)(*iter);
        // PacketStats threadStats = thread->getStats();
        // aggregatedStats.collectStats(threadStats);
        // printer.printRow(threadStats.getStatValuesAsString("|"), '|');
        delete thread;
    }

    // printer.printSeparator();
    // printer.printRow(aggregatedStats.getStatValuesAsString("|"), '|');

    args->shouldStop = true;
}

/**
 * Extract and print traffic stats from a device
 */
void printStats(DpdkDevice *device)
{
    DpdkDevice::DpdkDeviceStats stats;
    device->getStatistics(stats);

    printf("\nStatistics for port %d:\n", device->getDeviceId());

    std::vector<std::string> columnNames;
    columnNames.push_back(" ");
    columnNames.push_back("Total Packets");
    columnNames.push_back("Packets/sec");
    columnNames.push_back("Total Bytes");
    columnNames.push_back("Bytes/sec");

    std::vector<int> columnLengths;
    columnLengths.push_back(10);
    columnLengths.push_back(15);
    columnLengths.push_back(15);
    columnLengths.push_back(15);
    columnLengths.push_back(15);

    TablePrinter printer(columnNames, columnLengths);

    std::stringstream totalRx;
    totalRx << "rx"
            << "|" << stats.aggregatedRxStats.packets << "|" << stats.aggregatedRxStats.packetsPerSec << "|" << stats.aggregatedRxStats.bytes << "|" << stats.aggregatedRxStats.bytesPerSec;
    printer.printRow(totalRx.str(), '|');

    std::stringstream totalTx;
    totalTx << "tx"
            << "|" << stats.aggregatedTxStats.packets << "|" << stats.aggregatedTxStats.packetsPerSec << "|" << stats.aggregatedTxStats.bytes << "|" << stats.aggregatedTxStats.bytesPerSec;
    printer.printRow(totalTx.str(), '|');
}

/**
 * Prepare the configuration for each core. Configuration includes: which DpdkDevices and which RX queues to receive packets from, where to send the matched
 * packets, etc.
 */
void prepareCoreConfiguration(vector<DpdkDevice *> &dpdkDevicesToUse, vector<SystemCore> &coresToUse,
                              bool writePacketsToDisk, string packetFilePath, DpdkDevice *sendPacketsTo, int threshole,
                              AppWorkerConfig workerConfigArr[])
{

    workerConfigArr[0].CoreId = coresToUse.at(0).Id;
    workerConfigArr[0].RxDevice = dpdkDevicesToUse.at(0);
    workerConfigArr[0].RxQueues = 1;
    workerConfigArr[0].TxDevice = dpdkDevicesToUse.at(0);

    // std::stringstream packetFileName0;
    // packetFileName0 << packetFilePath << "Core" << workerConfigArr[0].CoreId << ".pcap";

    workerConfigArr[0].PathToWritePackets = packetFilePath;
    // workerConfigArr[0].pcappramdata = pcappramdata;
    workerConfigArr[0].WriteMatchedPacketsToFile = true;
    workerConfigArr[0].time_threshold = threshole;

    workerConfigArr[1]
        .CoreId = coresToUse.at(1).Id;
    workerConfigArr[1].RxDevice = dpdkDevicesToUse.at(1);
    workerConfigArr[1].RxQueues = 1;
    workerConfigArr[1].TxDevice = dpdkDevicesToUse.at(1);
    // std::stringstream packetFileName1;
    // packetFileName1 << packetFilePath << "Core" << workerConfigArr[1].CoreId << ".pcap";
    workerConfigArr[1].PathToWritePackets = packetFilePath;
    workerConfigArr[1].WriteMatchedPacketsToFile = true;
    workerConfigArr[1].time_threshold = threshole;

    printf("prepareCoreConfiguration >> PathToWritePackets: %s\n", workerConfigArr[0].PathToWritePackets.c_str());
    printf("prepareCoreConfiguration >> PathToWritePackets: %s\n", workerConfigArr[1].PathToWritePackets.c_str());
}

/**
 * main method of the application. Responsible for parsing user args, preparing worker thread configuration, creating the worker threads and activate them.
 * At program termination worker threads are stopped, statistics are collected from them and printed to console
 */
int main(int argc, char *argv[])
{
    AppName::init(argc, argv);

    std::vector<std::string> ifname;

    CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

    bool writePacketsToDisk = false;
    int sendPacketsToPort = -1;
    int threshole_time = 20;
    string packetFilePath = "../pcapfies_sample/";

    int optionIndex = 0;
    char opt = 0;

    uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;
    uint16_t queueQuantity = DEFAULT_QUEUE_QUANTITY;

    ProtocolType protocolToMatch = UnknownProtocol;

    static struct PcapFileParamData pcappramdata;

    pcappramdata.searchCriteria = "ip src 192.168.1.1";
    pcappramdata.analysePcapfile = false;
    // pcappramdata.begin_t = "2021-08-16 09:30:13";
    pcappramdata.begin_t = "2021-08-16 09:32:21";
    pcappramdata.end_t = "2021-08-16 09:32:21";
    // pcappramdata.begin_t = "";
    // pcappramdata.end_t = "";
    pcappramdata.path = packetFilePath;
    pcappramdata.outputFileName = pcappramdata.path + "output" + ".pcap";

    std::string detailedReportFileName = packetFilePath + "report.txt";

    FileExtract fileExtract;

    while ((opt = getopt_long(argc, argv, "d:c:s:t:p:m:i:I:p:P:r:f:o:b:e:hvlaz", AppOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
        case 0:
        {
            break;
        }
        case 'c':
        {
            coreMaskToUse = atoi(optarg);
            break;
        }
        case 'd':
        {
            string portListAsString = string(optarg);
            stringstream stream(portListAsString);
            string portAsString;
            // break comma-separated string into string list
            while (getline(stream, portAsString, ','))
            {
                std::stringstream stream2(portAsString);

                // printf("portAsString >>>>%s\n", portAsString.c_str());
                ifname.push_back(portAsString);
            }

            break;
        }

        case 's':
        {
            sendPacketsToPort = atoi(optarg);
            break;
        }

        case 't':
        {
            threshole_time = atoi(optarg);
            break;
        }

        case 'p':
        {
            packetFilePath = string(optarg);
            writePacketsToDisk = true;
            if (packetFilePath.empty())
            {
                EXIT_WITH_ERROR_AND_PRINT_USAGE("Filename to write packets is empty");
            }
            break;
        }

        case 'm':
        {
            mBufPoolSize = atoi(optarg);
            break;
        }

        case 'q':
        {
            queueQuantity = atoi(optarg);
            break;
        }

        case 'z':
        {
            // zmq_enable = true;
            break;
        }

        case 'a':
        {
            pcappramdata.analysePcapfile = true;
            break;
        }

        case 'f':
        {
            pcappramdata.searchCriteria = optarg;
            break;
        }

        case 'b':
        {

            if (!fileExtract.checkTimeformat(optarg))
            {
                EXIT_WITH_ERROR("Begin Time was wrong format");
            }
            else
            {
                pcappramdata.begin_t = optarg;
            }
            break;
        }

        case 'e':
        {
            if (!fileExtract.checkTimeformat(optarg))
            {
                EXIT_WITH_ERROR("End Time was wrong format");
            }
            else
            {
                pcappramdata.end_t = optarg;
            }
            break;
        }

        case 'o':
        {
            pcappramdata.outputFileName = optarg;
            break;
        }

        case 'r':
        {
            detailedReportFileName = optarg;
            break;
        }

        case 'h':
        {
            printUsage();
            exit(0);
        }
        case 'l':
        {
            listDpdkPorts();
            exit(0);
        }
        case 'v':
        {
            printAppVersion();
            break;
        }

        default:
        {
            printUsage();
            exit(0);
        }
        }
    }

    if (pcappramdata.analysePcapfile)
    {
        printf("*****Pcap Analysing mode*****\n");
        printf("Pcap file output to %s\n", pcappramdata.outputFileName.c_str());
        printf("Log file output to %s\n", detailedReportFileName.c_str());

        // open the detailed report file if requested by the user
        std::ofstream *detailedReportFile = NULL;
        if (detailedReportFileName != "")
        {
            detailedReportFile = new std::ofstream();
            detailedReportFile->open(detailedReportFileName.c_str());
            if (detailedReportFile->fail())
            {
                EXIT_WITH_ERROR("Couldn't open detailed report file '%s' for writing", detailedReportFileName.c_str());
            }

            // in cases where the user requests a detailed report, all errors will be written to the report also. That's why we need to save the error messages
            // to a variable and write them to the report file later
            pcpp::LoggerPP::getInstance().setErrorString(errorString, ERROR_STRING_LEN);
            pcappramdata.detailedReportFile = detailedReportFile;
        }
        else
        {
            pcappramdata.detailedReportFile = NULL;
        }

        fileExtract.PcapExtractEngine(&pcappramdata);
    }
    else
    {
        // verify list is not empty
        if (ifname.empty())
        {
            EXIT_WITH_ERROR_AND_PRINT_USAGE("DPDK virtual devices list is empty. Please use the -i switch");
        }

        DpdkDeviceList::addVirtualDev(ifname, false);

        // extract core vector from core mask
        vector<SystemCore> coresToUse;
        createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);
        // EXIT_WITH_ERROR("coresToUse : %d\n", coresToUse.at(1).Id);
        // need minimum of 2 cores to start - 1 management core + 1 (or more) worker thread(s)
        if (coresToUse.size() < 2)
        {
            EXIT_WITH_ERROR("Needed minimum of 2 cores to start the application");
        }

        // initialize DPDK
        if (!DpdkDeviceList::initDpdk(coreMaskToUse, mBufPoolSize))
        {
            EXIT_WITH_ERROR("Couldn't initialize DPDK");
        }

        // removing DPDK master core from core mask because DPDK worker threads cannot run on master core
        coreMaskToUse = coreMaskToUse & ~(DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);

        // re-calculate cores to use after removing master core
        coresToUse.clear();
        createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

        // collect the list of DPDK devices
        vector<DpdkDevice *> dpdkDevicesToUse;
        // for (vector<int>::iterator iter = dpdkPortVec.begin(); iter != dpdkPortVec.end(); iter++)
        for (uint i = 0; i < ifname.size(); i++)
        {
            DpdkDevice *dev = DpdkDeviceList::getInstance().getDeviceByPort(i);
            if (dev == NULL)
            {
                EXIT_WITH_ERROR("DPDK device for port %d doesn't exist", i);
            }
            dpdkDevicesToUse.push_back(dev);
        }

        // go over all devices and open them
        for (vector<DpdkDevice *>::iterator iter = dpdkDevicesToUse.begin(); iter != dpdkDevicesToUse.end(); iter++)
        {
            if (!(*iter)->openMultiQueues(queueQuantity, 1))
            {
                EXIT_WITH_ERROR("Couldn't open DPDK device #%d, PMD '%s'", (*iter)->getDeviceId(), (*iter)->getPMDName().c_str());
            }
        }

        sendPacketsToPort = -1;
        writePacketsToDisk = true;
        // get DPDK device to send packets to (or NULL if doesn't exist)
        DpdkDevice *sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
        if (sendPacketsTo != NULL && !sendPacketsTo->isOpened() && !sendPacketsTo->open())
        {
            EXIT_WITH_ERROR("Could not open port#%d for sending matched packets", sendPacketsToPort);
        }

        // prepare configuration for every core
        AppWorkerConfig workerConfigArr[coresToUse.size()];
        prepareCoreConfiguration(dpdkDevicesToUse, coresToUse, writePacketsToDisk, packetFilePath, sendPacketsTo, threshole_time, workerConfigArr);

        DpdkBridgeArgs args;
        // create worker thread for every core
        vector<DpdkWorkerThread *> workerThreadVec;
        int i = 0;
        for (vector<SystemCore>::iterator iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
        {
            printf("coresToUse :%d\n", i);
            AppWorkerThread *newWorker = new AppWorkerThread(workerConfigArr[i], args.zmq_device);
            workerThreadVec.push_back(newWorker);
            i++;
        }
        // EXIT_WITH_ERROR("Couldn't start worker threads");
        // start all worker threads
        if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
        {
            EXIT_WITH_ERROR("Couldn't start worker threads");
        }

        // register the on app close event to print summary stats on app termination

        args.workerThreadsVector = &workerThreadVec;
        ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);
        //
        // infinite loop (until program is terminated)
        uint64_t counter = 0;
        int statsCounter = 1;
        // EXIT_WITH_ERROR("testing");
        while ((!args.shouldStop))
        {
            sleep(5);
        }

        // Keep running while flag is on
        while (!args.shouldStop)
        {
            // Sleep for 1 second
            sleep(1);

            // Print stats every COLLECT_STATS_EVERY_SEC seconds
            if (counter % COLLECT_STATS_EVERY_SEC == 0)
            {
                // Clear screen and move to top left
                const char clr[] = {27, '[', '2', 'J', '\0'};
                const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
                printf("%s%s", clr, topLeft);

                // Print devices traffic stats
                printf("Stats #%d\n==========\n", statsCounter++);
                printStats(dpdkDevicesToUse.at(0));
                printStats(dpdkDevicesToUse.at(1));
            }
            counter++;
        }
    }
}
