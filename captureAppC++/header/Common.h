#ifndef __COMMON_H__
#define __COMMON_H__
#pragma once

#include "DpdkDevice.h"
#include "Packet.h"

#include <SystemUtils.h>

#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <vector>

using namespace std;
using namespace pcpp;

/**
 * Macros for exiting the application with error
 */

#define EXIT_WITH_ERROR(reason, ...)                                            \
    do                                                                          \
    {                                                                           \
        printf("Application terminated in error: " reason "\n", ##__VA_ARGS__); \
        exit(1);                                                                \
    } while (0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason, ...)      \
    do                                                    \
    {                                                     \
        printf("\nError: " reason "\n\n", ##__VA_ARGS__); \
        printUsage();                                     \
        exit(1);                                          \
    } while (0)

struct PcapFileParamData
{
    bool analysePcapfile;
    std::string begin_t;
    std::string end_t;
    std::string searchCriteria;
    std::string path;
    std::string outputFileName;
    std::ofstream *detailedReportFile;
};

struct RawPackets_t
{
    uint8_t core_id;
    uint64_t idx;
    uint64_t stamptime_sec;
    uint64_t stamptime_nsec;
    uint64_t pkg_len;
    char rawdata[8000];
};

/**
 * Contains all the configuration needed for the worker thread including:
 * - Which DPDK port to receive packets from
 * - Which DPDK port to send packets to
 */
struct AppWorkerConfig
{
    uint32_t CoreId;
    DpdkDevice *RxDevice;
    uint16_t RxQueues;
    DpdkDevice *TxDevice;

    DpdkDevice *SendPacketsTo;
    bool WriteMatchedPacketsToFile;
    string PathToWritePackets;
    double time_threshold;

    AppWorkerConfig() : CoreId(MAX_NUM_OF_CORES + 1),
                        RxDevice(NULL),
                        RxQueues(1),
                        TxDevice(NULL),
                        SendPacketsTo(NULL),
                        WriteMatchedPacketsToFile(false),
                        PathToWritePackets("")
    {
    }
};

/**
 * Collect and analyze packet and flow statistics
 */
struct PacketStats
{
public:
    uint8_t WorkerId;

    int PacketCount;
    int EthCount;
    int ArpCount;
    int Ip4Count;
    int Ip6Count;
    int TcpCount;
    int UdpCount;
    int HttpCount;

    int MatchedTcpFlows;
    int MatchedUdpFlows;
    int MatchedPackets;

    PacketStats() : WorkerId(MAX_NUM_OF_CORES + 1), PacketCount(0), EthCount(0), ArpCount(0), Ip4Count(0), Ip6Count(0), TcpCount(0), UdpCount(0), HttpCount(0), MatchedTcpFlows(0), MatchedUdpFlows(0), MatchedPackets(0) {}

    void collectStats(pcpp::Packet &packet)
    {
        PacketCount++;
        // printf("PacketCount : %d\n", PacketCount);
        if (packet.isPacketOfType(pcpp::Ethernet))
            EthCount++;
        if (packet.isPacketOfType(pcpp::ARP))
            ArpCount++;
        if (packet.isPacketOfType(pcpp::IPv4))
            Ip4Count++;
        if (packet.isPacketOfType(pcpp::IPv6))
            Ip6Count++;
        if (packet.isPacketOfType(pcpp::TCP))
            TcpCount++;
        if (packet.isPacketOfType(pcpp::UDP))
            UdpCount++;
        if (packet.isPacketOfType(pcpp::HTTP))
            HttpCount++;
    }

    void collectStats(PacketStats &stats)
    {
        PacketCount += stats.PacketCount;

        EthCount += stats.EthCount;
        ArpCount += stats.ArpCount;
        Ip4Count += stats.Ip4Count;
        Ip6Count += stats.Ip6Count;
        TcpCount += stats.TcpCount;
        UdpCount += stats.UdpCount;
        HttpCount += stats.HttpCount;

        MatchedTcpFlows += stats.MatchedTcpFlows;
        MatchedUdpFlows += stats.MatchedUdpFlows;
        MatchedPackets += stats.MatchedPackets;
    }

    void clear()
    {
        WorkerId = MAX_NUM_OF_CORES + 1;
        PacketCount = 0;
        EthCount = 0;
        ArpCount = 0;
        Ip4Count = 0;
        Ip6Count = 0;
        TcpCount = 0;
        UdpCount = 0;
        HttpCount = 0;
        MatchedTcpFlows = 0;
        MatchedUdpFlows = 0;
        MatchedPackets = 0;
    }

    std::string getStatValuesAsString(std::string delimiter)
    {
        std::stringstream values;
        if (WorkerId == MAX_NUM_OF_CORES + 1)
            values << "Total" << delimiter;
        else
            values << (int)WorkerId << delimiter;
        values << PacketCount << delimiter;
        values << EthCount << delimiter;
        values << ArpCount << delimiter;
        values << Ip4Count << delimiter;
        values << Ip6Count << delimiter;
        values << TcpCount << delimiter;
        values << UdpCount << delimiter;
        values << HttpCount << delimiter;
        values << MatchedTcpFlows << delimiter;
        values << MatchedUdpFlows << delimiter;
        values << MatchedPackets;

        return values.str();
    }

    static void getStatsColumns(std::vector<std::string> &columnNames, std::vector<int> &columnWidths)
    {
        columnNames.clear();
        columnWidths.clear();

        static const int narrowColumnWidth = 11;
        static const int wideColumnWidth = 18;

        columnNames.push_back("Core ID");
        columnNames.push_back("Packet Cnt");
        columnNames.push_back("Eth Cnt");
        columnNames.push_back("ARP Cnt");
        columnNames.push_back("IPv4 Cnt");
        columnNames.push_back("IPv6 Cnt");
        columnNames.push_back("TCP Cnt");
        columnNames.push_back("UDP Cnt");
        columnNames.push_back("HTTP Cnt");
        columnNames.push_back("Matched TCP Flows");
        columnNames.push_back("Matched UDP Flows");
        columnNames.push_back("Matched Packets");

        columnWidths.push_back(7);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(narrowColumnWidth);
        columnWidths.push_back(wideColumnWidth);
        columnWidths.push_back(wideColumnWidth);
        columnWidths.push_back(wideColumnWidth);
    }
};

#endif /* __COMMON_H__ */