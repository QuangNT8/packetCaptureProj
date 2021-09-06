#ifndef __APPWORKERTHREAD_H__
#define __APPWORKERTHREAD_H__

#pragma once

#include "Common.h"

#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "PacketUtils.h"
#include "PcapFileDevice.h"
#include <Logger.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <PcapPlusPlusVersion.h>
#include <RawPacket.h>
#include <SystemUtils.h>
#include <dirent.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <map>
#include <sstream>
#include <stdlib.h>
#include <sys/stat.h>
#include <vector>

#include <unistd.h>

#include "Fileextract.h"
#include "Timeconverter.h"
#include "chrono"

#include <dirent.h>
#include <sys/stat.h>

#include <zmqpp/zmqpp.hpp>

#include "ZmqDevives.h"

using namespace pcpp;
using namespace std::chrono;

/**
 * The worker thread class which does all the work. It's initialized with pointers to the RX and TX devices, then it runs in
 * an endless loop which reads packets from the RX device and sends them to the TX device.
 * The endless loop is interrupted only when the thread is asked to stop (calling its stop() method)
 */
class AppWorkerThread : public DpdkWorkerThread
{
private:
    AppWorkerConfig &m_WorkerConfig;
    ZmqDevices &m_ZmqDevice;
    zmqpp::context context;
    zmqpp::socket_type type = zmqpp::socket_type::dealer;

    bool m_Stop;
    uint32_t m_CoreId;
    PacketStats m_Stats;
    pcpp::DpdkDevice *SendPacketsTo;
    // bool WriteMatchedPacketsToFile;
    // bool analysePcapfile;
    string PathToWritePackets;

    TimeConverter timeconvert;
    // FileExtract fileExtract;

    bool isEnpoindGood = m_ZmqDevice.GetEnpointStatus();

    timespec getcurrent_timestamp()
    {
        timespec now;
        int retval = clock_gettime(CLOCK_REALTIME, &now);
        return now;
    }

    pcpp::PcapFileWriterDevice *create_file(std::string filename)
    {
        pcpp::PcapFileWriterDevice *pcapWriter = NULL;

        if (m_WorkerConfig.WriteMatchedPacketsToFile)
        {
            pcapWriter = new pcpp::PcapFileWriterDevice(filename);
            if (!pcapWriter->open())
            {
                EXIT_WITH_ERROR("Couldn't open pcap writer device");
            }
        }

        return pcapWriter;
    }

    std::string getfilenamebytimestamp()
    {
        std::string path = m_WorkerConfig.PathToWritePackets;
        std::string filename = "";
        std::stringstream timestampname;

        std::string utc;
        timespec curtime;
        static timespec prev_time;
        double diff_timer = 0; //, threshold = 1;

        curtime = getcurrent_timestamp();

        // printf("%s\n", buf.c_str());
        diff_timer = difftime(curtime.tv_sec, prev_time.tv_sec);
        if (diff_timer > m_WorkerConfig.time_threshold - 1)
        {
            // printf("diff_timer : %ld\n", diff_timer);
            timestampname << curtime.tv_nsec << "." << curtime.tv_sec;
            prev_time = curtime;
            // utc = timeconvert.local_system_timestamp(curtime);
            // filename = utc;
            filename = timestampname.str();
            // printf("%s\n", filename.c_str());
        }

        if (path != "" && filename != "")
        {
            std::stringstream packetFileName;
            packetFileName << path << "Core" << m_CoreId << "_" << filename << ".pcap";
            filename = packetFileName.str();
            // printf("filename %s\n", filename.c_str());
        }
        //
        return filename;
    }

public:
    AppWorkerThread(AppWorkerConfig &workerConfig, ZmqDevices &zmq_dev) : m_WorkerConfig(workerConfig),
                                                                          m_ZmqDevice(zmq_dev),
                                                                          m_Stop(true),
                                                                          m_CoreId(MAX_NUM_OF_CORES + 1)
    {
    }

    virtual ~AppWorkerThread()
    {
        // do nothing
        printf("~AppWorkerThread()\n");
        delete &m_ZmqDevice;
        // zmq_close(socket);
        // m_ZmqDevice.term_context();
        // zmq_ctx_destroy(context);
    }

    PacketStats &getStats()
    {
        return m_Stats;
    }

    // implement abstract methods

    bool run(uint32_t coreId)
    {
        m_CoreId = coreId;
        m_Stop = false;
        DpdkDevice *rxDevice = m_WorkerConfig.RxDevice;
        DpdkDevice *txDevice = m_WorkerConfig.TxDevice;
        pcpp::PcapFileWriterDevice *pcapWriter = NULL;
        std::string prev_filename = "";

        // printf("Default EndPoint: %s\n", m_ZmqDevice.GetDefaultEndpoint().c_str());
        std::stringstream zmq_msg;

        // zmqpp::socket zmq_socket(*m_ZmqDevice.GetContext(), *m_ZmqDevice.GetSocketType());
        zmqpp::socket socket(context, type);
        socket.connect(m_ZmqDevice.GetDefaultEndpoint());

        if (isEnpoindGood)
        {
            printf("Default EndPoint: %s\n", m_ZmqDevice.GetDefaultEndpoint().c_str());
        }

        // if no DPDK devices were assigned to this worker/core don't enter the main loop and exit
        if (!rxDevice || !txDevice)
        {
            return true;
        }

        printf("PathToWritePackets: %s\n", m_WorkerConfig.PathToWritePackets.c_str());

        std::string filename = getfilenamebytimestamp();
        if (filename != prev_filename)
        {
            printf("filename on first time %s\n", filename.c_str());
            prev_filename = filename;
            pcapWriter = create_file(filename);
        }

        MBufRawPacket *packetArr[MAX_RECEIVE_BURST] = {};
        long idx = 0;
        // main loop, runs until be told to stop
        while (!m_Stop)
        {
            for (uint16_t i = 0; i < m_WorkerConfig.RxQueues; i++)
            {
                // receive packets from network on the specified DPDK device
                uint16_t packetsReceived = rxDevice->receivePackets(packetArr, MAX_RECEIVE_BURST, i);
                for (int j = 0; j < packetsReceived; j++)
                {
                    // parse packet
                    pcpp::Packet parsedPacket(packetArr[j]);
                    // collect packet statistics
                    // printf("coreId %u\n", coreId);
                    m_Stats.collectStats(parsedPacket);
                    // save packet to file if needed
                    if (pcapWriter != NULL)
                    {
                        pcapWriter->writePacket(*packetArr[j]);
                    }

                    /* Send packet via Zmq */
                    if (isEnpoindGood)
                    {
                        int pkglen = parsedPacket.getRawPacket()->getRawDataLen();

                        if (pkglen > 0)
                        {
                            idx++;
                            timespec timestamp = parsedPacket.getRawPacket()->getPacketTimeStamp();
                            zmqpp::message message;
                            // message << coreId; // << pkglen;
                            message.add(coreId);
                            message.add(idx);
                            message.add(timestamp.tv_sec);
                            message.add(timestamp.tv_nsec);
                            message.add(pkglen);
                            // message.push_back(parsedPacket.getRawPacket()->getRawData());
                            bool ret = socket.send(message);

                            if (ret)
                            {
                                bool ret_raw = socket.send_raw((char *)parsedPacket.getRawPacket()->getRawData(), parsedPacket.getRawPacket()->getRawDataLen());
                                printf(" zmq_socket.send_raw %d\n", ret_raw);
                                // m_ZmqDevice.wait_for_socket(zmq_socket);
                            }
                        }

                        printf("parsedPacket.getRawPacket()->getRawDataLen %d >> %ld\n", pkglen, idx);
                        for (int u = 0; u < pkglen; u++)
                        {
                            uint8_t data = parsedPacket.getRawPacket()->getRawData()[u];
                            printf(" %x", data);
                        }
                        printf("\n");
                    }
                }
            }

            filename = getfilenamebytimestamp();
            if ((filename != "") && (filename != prev_filename))
            {
                if (pcapWriter != NULL)
                {
                    delete pcapWriter;
                }

                pcapWriter = create_file(filename);

                printf("filename %s\n", filename.c_str());
                prev_filename = filename;
            }
        }

        // free packet array (frees all mbufs as well)
        for (int i = 0; i < MAX_RECEIVE_BURST; i++)
        {
            if (packetArr[i] != NULL)
                delete packetArr[i];
        }

        // close and delete pcap file writer
        if (pcapWriter != NULL)
        {
            delete pcapWriter;
        }

        /* destroy the ZMQ */
        if (m_Stop && isEnpoindGood)
        {
            printf("zmq_close\n");
            zmq_close(socket);
        }

        return true;
    }

    void stop()
    {
        // assign the stop flag which will cause the main loop to end
        m_Stop = true;
        // printf("stop app %d\n", m_CoreId);
    }

    uint32_t getCoreId() const
    {
        return m_CoreId;
    }
};

#endif /* __APPWORKERTHREAD_H__ */
