#ifndef __ZMQDEVICES_H__
#define __ZMQDEVICES_H__
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

#include <iostream>
#include <string>

#include <zmqpp/zmqpp.hpp>

#define DEFAULT_ZMQ_ENDPOINT "ipc:///tmp/zmq_server.ipc"

using namespace std;
using namespace pcpp;
using namespace std::chrono;

class ZmqDevices
{
private:
    bool m_isTerm = false;
    bool m_enpoint_status = false;
    const int max_poll_timeout = 100;
    const string endpoint = DEFAULT_ZMQ_ENDPOINT;

    zmqpp::context context;
    zmqpp::socket_type type = zmqpp::socket_type::dealer;

public:
    bool GetEnpointStatus()
    {
        return m_enpoint_status;
    }

    ZmqDevices()
    {
        printf("ZmqDevices start\n");
        zmqpp::socket socket(context, type);
        socket.connect(endpoint);

        socket.send(endpoint.c_str());

        string message;
        wait_for_socket(socket);

        zmqpp::loop loop;
        string end_p = endpoint;

        auto receiver = [&loop, &message, &end_p, &socket]() -> bool
        {
            cout << "Receiving Confirm message..." << endl;
            socket.receive(message);
            printf("message >> %s \n", message.c_str());
            return true;
        };

        auto end_loop = []() -> bool
        {
            return false;
        };

        loop.add(socket, receiver);
        loop.add(std::chrono::seconds(1), 1, end_loop);
        loop.start();
        // socket.receive(message);
        // printf("message >> %s\n", message.c_str());
        // printf("message.compare(endpoint) >> %d\n", message.compare(endpoint));
        if (message.compare(endpoint) == 0)
        {
            m_enpoint_status = true;
        }
        else
        {
            m_enpoint_status = false;
            EXIT_WITH_ERROR("could not received the response msg from endpoint : %s", endpoint.c_str());
        }
    }

    void term_context()
    {
        if ((context != NULL) && (!m_isTerm))
        {
            // zmq_term(context);
            zmq_ctx_destroy(context);
            m_isTerm = true;
        }
    }

    zmqpp::context *GetContext()
    {
        return &context;
    }

    zmqpp::socket_type *GetSocketType()
    {
        return &type;
    }

    string GetDefaultEndpoint()
    {
        return endpoint;
    }

    int wait_for_socket(zmqpp::socket &socket)
    {
        zmq_pollitem_t item = {socket, 0, ZMQ_POLLIN, 0};
        int result = zmq_poll(&item, 1, max_poll_timeout);
        return result;
    }

    ~ZmqDevices()
    {
        printf("ZmqDevices destroy\n");
        if (m_enpoint_status)
        {
            zmq_ctx_destroy(context);
        }
    }
};

#endif /* __ZMQDEVICES_H__ */