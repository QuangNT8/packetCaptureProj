
#include <iostream>
#include <string>
#include <zmqpp/zmqpp.hpp>

#define DEFAULT_ZMQ_ENDPOINT "ipc:///tmp/zmq_server.ipc"
using namespace std;

int main(int argc, char *argv[])
{
    enum modes
    {
        CONFIRM,
        RESPONSE,
        GETMSG,
    };
    // const string endpoint = "tcp://*:4242";
    const string endpoint = DEFAULT_ZMQ_ENDPOINT;

    // initialize the 0MQ context
    zmqpp::context context;

    // generate a pull socket
    zmqpp::socket_type type = zmqpp::socket_type::dealer;
    zmqpp::socket socket(context, type);

    cout << "Binding to " << endpoint << "..." << endl;
    socket.bind(endpoint);

    zmqpp::loop loop;
    zmqpp::message message;
    string msg_checker;

    modes mode = CONFIRM;
    // len = 5;
    // BOOST_CHECK(puller.receive_raw(buf, len));

    auto getmsgs = [&message, &endpoint, &socket, &mode]() -> bool
    {
        if (mode == GETMSG)
        {
            cout << "Receiving message..." << endl;
            socket.receive(message);
            int numparts = message.parts();
            printf("message.parts >> %d \n", message.parts());
            if (numparts > 0 && numparts < 5)
            {
                string txt_msg;
                message >> txt_msg;
                printf("txt_msg>> %s \n", txt_msg.c_str());

                if (txt_msg.compare(endpoint) == 0)
                {
                    printf("endpoint >>> %s\n", endpoint.c_str());
                    txt_msg.clear();
                    socket.send(endpoint);
                    mode = RESPONSE;
                    return true;
                }
            }
            if (numparts == 5)
            {
                char buf[8000];
                memset(buf, 0, sizeof(buf));
                int core = message.get<int>(0);
                long numberpkg = message.get<long>(1);
                long tim_sec = message.get<long>(2);
                long tim_nsec = message.get<long>(3);
                int pkglen = message.get<int>(4);

                size_t len = (size_t)pkglen;
                socket.receive_raw(buf, len);
                printf("total pkg >>>  %ld \n", numberpkg);
                printf("time stamp >>> sec %ld, nsec : %ld\n", tim_sec, tim_nsec);
                printf("message >>> core %d, pkg len : %d\n", core, pkglen);
                printf("raw data >> %d ", 0);
                for (int i = 0; i < pkglen; i++)
                {
                    uint8_t dat = (uint8_t)buf[i];
                    printf(" 0x%x", dat);
                }
            }

            printf("\n");
        }

        return true;
    };

    // loop.add(socket, checker);
    auto checker = [&loop, &msg_checker, &endpoint, &socket, &mode]() -> bool
    {
        if (mode == CONFIRM || mode == RESPONSE)
        {
            cout << "Receiving Confirm message..." << endl;
            socket.receive(msg_checker);
            printf("message >> %s \n", msg_checker.c_str());

            if (msg_checker.compare(endpoint) == 0)
            {
                printf("endpoint >>> %s\n", endpoint.c_str());
                msg_checker.clear();
                mode = RESPONSE;
            }
            else
            {
                mode = GETMSG;
            }
        }

        return true;
    };

    auto sendmsg = [&loop, &msg_checker, &endpoint, &socket, &mode]() -> bool
    {
        if (mode == RESPONSE)
        {
            cout << "Sending Confirm message..." << endl;
            socket.send(endpoint);
            mode = GETMSG;
        }
        return true;
    };

    auto end_loop = []() -> bool
    {
        return false;
    };

    loop.add(socket, checker);
    loop.add(socket, sendmsg);
    loop.add(socket, getmsgs);
    // loop.add(std::chrono::seconds(10), 1, end_loop);

    // loop.add(std::chrono::seconds(60), 1, end_loop);
    loop.start();
    printf("Finished. \n");
}
