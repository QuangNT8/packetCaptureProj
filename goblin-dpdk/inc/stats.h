
#ifndef __STATS_H__
#define __STATS_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_ZMQ_ENDPOINT "ipc:///tmp/zmq_server.ipc"
#define MAX_FLOW 4000000U
#define MAX_DEVICES 2

struct consumer_stats
{
    u_int64_t __cache_line_padding_p[8];
    u_int64_t numPkts;
    u_int64_t numBytes;
    u_int64_t numDrops;
    u_int64_t __cache_line_padding_a[5];
    volatile u_int64_t do_shutdown;
};

struct capture_interfaces_info
{
    char ifname[128];
    uint8_t port_id;
    uint64_t last_actflows[10];
    uint64_t speed;
    uint64_t mtu;
    uint64_t tot_pkts;
    uint64_t tot_bytes;
    uint64_t recv_pkts;
    uint64_t sent_pkts;
    uint64_t recv_bytes;
    uint64_t sent_bytes;
    uint64_t drop_pkts;
    uint64_t drop_bytes;
    uint64_t rx_thoughput;
    uint64_t tx_thoughput;
    uint64_t tot_flows;
    uint64_t act_flows;
    uint64_t tot_threads;
    uint64_t tot_err_flows;
};

#endif /* __STATS_H__ */