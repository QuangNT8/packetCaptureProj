/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_string_fns.h>

#include "../main.h"

/*
 * Forwarding of packets in I/O mode.
 * Forward packets "as-is".
 * This is the fastest possible forwarding operation, as it does not access
 * to packets data.
 */
static void
pkt_burst_io_forward(struct fwd_stream *fs)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint16_t nb_rx;
    uint16_t nb_tx;
    uint32_t retry;
    uint64_t start_tsc = 0;

    get_start_cycles(&start_tsc);

    /*
	 * Receive a burst of packets and forward them.
	 */
    nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
                             pkts_burst, nb_pkt_per_burst);
    inc_rx_burst_stats(fs, nb_rx);
    if (unlikely(nb_rx == 0))
        return;
    fs->rx_packets += nb_rx;
    // printf("pkt_burst_io_forward>>>>>>>rx_port %u tx_port %u\n", fs->rx_port, fs->tx_port);
    nb_tx = rte_eth_tx_burst(fs->rx_port, fs->rx_queue,
                             pkts_burst, nb_rx);
    // printf("pkt_burst_io_forward>>>>>>>nb_rx %u\n", nb_rx);
    /*
	 * Retry if necessary
	 */
    if (unlikely(nb_tx < nb_rx) && fs->retry_enabled)
    {
        retry = 0;
        // printf("rte_delay_us>>>>>>>nb_rx %u\n", nb_rx);
        while (nb_tx < nb_rx && retry++ < burst_tx_retry_num)
        {
            rte_delay_us(burst_tx_delay_time);
            nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
                                      &pkts_burst[nb_tx], nb_rx - nb_tx);
        }
    }
    fs->tx_packets += nb_tx;
    inc_tx_burst_stats(fs, nb_tx);
    if (unlikely(nb_tx < nb_rx))
    {
        fs->fwd_dropped += (nb_rx - nb_tx);
        do
        {
            rte_pktmbuf_free(pkts_burst[nb_tx]);
        } while (++nb_tx < nb_rx);
    }

    get_end_cycles(fs, start_tsc);
}

static void
port_io_fwd_begin(portid_t pi)
{
    printf("\n++++++++++++++++++++++++ port%u_io_fwd_begin +++++++++++++++++++++++++\n", pi);
}

static void
port_io_fwd_end(portid_t pi)
{
    printf("\n++++++++++++++++++++++++ port%u_io_fwd_end +++++++++++++++++++++++++\n", pi);
}

static void
port_print_stats(portid_t pi)
{
    struct rte_eth_stats stats;
    printf("\n  =========================== Port %u statistics =============================\n", pi);
    nic_stats_display(pi);
}

uint16_t rx_callback(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
                     uint16_t nb_pkts, __rte_unused uint16_t max_pkts,
                     __rte_unused void *user_param)
{
    // printf("\n  ============================= rx_callback %u ===============================\n", port_id);
    // dump_pkt_burst(port_id, queue, pkts, nb_pkts, 1);
    dump_rx_pkts(port_id, queue, pkts, nb_pkts, max_pkts, user_param);
    // dump_pkt_burst(port_id, queue, pkts, nb_pkts, 1);
    return nb_pkts;
}

struct fwd_engine io_fwd_engine = {
    .fwd_mode_name = "io",
    .port_fwd_begin = port_io_fwd_begin,
    .port_fwd_end = port_io_fwd_end,
    .packet_fwd = pkt_burst_io_forward,
    .print_stats = port_print_stats,
    .rx_callback = rx_callback,
};
