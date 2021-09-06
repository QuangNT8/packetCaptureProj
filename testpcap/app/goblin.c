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
#include "db_zmq.h"
#include "ftutils.h"

uint8_t cur_queu;
/* ************************************ */
int send2ft(pfring_ft_table *ft, uint16_t nb_pkt, struct rte_mbuf *pkts_burst)
{
    int ret = 0;
    pfring_ft_pcap_pkthdr h;
    pfring_ft_ext_pkthdr ext_hdr = {0};

    char *data = rte_pktmbuf_mtod(pkts_burst, char *);
    int len = rte_pktmbuf_pkt_len(pkts_burst);

    h.len = h.caplen = len;
    gettimeofday(&h.ts, NULL);

    if (pfring_ft_process(ft, (const u_char *)data, &h, &ext_hdr) != PFRING_FT_ACTION_DISCARD)
    {
        ret = 0;
    }
    else
    {
        ret = -1;
    }

    return ret;
}
/* ************************************ */
static void
goblin_main_func(struct fwd_stream *fs)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint16_t nb_rx;
    uint16_t nb_tx;
    uint32_t retry;
    uint64_t start_tsc = 0;
    uint16_t coreid;

    get_start_cycles(&start_tsc);
    coreid = current_fwd_lcore()->cpuid_idx;

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
    // printf("goblin_main_func %u\n", coreid);
    /*
	 * Retry if necessary
	 */
#if 0
    pfring_ft_table *ft = fts[fs->rx_port];
    pfring_ft_pcap_pkthdr h;
    pfring_ft_ext_pkthdr ext_hdr = {0};
    uint16_t i;

    if (unlikely(nb_rx == 0))
    {
        pfring_ft_housekeeping(ft, time(NULL));
        // return nb_pkt;
    }

    for (i = 0; i < nb_rx; i++)
    {
        char *data = rte_pktmbuf_mtod(pkts_burst[i], char *);
        int len = rte_pktmbuf_pkt_len(pkts_burst[i]);

        h.len = h.caplen = len;
        gettimeofday(&h.ts, NULL);
        // printf("pfring_ft_process nb_rx %u\n", nb_rx);
        pfring_ft_process(ft, (const u_char *)data, &h, &ext_hdr);

        // statistics[portid].num_pkts++;
        // statistics[portid].num_bytes += len + 24;

        // rte_pktmbuf_free(bufs[i]);
    }
#endif
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
/* ************************************ */
static void
goblin_init(portid_t pi)
{
    printf("\n++++++++++++++++++++++++ port%u goblin_init +++++++++++++++++++++++++\n", pi);
    // nic_xstats_display(pi);
}
/* ************************************ */
static void
goblin_uninit(portid_t pi)
{
    printf("\n++++++++++++++++++++++++ port%u goblin_uninit +++++++++++++++++++++++++\n", pi);
    // zmq_close(zmq_clients[pi]);
}
/* ************************************ */
static void
goblin_port_print_stats(portid_t pi)
{
    // struct capture_interfaces_info capture_info;
    // struct rte_eth_stats stats;
    uint64_t mpps_rx, mpps_tx, mbps_rx, mbps_tx;
    // nic_xstats_display(pi);
    nic_stats_display(pi);

    // snprintf(capture_info.ifname, 64, "goblin(%s)", ifaces[pi]);
    snprintf(capture_info.ifname, 64, "%s", ifaces[pi]);

    send_stats(pi);
    printf("\n  =================== Port %u goblin statistics ========================\n", pi);

    printf("  tot_pkts:   %-10" PRIu64 " tot_bytes:  %-10" PRIu64 "  recv_bytes: "
           "%-" PRIu64 "\n",
           capture_info.tot_pkts, capture_info.tot_bytes, capture_info.recv_bytes);

    printf("  sent_bytes: %-10" PRIu64 " recv_pkts:  %-10" PRIu64 "  sent_pkts:  "
           "%-" PRIu64 "\n",
           capture_info.sent_bytes, capture_info.recv_pkts, capture_info.sent_pkts);

    printf("  drop_pkts: %-10" PRIu64 "  tx_thoughput: %-10" PRIu64 "rx_thoughput:  "
           "%-" PRIu64 "\n",
           capture_info.drop_pkts, capture_info.tx_thoughput, capture_info.rx_thoughput);
    printf("  ifname: %s\n", capture_info.ifname);
    // pkt_fwd_config_display(&cur_fwd_config);
    // rte_exit(EXIT_FAILURE, "goblin_port_print_stats %u\n", cur_fwd_config.nb_fwd_lcores);
}
/* ************************************ */
uint16_t goblin_rx_callback(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
                            uint16_t nb_pkts, __rte_unused uint16_t max_pkts,
                            __rte_unused void *user_param)
{
    uint16_t i;
    pfring_ft_table *ft = fts[port_id];

    if (unlikely(nb_pkts == 0))
    {
        pfring_ft_housekeeping(ft, time(NULL));
    }
    else
    {
        for (i = 0; i < nb_pkts; i++)
        {
            send2ft(ft, nb_pkts, pkts[i]);
        }
    }

    // dump_rx_pkts(port_id, queue, pkts, nb_pkts, max_pkts, user_param);
    return nb_pkts;
}

/* ************************************ */
static void app_init(portid_t nb_p)
{
    int ret = 0, q;
    static u_int32_t ft_flags = 0;
    /**************************** ZMQ Init ****************************/
    ret = init_zmq(nb_p);
    if (ret != 0)
    {
        rte_exit(EXIT_FAILURE, "ZMQ init failed: %s\n", strerror(-ret));
    }

    if (enable_l7)
    {
        /************************ PFRING FT Init **************************/
        ret = initft(nb_p);
        if (ret != 0)
        {
            rte_exit(EXIT_FAILURE, "ft init failed: %s\n", strerror(-ret));
        }
    }
}
/* ************************************ */
static void
app_uninit(portid_t nb_p)
{
    int i;

    if (enable_l7)
    {
        uinitft((uint8_t)nb_p);
    }
    uinit_zmq((uint8_t)nb_p);
}
/* ************************************ */
struct fwd_engine goblin_engine = {
    .fwd_mode_name = "goblin",
    .app_init = app_init,
    .port_fwd_begin = goblin_init,
    .port_fwd_end = goblin_uninit,
    .packet_fwd = goblin_main_func,
    .print_stats = goblin_port_print_stats,
    .rx_callback = goblin_rx_callback,
    .app_uninit = app_uninit,
};
