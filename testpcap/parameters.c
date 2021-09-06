/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_string_fns.h>
#ifdef RTE_NET_BOND
#include <rte_eth_bond.h>
#endif
#include <rte_flow.h>

#include "main.h"

static void
usage(char *progname)
{
    printf("\nUsage: %s [EAL options] -- [goblin options]\n\n",
           progname);
    printf("  --i <devices>     Devices (interface names)\n");
    printf("  --S: force link speed.\n");
    printf("  --help: display this message and quit.\n");
    printf("  --stats-period=PERIOD: statistics will be shown "
           "every PERIOD seconds (only if interactive is disabled).\n");
    printf("  --l7: enable L7 protocol.\n");
    printf("  --nb-cores=N: set the number of forwarding cores "
           "(1 <= N <= %d).\n",
           nb_lcores);
    printf("  --nb-ports=N: set the number of forwarding ports "
           "(1 <= N <= %d).\n",
           nb_ports);
    printf("  --coremask=COREMASK: hexadecimal bitmask of cores running "
           "the packet forwarding test. The main lcore is reserved for "
           "command line parsing only, and cannot be masked on for "
           "packet forwarding.\n");
    printf("  --portmask=PORTMASK: hexadecimal bitmask of ports used "
           "by the packet forwarding test.\n");
    printf("  --portlist=PORTLIST: list of forwarding ports\n");
    printf("  --numa: enable NUMA-aware allocation of RX/TX rings and of "
           "RX memory buffers (mbufs).\n");
    printf("  --no-numa: disable NUMA-aware allocation.\n");
    printf("  --port-numa-config=(port,socket)[,(port,socket)]: "
           "specify the socket on which the memory pool "
           "used by the port will be allocated.\n");
    printf("  --ring-numa-config=(port,flag,socket)[,(port,flag,socket)]: "
           "specify the socket on which the TX/RX rings for "
           "the port will be allocated "
           "(flag: 1 for RX; 2 for TX; 3 for RX and TX).\n");
    printf("  --socket-num=N: set socket from which all memory is allocated "
           "in NUMA mode.\n");
    printf("  --mbuf-size=N,[N1[,..Nn]: set the data size of mbuf to "
           "N bytes. If multiple numbers are specified the extra pools "
           "will be created to receive with packet split features\n");
    printf("  --total-num-mbufs=N: set the number of mbufs to be allocated "
           "in mbuf pools.\n");
    printf("  --max-pkt-len=N: set the maximum size of packet to N bytes.\n");

    printf("  --port-topology=<paired|chained|loop>: set port topology (paired "
           "is default).\n");

    printf("  --no-flush-rx: Don't flush RX streams before forwarding."
           " Used mainly with PCAP drivers.\n");
    printf("  --rxoffs=X[,Y]*: set RX segment offsets for split.\n");
    printf("  --rxpkts=X[,Y]*: set RX segment sizes to split.\n");
    printf("  --txpkts=X[,Y]*: set TX segment sizes"
           " or total packet length.\n");
    printf("  --txonly-multi-flow: generate multiple flows in txonly mode\n");

    printf("  --disable-link-check: disable check on link status when "
           "starting/stopping ports.\n");

    printf("  --bitrate-stats=N: set the logical core N to perform "
           "bit-rate calculation.\n");

    printf("  --geneve-parsed-port=N: UPD port to parse GENEVE tunnel protocol\n");
    printf("  --mp-alloc <native|anon|xmem|xmemhuge>: mempool allocation method.\n"
           "    native: use regular DPDK memory to create and populate mempool\n"
           "    anon: use regular DPDK memory to create and anonymous memory to populate mempool\n"
           "    xmem: use anonymous memory to create and populate mempool\n"
           "    xmemhuge: use anonymous hugepage memory to create and populate mempool\n");
    printf("  --rx-mq-mode=0xX: hexadecimal bitmask of RX mq mode can be "
           "enabled\n");
    printf("  --record-core-cycles: enable measurement of CPU cycles.\n");
}

/*
 * Parse the coremask given as argument (hexadecimal string) and set
 * the global configuration of forwarding cores.
 */
static void
parse_fwd_coremask(const char *coremask)
{
    char *end;
    unsigned long long int cm;

    /* parse hexadecimal string */
    end = NULL;
    cm = strtoull(coremask, &end, 16);
    if ((coremask[0] == '\0') || (end == NULL) || (*end != '\0'))
        rte_exit(EXIT_FAILURE, "Invalid fwd core mask\n");
    else if (set_fwd_lcores_mask((uint64_t)cm) < 0)
        rte_exit(EXIT_FAILURE, "coremask is not valid\n");
}

/*
 * Parse the coremask given as argument (hexadecimal string) and set
 * the global configuration of forwarding cores.
 */
static void
parse_fwd_portmask(const char *portmask)
{
    char *end;
    unsigned long long int pm;

    /* parse hexadecimal string */
    end = NULL;
    pm = strtoull(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        rte_exit(EXIT_FAILURE, "Invalid fwd port mask\n");
    else
        set_fwd_ports_mask((uint64_t)pm);
}

static void
print_invalid_socket_id_error(void)
{
    unsigned int i = 0;

    printf("Invalid socket id, options are: ");
    for (i = 0; i < num_sockets; i++)
    {
        printf("%u%s", socket_ids[i],
               (i == num_sockets - 1) ? "\n" : ",");
    }
}

static int
parse_portnuma_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    uint8_t i, socket_id;
    portid_t port_id;
    unsigned size;
    enum fieldnames
    {
        FLD_PORT = 0,
        FLD_SOCKET,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];

    /* reset from value set at definition */
    while ((p = strchr(p0, '(')) != NULL)
    {
        ++p;
        if ((p0 = strchr(p, ')')) == NULL)
            return -1;

        size = p0 - p;
        if (size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++)
        {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        port_id = (portid_t)int_fld[FLD_PORT];
        if (port_id_is_invalid(port_id, ENABLED_WARN) ||
            port_id == (portid_t)RTE_PORT_ALL)
        {
            print_valid_ports();
            return -1;
        }
        socket_id = (uint8_t)int_fld[FLD_SOCKET];
        if (new_socket_id(socket_id))
        {
            if (num_sockets >= RTE_MAX_NUMA_NODES)
            {
                print_invalid_socket_id_error();
                return -1;
            }
            socket_ids[num_sockets++] = socket_id;
        }
        port_numa[port_id] = socket_id;
    }

    return 0;
}

static int
parse_ringnuma_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    uint8_t i, ring_flag, socket_id;
    portid_t port_id;
    unsigned size;
    enum fieldnames
    {
        FLD_PORT = 0,
        FLD_FLAG,
        FLD_SOCKET,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
#define RX_RING_ONLY 0x1
#define TX_RING_ONLY 0x2
#define RXTX_RING 0x3

    /* reset from value set at definition */
    while ((p = strchr(p0, '(')) != NULL)
    {
        ++p;
        if ((p0 = strchr(p, ')')) == NULL)
            return -1;

        size = p0 - p;
        if (size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++)
        {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        port_id = (portid_t)int_fld[FLD_PORT];
        if (port_id_is_invalid(port_id, ENABLED_WARN) ||
            port_id == (portid_t)RTE_PORT_ALL)
        {
            print_valid_ports();
            return -1;
        }
        socket_id = (uint8_t)int_fld[FLD_SOCKET];
        if (new_socket_id(socket_id))
        {
            if (num_sockets >= RTE_MAX_NUMA_NODES)
            {
                print_invalid_socket_id_error();
                return -1;
            }
            socket_ids[num_sockets++] = socket_id;
        }
        ring_flag = (uint8_t)int_fld[FLD_FLAG];
        if ((ring_flag < RX_RING_ONLY) || (ring_flag > RXTX_RING))
        {
            printf("Invalid ring-flag=%d config for port =%d\n",
                   ring_flag, port_id);
            return -1;
        }

        switch (ring_flag & RXTX_RING)
        {
        case RX_RING_ONLY:
            rxring_numa[port_id] = socket_id;
            break;
        case TX_RING_ONLY:
            txring_numa[port_id] = socket_id;
            break;
        case RXTX_RING:
            rxring_numa[port_id] = socket_id;
            txring_numa[port_id] = socket_id;
            break;
        default:
            printf("Invalid ring-flag=%d config for port=%d\n",
                   ring_flag, port_id);
            break;
        }
    }

    return 0;
}

static int
parse_event_printing_config(const char *optarg, int enable)
{
    uint32_t mask = 0;

    if (!strcmp(optarg, "unknown"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_UNKNOWN;
    else if (!strcmp(optarg, "intr_lsc"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_INTR_LSC;
    else if (!strcmp(optarg, "queue_state"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_QUEUE_STATE;
    else if (!strcmp(optarg, "intr_reset"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_INTR_RESET;
    else if (!strcmp(optarg, "vf_mbox"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_VF_MBOX;
    else if (!strcmp(optarg, "ipsec"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_IPSEC;
    else if (!strcmp(optarg, "macsec"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_MACSEC;
    else if (!strcmp(optarg, "intr_rmv"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_INTR_RMV;
    else if (!strcmp(optarg, "dev_probed"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_NEW;
    else if (!strcmp(optarg, "dev_released"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_DESTROY;
    else if (!strcmp(optarg, "flow_aged"))
        mask = UINT32_C(1) << RTE_ETH_EVENT_FLOW_AGED;
    else if (!strcmp(optarg, "all"))
        mask = ~UINT32_C(0);
    else
    {
        fprintf(stderr, "Invalid event: %s\n", optarg);
        return -1;
    }
    if (enable)
        event_print_mask |= mask;
    else
        event_print_mask &= ~mask;
    return 0;
}

static int
parse_link_speed(int n)
{
    uint32_t speed = ETH_LINK_SPEED_FIXED;

    switch (n)
    {
    case 1:
        speed |= ETH_LINK_SPEED_1G;
        break;
    case 10:
        speed |= ETH_LINK_SPEED_10G;
        break;
    case 25:
        speed |= ETH_LINK_SPEED_25G;
        break;
    case 40:
        speed |= ETH_LINK_SPEED_40G;
        break;
    case 50:
        speed |= ETH_LINK_SPEED_50G;
        break;
    case 100:
        speed |= ETH_LINK_SPEED_100G;
        break;
    case 200:
        speed |= ETH_LINK_SPEED_200G;
        break;
    default:
        rte_exit(EXIT_FAILURE, "Unsupported fixed speed %u\n", n);
        return 0;
    }

    return speed;
}

static int parse_iface(char *optarg)
{
    int i = 0;
    char *p = strtok(optarg, ",");

    if (strlen(optarg) > 0)
    {
        memset(ifaces[i], '\0', sizeof(ifaces[i]));
        while (p != NULL)
        {
            // snprintf(ifaces[i], sizeof(ifaces[i]),"%s", p);
            strcpy(ifaces[i], p);
            printf(" %s\n", p);
            p = strtok(NULL, ",");
            i++;
            // strcpy(ifaces,p);
        }
        return 0;
    }
    else
    {
        rte_exit(EXIT_FAILURE, "Invalid interface %s\n", optarg);
    }
}

void launch_args_parse(int argc, char **argv)
{
    int n, opt;
    char **argvopt;
    int opt_idx;
    portid_t pid;
    enum
    {
        TX,
        RX
    };
    /* Default offloads for all ports. */
    uint64_t rx_offloads = rx_mode.offloads;
    uint64_t tx_offloads = tx_mode.offloads;
    struct rte_eth_dev_info dev_info;
    uint16_t rec_nb_pkts;
    int ret;

    static struct option lgopts[] = {
        {"help", 0, 0, 0},
        {"stats-period", 1, 0, 0},
        {"nb-cores", 1, 0, 0},
        {"nb-ports", 1, 0, 0},
        {"coremask", 1, 0, 0},
        {"portmask", 1, 0, 0},
        {"portlist", 1, 0, 0},
        {"numa", 0, 0, 0},
        {"no-numa", 0, 0, 0},
        {"mp-anon", 0, 0, 0}, /* deprecated */
        {"port-numa-config", 1, 0, 0},
        {"ring-numa-config", 1, 0, 0},
        {"socket-num", 1, 0, 0},
        {"mbuf-size", 1, 0, 0},
        {"total-num-mbufs", 1, 0, 0},
        {"max-pkt-len", 1, 0, 0},

        {"port-topology", 1, 0, 0},
        {"i", 1, 0, 0},
        {"l7", 1, 0, 0},

        {"no-flush-rx", 0, 0, 0},
        {"rxoffs", 1, 0, 0},
        {"rxpkts", 1, 0, 0},
        {"txpkts", 1, 0, 0},
        {"txonly-multi-flow", 0, 0, 0},
        {"S", 1, 0, 0},
        {"disable-link-check", 0, 0, 0},

        {"geneve-parsed-port", 1, 0, 0},
        {"mlockall", 0, 0, 0},
        {"no-mlockall", 0, 0, 0},
        {"mp-alloc", 1, 0, 0},

        {"no-iova-contig", 0, 0, 0},
        {"rx-mq-mode", 1, 0, 0},
        {"record-core-cycles", 0, 0, 0},
        {"record-burst-stats", 0, 0, 0},
        {0, 0, 0, 0},
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "i"
                                             "ah",
                              lgopts, &opt_idx)) != EOF)
    {
        switch (opt)
        {
        case 'a':
            printf("Auto-start selected\n");
            auto_start = 1;
            break;

        case 0: /*long options */
            if (!strcmp(lgopts[opt_idx].name, "help"))
            {
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            }

            if (!strcmp(lgopts[opt_idx].name, "i"))
            {
                parse_iface(optarg);
            }

            if (!strcmp(lgopts[opt_idx].name, "l7"))
            {
                // parse_iface(optarg);

                enable_l7 = atoi(optarg);
                if (enable_l7)
                {
                    verbose_level = 1;
                }
                else
                {
                    verbose_level = 0;
                }
            }

            if (!strcmp(lgopts[opt_idx].name, "nb-ports"))
            {
                n = atoi(optarg);
                if (n > 0 && n <= nb_ports)
                    nb_fwd_ports = n;
                else
                    rte_exit(EXIT_FAILURE,
                             "Invalid port %d\n", n);
            }
            if (!strcmp(lgopts[opt_idx].name, "nb-cores"))
            {
                n = atoi(optarg);
                if (n > 0 && n <= nb_lcores)
                    nb_fwd_lcores = (uint8_t)n;
                else
                    rte_exit(EXIT_FAILURE,
                             "nb-cores should be > 0 and <= %d\n",
                             nb_lcores);
            }
            if (!strcmp(lgopts[opt_idx].name, "stats-period"))
            {
                char *end = NULL;
                unsigned int n;

                n = strtoul(optarg, &end, 10);
                if ((optarg[0] == '\0') || (end == NULL) ||
                    (*end != '\0'))
                    break;

                stats_period = n;
                break;
            }
            if (!strcmp(lgopts[opt_idx].name, "coremask"))
                parse_fwd_coremask(optarg);
            if (!strcmp(lgopts[opt_idx].name, "portmask"))
                parse_fwd_portmask(optarg);
            if (!strcmp(lgopts[opt_idx].name, "portlist"))
                parse_fwd_portlist(optarg);
            if (!strcmp(lgopts[opt_idx].name, "no-numa"))
                numa_support = 0;
            if (!strcmp(lgopts[opt_idx].name, "numa"))
                numa_support = 1;
            if (!strcmp(lgopts[opt_idx].name, "mp-anon"))
            {
                mp_alloc_type = MP_ALLOC_ANON;
            }

            if (!strcmp(lgopts[opt_idx].name, "port-numa-config"))
            {
                if (parse_portnuma_config(optarg))
                    rte_exit(EXIT_FAILURE,
                             "invalid port-numa configuration\n");
            }
            if (!strcmp(lgopts[opt_idx].name, "ring-numa-config"))
                if (parse_ringnuma_config(optarg))
                    rte_exit(EXIT_FAILURE,
                             "invalid ring-numa configuration\n");
            if (!strcmp(lgopts[opt_idx].name, "socket-num"))
            {
                n = atoi(optarg);
                if (!new_socket_id((uint8_t)n))
                {
                    socket_num = (uint8_t)n;
                }
                else
                {
                    print_invalid_socket_id_error();
                    rte_exit(EXIT_FAILURE,
                             "Invalid socket id");
                }
            }
            if (!strcmp(lgopts[opt_idx].name, "mbuf-size"))
            {
                unsigned int mb_sz[MAX_SEGS_BUFFER_SPLIT];
                unsigned int nb_segs, i;

                // nb_segs = parse_item_list(optarg, "mbuf-size",
                //                           MAX_SEGS_BUFFER_SPLIT, mb_sz, 0);
                if (nb_segs <= 0)
                    rte_exit(EXIT_FAILURE,
                             "bad mbuf-size\n");
                for (i = 0; i < nb_segs; i++)
                {
                    if (mb_sz[i] <= 0 || mb_sz[i] > 0xFFFF)
                        rte_exit(EXIT_FAILURE,
                                 "mbuf-size should be "
                                 "> 0 and < 65536\n");
                    mbuf_data_size[i] = (uint16_t)mb_sz[i];
                }
                mbuf_data_size_n = nb_segs;
            }
            if (!strcmp(lgopts[opt_idx].name, "total-num-mbufs"))
            {
                n = atoi(optarg);
                if (n > 1024)
                    param_total_num_mbufs = (unsigned)n;
                else
                    rte_exit(EXIT_FAILURE,
                             "total-num-mbufs should be > 1024\n");
            }

            if (!strcmp(lgopts[opt_idx].name, "max-pkt-len"))
            {
                n = atoi(optarg);
                if (n >= RTE_ETHER_MIN_LEN)
                    rx_mode.max_rx_pkt_len = (uint32_t)n;
                else
                    rte_exit(EXIT_FAILURE,
                             "Invalid max-pkt-len=%d - should be > %d\n",
                             n, RTE_ETHER_MIN_LEN);
            }

            if (!strcmp(lgopts[opt_idx].name, "port-topology"))
            {
                if (!strcmp(optarg, "paired"))
                    port_topology = PORT_TOPOLOGY_PAIRED;
                else if (!strcmp(optarg, "chained"))
                    port_topology = PORT_TOPOLOGY_CHAINED;
                else if (!strcmp(optarg, "loop"))
                    port_topology = PORT_TOPOLOGY_LOOP;
                else
                    rte_exit(EXIT_FAILURE, "port-topology %s invalid -"
                                           " must be: paired, chained or loop\n",
                             optarg);
            }

            if (!nb_rxq && !nb_txq)
            {
                rte_exit(EXIT_FAILURE, "Either rx or tx queues should "
                                       "be non-zero\n");
            }

            if (!strcmp(lgopts[opt_idx].name, "rxoffs"))
            {
                unsigned int seg_off[MAX_SEGS_BUFFER_SPLIT];
                unsigned int nb_offs;

                // nb_offs = parse_item_list(optarg, "rxpkt offsets",
                //                           MAX_SEGS_BUFFER_SPLIT,
                //                           seg_off, 0);
                if (nb_offs > 0)
                    set_rx_pkt_offsets(seg_off, nb_offs);
                else
                    rte_exit(EXIT_FAILURE, "bad rxoffs\n");
            }
            if (!strcmp(lgopts[opt_idx].name, "rxpkts"))
            {
                unsigned int seg_len[MAX_SEGS_BUFFER_SPLIT];
                unsigned int nb_segs;

                // nb_segs = parse_item_list(optarg, "rxpkt segments",
                //                           MAX_SEGS_BUFFER_SPLIT,
                //                           seg_len, 0);
                if (nb_segs > 0)
                    set_rx_pkt_segments(seg_len, nb_segs);
                else
                    rte_exit(EXIT_FAILURE, "bad rxpkts\n");
            }
            if (!strcmp(lgopts[opt_idx].name, "txpkts"))
            {
                unsigned seg_lengths[RTE_MAX_SEGS_PER_PKT];
                unsigned int nb_segs;

                // nb_segs = parse_item_list(optarg, "txpkt segments",
                //                           RTE_MAX_SEGS_PER_PKT, seg_lengths, 0);
                if (nb_segs > 0)
                    set_tx_pkt_segments(seg_lengths, nb_segs);
                else
                    rte_exit(EXIT_FAILURE, "bad txpkts\n");
            }
            if (!strcmp(lgopts[opt_idx].name, "txonly-multi-flow"))
                txonly_multi_flow = 1;
            if (!strcmp(lgopts[opt_idx].name, "no-flush-rx"))
                no_flush_rx = 1;
            if (!strcmp(lgopts[opt_idx].name, "S"))
            {
                n = atoi(optarg);
                if (n >= 0 && parse_link_speed(n) > 0)
                    eth_link_speed = parse_link_speed(n);
            }
            if (!strcmp(lgopts[opt_idx].name, "disable-link-check"))
                no_link_check = 1;

            if (!strcmp(lgopts[opt_idx].name, "no-iova-contig"))
                mempool_flags = MEMPOOL_F_NO_IOVA_CONTIG;

            if (!strcmp(lgopts[opt_idx].name, "rx-mq-mode"))
            {
                char *end = NULL;
                n = strtoul(optarg, &end, 16);
                if (n >= 0 && n <= ETH_MQ_RX_VMDQ_DCB_RSS)
                    rx_mq_mode = (enum rte_eth_rx_mq_mode)n;
                else
                    rte_exit(EXIT_FAILURE,
                             "rx-mq-mode must be >= 0 and <= %d\n",
                             ETH_MQ_RX_VMDQ_DCB_RSS);
            }
            if (!strcmp(lgopts[opt_idx].name, "record-core-cycles"))
                record_core_cycles = 1;
            if (!strcmp(lgopts[opt_idx].name, "record-burst-stats"))
                record_burst_stats = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        default:
            usage(argv[0]);
            printf("Invalid option: %s\n", argv[optind]);
            rte_exit(EXIT_FAILURE,
                     "Command line is incomplete or incorrect\n");
            break;
        }
    }

    if (optind != argc)
    {
        usage(argv[0]);
        printf("Invalid parameter: %s\n", argv[optind]);
        rte_exit(EXIT_FAILURE, "Command line is incorrect\n");
    }

    /* Set offload configuration from command line parameters. */
    rx_mode.offloads = rx_offloads;
    tx_mode.offloads = tx_offloads;

    if (mempool_flags & MEMPOOL_F_NO_IOVA_CONTIG &&
        mp_alloc_type != MP_ALLOC_ANON)
    {
        TESTPMD_LOG(WARNING, "cannot use no-iova-contig without "
                             "mp-alloc=anon. mempool no-iova-contig is "
                             "ignored\n");
        mempool_flags = 0;
    }
}
