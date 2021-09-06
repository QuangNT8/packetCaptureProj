
#include "../inc/dpdk.h"

extern u_int8_t do_loop;

/* ************************************ */
void print_help(void)
{
    printf("goblin_dpdk - (C)\n");
    printf("Usage: goblin_dpdk [EAL options] -- [options]\n");
    printf("-p <id>[,<id>]  Port id (up to 2 ports are supported)\n");
    printf("-n <num cores>  Enable multiple cores/queues (default: 1)\n");
    printf("-i <devices>     Devices (interface names)\n");
    printf("-S <speed>      Set the port speed in Gbit/s (1/10/25/40/50/100)\n");
    printf("-g              Goblin (set this device for Goblin)\n");
    printf("-h              Print this help\n");
    printf("-Z <zmq endpoint>    Set the ZMQ endpoint (default: %s)\n", DEFAULT_ZMQ_ENDPOINT);
}

/* ************************************ */
/* Parse the argument given in the command line of the application */
int parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "FhHlmi:l:M:n:p:tUvP:S:T:K01g:2:7", lgopts, &option_index)) != EOF)
    {
        switch (opt)
        {
        case 'F':
            break;
        case 'h':
            print_help();
            exit(0);
            break;
        case 'H':
            break;
        case 'M':
            break;
        case 'l':
            break;
        case 'm':
            break;
        case 'n':
            if (optarg)
            {
                num_queues = atoi(optarg);
            }
            break;
        case 'p':
            break;
        case 't':
            break;

        case 'v':
            break;

        case 'g':
            isgolbindev = 1;
            goblin_port = atoi(optarg);
            break;
        case '0':
            break;
        case '1':
            rx_ring_size = atoi(optarg);
            break;
        case '2':
            tx_ring_size = atoi(optarg);
            break;
        case '7':
            break;
        case 'T':

            break;
        case 'U':
            break;
        case 'P':
            break;
        case 'S':
            port_speed = atoi(optarg);
            break;
        case 'K':
            break;
        case 'Z':
            zmq_setendpoint(strdup(optarg));
            break;
        case 'i':
            // device = strdup(optarg);
            if (optarg)
            {
                int i = 0;
                char *p = strtok(optarg, ",");

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
            }
            break;
        default:
            print_help();
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1;
    return ret;
}

/* ************************************ */
void create_mbuf_pool()
{
    unsigned nb_ports;

    nb_ports = rte_eth_dev_count_avail();
    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
    {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
}
/* ************************************ */
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{

    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = rx_ring_size;
    uint16_t nb_txd = tx_ring_size;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));
        return retval;
    }

    if (port_speed)
    {
        switch (port_speed)
        {
        case 1:
            port_conf.link_speeds = ETH_LINK_SPEED_1G;
            break;
        case 10:
            port_conf.link_speeds = ETH_LINK_SPEED_10G;
            break;
        case 25:
            port_conf.link_speeds = ETH_LINK_SPEED_25G;
            break;
        case 40:
            port_conf.link_speeds = ETH_LINK_SPEED_40G;
            break;
        case 50:
            port_conf.link_speeds = ETH_LINK_SPEED_50G;
            break;
        case 100:
            port_conf.link_speeds = ETH_LINK_SPEED_100G;
            break;
        default:
            break;
        }
        port_conf.link_speeds |= ETH_LINK_SPEED_FIXED;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           port,
           addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

/* ************************************ */

void send_stats(uint8_t queuidx)
{
    ndpi_serializer serializer;
    int ret = -1;
    u_int32_t buffer_len = 0;
    ret = stats2json(&capture_info, &serializer);
    if (ret == 0)
    {
        char *msg = ndpi_serializer_get_buffer(&serializer, &buffer_len);
        zmq_send(zmq_clients[queuidx], msg, buffer_len, 0);
        ndpi_term_serializer(&serializer);
    }
}

/* ************************************ */

void print_stats(uint8_t index)
{
    pfring_ft_stats fstat_sum = {0};
    pfring_ft_stats *fstat;
    struct rte_eth_stats pstats = {0};
    static struct timeval start_time = {0};
    static struct timeval last_time = {0};
    struct timeval end_time;

    unsigned long long n_drops = 0;
    unsigned long long tx_n_bytes = 0, tx_n_pkts = 0, tx_n_drops = 0;
    unsigned long long rx_n_bytes = 0, rx_n_pkts = 0, rx_n_drops = 0;
    unsigned long long q_n_bytes = 0, q_n_pkts = 0;

    double diff, bytes_diff;
    double delta_last = 0;
    char buf[512];
    int len;
    uint8_t portid;

    portid = lcore_params[index].port_id;

    printf("print stats [Port: %u] [Iface :%s]\n", portid, capture_info.ifname);

    if (start_time.tv_sec == 0)
        gettimeofday(&start_time, NULL);

    gettimeofday(&end_time, NULL);

    if (last_time.tv_sec > 0)
        delta_last = delta_time(&end_time, &last_time);

    memcpy(&last_time, &end_time, sizeof(last_time));

    q_n_pkts = statistics[portid].num_pkts;
    q_n_bytes = statistics[portid].num_bytes;

    len = snprintf(buf, sizeof(buf), "[Q#%u]  ", index);

    len += snprintf(&buf[len], sizeof(buf) - len, "[PORT#%u]  ", portid);

    len += snprintf(&buf[len], sizeof(buf) - len, "[Iface: %s]  ", capture_info.ifname);

    len += snprintf(&buf[len], sizeof(buf) - len,
                    "Packets: %llu\t"
                    "Bytes: %llu\t",
                    q_n_pkts,
                    q_n_bytes);

    if (delta_last)
    {
        diff = q_n_pkts - statistics[portid].last_pkts;
        bytes_diff = q_n_bytes - statistics[portid].last_bytes;
        bytes_diff /= (1000 * 1000 * 1000) / 8;

        len += snprintf(&buf[len], sizeof(buf) - len,
                        "Throughput: %.3f Mpps",
                        ((double)diff / (double)(delta_last / 1000)) / 1000000);

        capture_info.rx_thoughput = (u_int64_t)((double)bytes_diff / (double)(delta_last / 1000));

        len += snprintf(&buf[len], sizeof(buf) - len,
                        " (%.3f Gbps)\t",
                        capture_info.rx_thoughput);
    }

    statistics[portid].last_pkts = q_n_pkts;
    statistics[portid].last_bytes = q_n_bytes;

    fprintf(stderr, "%s\n", buf);

    if ((fstat = pfring_ft_get_stats(fts[index])))
    {
        fstat_sum.active_flows += fstat->active_flows;
        fstat_sum.flows += fstat->flows;
        fstat_sum.err_no_room += fstat->err_no_room;
        fstat_sum.err_no_mem += fstat->err_no_mem;
    }

    if (rte_eth_stats_get(portid, &pstats) == 0)
    {
        rx_n_pkts = pstats.ipackets;
        rx_n_bytes = pstats.ibytes + (rx_n_pkts * 24);
        n_drops = pstats.imissed + pstats.ierrors;
        tx_n_pkts = pstats.opackets;
        tx_n_bytes = pstats.obytes + (tx_n_pkts * 24);
        tx_n_drops = pstats.oerrors;
    }

    len = snprintf(buf, sizeof(buf), "[Total] ");

    len += snprintf(&buf[len], sizeof(buf) - len,
                    "ActFlows: %ju\t"
                    "TotFlows: %ju\t"
                    "Errors: %ju\t",
                    fstat_sum.active_flows,
                    fstat_sum.flows,
                    fstat_sum.err_no_room + fstat_sum.err_no_mem);

    len += snprintf(&buf[len], sizeof(buf) - len,
                    "RXPackets: %llu\t"
                    "RXBytes: %llu\t",
                    rx_n_pkts,
                    rx_n_bytes);

    len += snprintf(&buf[len], sizeof(buf) - len,
                    "Drops: %llu\t",
                    n_drops);

    len += snprintf(&buf[len], sizeof(buf) - len,
                    "TXPackets: %llu\t"
                    "TXBytes: %llu\t"
                    "TXDrops: %llu\t",
                    tx_n_pkts,
                    tx_n_bytes,
                    tx_n_drops);

    fprintf(stderr, "Port %u -- %s\n---\n", portid, buf);

    capture_info.last_actflows[portid] = fstat_sum.active_flows;
    capture_info.tot_pkts = q_n_pkts;
    capture_info.tot_bytes = q_n_bytes;
    capture_info.recv_bytes = rx_n_bytes;
    capture_info.sent_bytes = tx_n_bytes;
    capture_info.recv_pkts = rx_n_pkts;
    capture_info.sent_pkts = tx_n_pkts;
    capture_info.drop_pkts = n_drops;
    capture_info.act_flows = fstat_sum.active_flows;
    capture_info.tot_flows = fstat_sum.flows;
    capture_info.tot_err_flows = fstat_sum.err_no_room + fstat_sum.err_no_mem;
    // capture_info.rx_thoughput = bytes_diff;
    capture_info.tx_thoughput = 0;
    // if (q_n_pkts > 0)
    // {
    //     capture_info.drop_bytes = (lastBytes * (n_drops)) / rx_n_pkts;
    // }
}

/* ************************************ */

void port_close(void)
{
    int i;

    for (i = 0; i < num_ports; i++)
    {

        printf("Releasing port %u...\n", i);

        rte_eth_dev_stop(i);
        rte_eth_dev_close(i);
    }
}

/* ************************************ */
u_int8_t getGolblinPort(void)
{
    return goblin_port;
}
/* ************************************ */
void setGolblinPort(u_int8_t portidx)
{
    goblin_port = portidx;
}
/* ************************************ */
u_int8_t isGolblinDev(void)
{
    return isgolbindev;
}