
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#ifdef RTE_ETHER_MAX_LEN
#define ether_header rte_ether_hdr
#define ether_addr rte_ether_addr
#define ETHER_MAX_LEN RTE_ETHER_MAX_LEN
#else
#define ether_header ether_hdr
#endif

#define ALARM_SLEEP 1

#include "ftutils.c"

#include "pfring_ft.h"

#define RX_RING_SIZE (1 * 1024)
#define TX_RING_SIZE (1 * 1024)
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 64
#define PREFETCH_OFFSET 3
#define TX_TEST_PKT_LEN 60

//#define SCATTERED_RX_TEST
#ifdef SCATTERED_RX_TEST
#define MBUF_BUF_SIZE 512
#else
#define MBUF_BUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#endif

#define print_mac_addr(addr) printf("%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8, \
                                    addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])

#define MAX_PORT 10

struct user_data_type
{
  uint8_t port_id;
  pfring_ft_table *fts[RTE_MAX_LCORE];
};

static struct user_data_type userdata;

static struct rte_mempool *rx_mbuf_pool[RTE_MAX_LCORE] = {NULL};
static struct rte_mempool *tx_mbuf_pool[RTE_MAX_LCORE] = {NULL};
static pfring_ft_table *fts[MAX_PORT][RTE_MAX_LCORE] = {NULL};
static u_int32_t ft_flags = 0;
static u_int8_t port = 0;
static u_int8_t num_queues = 1;
static u_int8_t compute_flows = 1;
static u_int8_t do_loop = 1;
static u_int8_t verbose = 0;
static u_int8_t hw_stats = 0;
static u_int8_t fwd = 0;
static u_int8_t test_tx = 0;
static u_int8_t test_loop = 0;
static u_int8_t tx_csum_offload = 0;
static u_int8_t set_if_mac = 0;
static u_int8_t promisc = 1;
static u_int16_t mtu = 0;
static u_int16_t port_speed = 0;
static u_int16_t tx_test_pkt_len = TX_TEST_PKT_LEN;
static u_int32_t num_mbufs_per_lcore = 0;
static u_int32_t pps = 0;
static struct ether_addr if_mac = {0};
static u_int32_t rx_ring_size = RX_RING_SIZE;
static u_int32_t tx_ring_size = TX_RING_SIZE;

int num_ports;
static char ifaces[10][64];

static struct lcore_stats
{
  u_int64_t num_pkts;
  u_int64_t num_bytes;
  u_int64_t last_pkts;
  u_int64_t last_bytes;
  u_int64_t padding[2];
} stats[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = ETHER_MAX_LEN}};
  
/* ************************************ */
static int port_init(void)
{
  struct rte_eth_conf port_conf = port_conf_default;
  struct rte_eth_fc_conf fc_conf = {0};
  int retval, i;
  u_int16_t q;
  char name[64];
  uint8_t nb_ports;

  printf("port_init: num_ports = %u\n", num_ports);

  num_mbufs_per_lcore = 2 * (rx_ring_size + tx_ring_size + BURST_SIZE * 2)
#ifdef SCATTERED_RX_TEST
                        * 4
#endif
                        * (mtu ? (((mtu + ETHER_MAX_LEN - 1500) / MBUF_BUF_SIZE) + 1) : 1);

  for (q = 0; q < num_queues; q++)
  {
    snprintf(name, sizeof(name), "RX_MBUF_POOL_%u", q);
    rx_mbuf_pool[q] = rte_pktmbuf_pool_create(name, 8192, MBUF_CACHE_SIZE, 0,
                                              MBUF_BUF_SIZE, rte_socket_id());

    if (rx_mbuf_pool[q] == NULL)
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));

    snprintf(name, sizeof(name), "TX_MBUF_POOL_%u", q);
    tx_mbuf_pool[q] = rte_pktmbuf_pool_create(name, num_mbufs_per_lcore, MBUF_CACHE_SIZE, 0,
                                              MBUF_BUF_SIZE, rte_socket_id());

    if (tx_mbuf_pool[q] == NULL)
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
  }

  for (i = 0; i < num_ports; i++)
  {
    u_int8_t port_id = (u_int8_t)i;
    unsigned int numa_socket_id;

    printf("Configuring port %u...\n", port_id);

    fc_conf.mode = RTE_FC_NONE;
    fc_conf.autoneg = 0;

    // if (rte_eth_dev_flow_ctrl_set(port_id, &fc_conf) != 0)
    // printf("Unable to disable autoneg and flow control\n");

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

    if (tx_csum_offload)
    {
      port_conf.txmode.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM;
    }

    retval = rte_eth_dev_configure(port_id, 1 /* RX */, 1 /* TX */, &port_conf);

    if (retval != 0)
    {
      return retval;
    }

    if (mtu)
    {
      if (rte_eth_dev_set_mtu(port_id, mtu) != 0)
      {
        printf("Unable to set the MTU\n");
      }
      else
      {
        printf("MTU set to %u on port %u\n", mtu, port_id);
      }
    }

    numa_socket_id = rte_eth_dev_socket_id(port_id);

    for (q = 0; q < num_queues; q++)
    {

      printf("Configuring queue %u...\n", q);

      retval = rte_eth_rx_queue_setup(port_id, q, rx_ring_size, numa_socket_id, NULL, rx_mbuf_pool[q]);

      if (retval < 0)
      {
        return retval;
      }

      retval = rte_eth_tx_queue_setup(port_id, q, tx_ring_size, numa_socket_id, NULL);

      if (retval < 0)
      {
        return retval;
      }
    }

    retval = rte_eth_dev_start(port_id);

    if (retval < 0)
      return retval;

    if (promisc && !set_if_mac)
      rte_eth_promiscuous_enable(port_id);

    if (rte_eth_dev_set_link_up(port_id) < 0)
      printf("Unable to set link up\n");
  }

  if (set_if_mac)
  {
    retval = rte_eth_dev_default_mac_addr_set(port, &if_mac);
    if (retval != 0)
      printf("Unable to set the interface MAC address (%d)\n", retval);
  }

  return 0;
}

/* ************************************ */
/* ************************************ */

static void port_close(void)
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

void processFlow(pfring_ft_flow *flow, void *user)
{

  printf("processFlow \n");
  struct user_data_type *get_user_data = (struct user_data_type *)user;

  // pfring_ft_table *ft = (pfring_ft_table *) user;
  pfring_ft_table *ft = get_user_data->fts;
  pfring_ft_flow_key *k;
  pfring_ft_flow_value *v;
  char buf1[32], buf2[32], buf3[32];
  const char *ip1, *ip2;

  k = pfring_ft_flow_get_key(flow);
  v = pfring_ft_flow_get_value(flow);

  if (k->ip_version == 4)
  {
    ip1 = _intoa(k->saddr.v4, buf1, sizeof(buf1));
    ip2 = _intoa(k->daddr.v4, buf2, sizeof(buf2));
  }
  else
  {
    ip1 = inet_ntop(AF_INET6, &k->saddr.v6, buf1, sizeof(buf1));
    ip2 = inet_ntop(AF_INET6, &k->daddr.v6, buf2, sizeof(buf2));
  }
  printf("processFlow port_id %u\n", get_user_data->port_id);
#if 1

  printf("[Flow] "
         "srcIp: %s, dstIp: %s, srcPort: %u, dstPort: %u, protocol: %u, tcpFlags: 0x%02X, "
         "l7: %s, "
         "c2s: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
         "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }\n",
         ip1, ip2, k->sport, k->dport, k->protocol, v->direction[s2d_direction].tcp_flags | v->direction[d2s_direction].tcp_flags,
         pfring_ft_l7_protocol_name(ft, &v->l7_protocol, buf3, sizeof(buf3)),
         v->direction[s2d_direction].pkts, v->direction[s2d_direction].bytes,
         (u_int)v->direction[s2d_direction].first.tv_sec, (u_int)v->direction[s2d_direction].first.tv_usec,
         (u_int)v->direction[s2d_direction].last.tv_sec, (u_int)v->direction[s2d_direction].last.tv_usec,
         v->direction[d2s_direction].pkts, v->direction[d2s_direction].bytes,
         (u_int)v->direction[d2s_direction].first.tv_sec, (u_int)v->direction[d2s_direction].first.tv_usec,
         (u_int)v->direction[d2s_direction].last.tv_sec, (u_int)v->direction[d2s_direction].last.tv_usec);
#endif
  pfring_ft_flow_free(flow);
}

/* ************************************ */
static int capture2ft(uint16_t portid, pfring_ft_table *ft) {
    struct rte_mbuf *bufs[BURST_SIZE];
    pfring_ft_pcap_pkthdr h;
    pfring_ft_ext_pkthdr ext_hdr = {0};
    uint16_t num,i;
    
    // ft = userdata.fts[portid];
    
    num = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);
    
    if (unlikely(num == 0)) {
        pfring_ft_housekeeping(ft, time(NULL));
        return num;
    }

    for (i = 0; i < PREFETCH_OFFSET && i < num; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
    }

    for (i = 0; i < num; i++) {
        char *data = rte_pktmbuf_mtod(bufs[i], char *);
        int len = rte_pktmbuf_pkt_len(bufs[i]);
        
        pfring_ft_action action = PFRING_FT_ACTION_DEFAULT;
        h.len = h.caplen = len;
        gettimeofday(&h.ts, NULL);

        action = pfring_ft_process(ft, (const u_char *)data, &h, &ext_hdr);
        

        stats[portid].num_pkts++;
        stats[portid].num_bytes += len + 24;

        rte_pktmbuf_free(bufs[i]);
    }

    return num;
}
/* ************************************ */
#include "test.c"
static int processing_thread(__attribute__((unused)) void *arg)
{
  unsigned lcore_id = rte_lcore_id();
  unsigned lcore_index = rte_lcore_index(lcore_id);
  u_int16_t queue_id = lcore_index;
  u_int16_t num;
  u_int32_t i;

  if (lcore_index >= nb_lcore_params) {
    return (-1);
  } 
  
  printf("Capturing from port %u lcore_id %u...\n",  lcore_params[lcore_index].port_id,  lcore_params[lcore_index].lcore_id);
  
  while (do_loop) {
    // printf(".");
    
    // if (lcore_params[lcore_index].lcore_id == lcore_id) {
    //   printf("Capturing from port %u lcore_id %u...\n",  lcore_params[lcore_index].port_id,  lcore_params[lcore_index].lcore_id);
    // }
    // printf("processing_thread >> lcore_id lcore_index>>>>> %u %u\n",lcore_id, lcore_index);
    // if (lcore_params[lcore_index].lcore_id == lcore_id) {
    //   printf("Capturing from port %u lcore_id %u...\n",  lcore_params[lcore_index].port_id,  lcore_params[lcore_index].lcore_id);
    // }
    
    num = capture2ft(lcore_params[lcore_index].port_id, userdata.fts[lcore_index]);
    
    if (num == 0) {
        continue;
    }
  }

  return 0;
}

/* ************************************ */

static void print_help(void)
{
  printf("ftflow_dpdk - (C) 2018 ntop.org\n");
  printf("Usage: ftflow_dpdk [EAL options] -- [options]\n");
  printf("-p <id>[,<id>]  Port id (up to 2 ports are supported)\n");
  printf("-7              Enable L7 protocol detection (nDPI)\n");
  printf("-n <num cores>  Enable multiple cores/queues (default: 1)\n");
  printf("-0              Do not compute flows (packet capture only)\n");
  printf("-F              Enable forwarding when 2 ports are specified in -p\n");
  printf("-M <addr>       Set the port MAC address\n");
  printf("-U              Do not set promisc\n");
  printf("-S <speed>      Set the port speed in Gbit/s (1/10/25/40/50/100)\n");
  printf("-m <mtu>        Set the MTU\n");
  printf("-l              Test TX+RX (requires -p <id>,<id> cross connected)\n");
  printf("-t              Test TX\n");
  printf("-T <size>       TX test - packet size\n");
  printf("-K              TX test - enable checksum offload\n");
  printf("-P <pps>        TX test - packet rate (pps)\n");
  printf("-1 <size>       RX ring size\n");
  printf("-2 <size>       TX ring size\n");
  printf("-H              Print hardware stats\n");
  printf("-v              Verbose (print raw packets)\n");
  printf("-h              Print this help\n");
}

/* ************************************ */

static int parse_args(int argc, char **argv)
{
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  u_int mac_a, mac_b, mac_c, mac_d, mac_e, mac_f;
  static struct option lgopts[] = {
      {NULL, 0, 0, 0}};

  argvopt = argv;

  while ((opt = getopt_long(argc, argvopt, "FhHlmi:M:n:p:tUvP:S:T:K01:2:7", lgopts, &option_index)) != EOF)
  {
    switch (opt)
    {
    case 'F':
      fwd = 1;
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 'H':
      hw_stats = 1;
      break;
    case 'M':
      if (sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &mac_a, &mac_b, &mac_c, &mac_d, &mac_e, &mac_f) != 6)
      {
        printf("Invalid MAC address format (XX:XX:XX:XX:XX:XX)\n");
        exit(0);
      }
      if_mac.addr_bytes[0] = mac_a, if_mac.addr_bytes[1] = mac_b, if_mac.addr_bytes[2] = mac_c,
      if_mac.addr_bytes[3] = mac_d, if_mac.addr_bytes[4] = mac_e, if_mac.addr_bytes[5] = mac_f;
      set_if_mac = 1;
      break;
    case 'l':
      test_loop = 1;
      compute_csum = 0;
      compute_flows = 0;
      break;
    case 'm':
      mtu = atoi(optarg);
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
      test_tx = 1;
      compute_csum = 0;
      verbose = 1;
      break;
    case '0':
      compute_flows = 0;
      break;
    case '1':
      rx_ring_size = atoi(optarg);
      break;
    case '2':
      tx_ring_size = atoi(optarg);
      break;
    case '7':
      ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;
      break;
    case 'T':
      tx_test_pkt_len = atoi(optarg);
      if (tx_test_pkt_len < 60)
        tx_test_pkt_len = 60;
      break;
    case 'U':
      promisc = 0;
      break;
    case 'P':
      pps = atoi(optarg);
      break;
    case 'S':
      port_speed = atoi(optarg);
      break;
    case 'K':
      tx_csum_offload = 1;
      break;
    case 'i':
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

static void print_hw_stats(int port_id)
{
  struct rte_eth_xstat *xstats;
  struct rte_eth_xstat_name *xstats_names;
  int len, ret, i;

  len = rte_eth_xstats_get(port_id, NULL, 0);

  if (len < 0)
  {
    fprintf(stderr, "rte_eth_xstats_get(%u) failed: %d\n", port_id, len);
    return;
  }

  xstats = calloc(len, sizeof(*xstats));

  if (xstats == NULL)
  {
    fprintf(stderr, "Failed to calloc memory for xstats\n");
    return;
  }

  ret = rte_eth_xstats_get(port_id, xstats, len);

  if (ret < 0 || ret > len)
  {
    free(xstats);
    fprintf(stderr, "rte_eth_xstats_get(%u) len%i failed: %d\n", port_id, len, ret);
    return;
  }

  xstats_names = calloc(len, sizeof(*xstats_names));

  if (xstats_names == NULL)
  {
    free(xstats);
    fprintf(stderr, "Failed to calloc memory for xstats_names\n");
    return;
  }

  ret = rte_eth_xstats_get_names(port_id, xstats_names, len);

  if (ret < 0 || ret > len)
  {
    free(xstats);
    free(xstats_names);
    fprintf(stderr, "rte_eth_xstats_get_names(%u) len%i failed: %d\n", port_id, len, ret);
    return;
  }

  fprintf(stderr, "---\nPort %u hw stats:\n", port_id);

  for (i = 0; i < len; i++)
  {
    if (test_tx && xstats_names[i].name[0] != 't')
      continue;

    fprintf(stderr, "%s:\t%" PRIu64 "\n",
            xstats_names[i].name,
            xstats[i].value);
  }

  fprintf(stderr, "---\n");

  free(xstats);
  free(xstats_names);
}

/* ************************************ */

static void print_stats(uint8_t index)
{
  pfring_ft_stats fstat_sum = {0};
  pfring_ft_stats *fstat;
  struct rte_eth_stats pstats = {0};
  static struct timeval start_time = {0};
  static struct timeval last_time = {0};
  struct timeval end_time;

  unsigned long long n_bytes = 0, n_pkts = 0, n_drops = 0;
  unsigned long long tx_n_bytes = 0, tx_n_pkts = 0, tx_n_drops = 0;
  unsigned long long q_n_bytes = 0, q_n_pkts = 0;
  unsigned long long tx_q_n_bytes = 0, tx_q_n_pkts = 0, tx_q_n_drops = 0;

  double diff, bytes_diff;
  double tx_diff, tx_bytes_diff;
  double delta_last = 0;
  char buf[512];
  int len;
  uint8_t portid;

  portid = lcore_params[index].port_id;

  printf("print_stats Port %u \n", portid);

  if (start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);

  gettimeofday(&end_time, NULL);

  if (last_time.tv_sec > 0)
    delta_last = delta_time(&end_time, &last_time);

  memcpy(&last_time, &end_time, sizeof(last_time));

  // for (q = 0; q < num_queues; q++)
  // {

  q_n_pkts = stats[portid].num_pkts;
  q_n_bytes = stats[portid].num_bytes;

  len = snprintf(buf, sizeof(buf), "[Q#%u]   ", index);

  len += snprintf(&buf[len], sizeof(buf) - len, "[PORT#%u]", portid);

  len += snprintf(&buf[len], sizeof(buf) - len,
                  "Packets: %llu\t"
                  "Bytes: %llu\t",
                  q_n_pkts,
                  q_n_bytes);

  if (delta_last)
  {
    diff = q_n_pkts - stats[portid].last_pkts;
    bytes_diff = q_n_bytes - stats[portid].last_bytes;
    bytes_diff /= (1000 * 1000 * 1000) / 8;

    len += snprintf(&buf[len], sizeof(buf) - len,
                    "Throughput: %.3f Mpps",
                    ((double)diff / (double)(delta_last / 1000)) / 1000000);

    len += snprintf(&buf[len], sizeof(buf) - len,
                    " (%.3f Gbps)\t",
                    ((double)bytes_diff / (double)(delta_last / 1000)));
  }

  stats[portid].last_pkts = q_n_pkts;
  stats[portid].last_bytes = q_n_bytes;

  fprintf(stderr, "%s\n", buf);

  if ((fstat = pfring_ft_get_stats(userdata.fts[index]))) {
    printf("fstat->active_flows :>>>>>>>>>>>%u\n",fstat->active_flows);
    fstat_sum.active_flows += fstat->active_flows;
    fstat_sum.flows += fstat->flows;
    fstat_sum.err_no_room += fstat->err_no_room;
    fstat_sum.err_no_mem += fstat->err_no_mem;
  }
  // }

  if (rte_eth_stats_get(portid, &pstats) == 0)
  {
    n_pkts = pstats.ipackets;
    n_bytes = pstats.ibytes + (n_pkts * 24);
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
                  "Packets: %llu\t"
                  "Bytes: %llu\t",
                  n_pkts,
                  n_bytes);

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
}

/* ************************************ */

void sigproc(int sig)
{
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called)
    return;
  else
    called = 1;

  do_loop = 0;
}

/* ************************************ */

void my_sigalarm(int sig)
{
  printf("my_sigalarm\n");
  int i;
  if (!do_loop)
    return;

  for (i = 0; i < nb_lcore_params; i++) {
    print_stats(i);
  }

  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ************************************ */
int add_interfaces()
{

  int ret = 0;
  uint8_t i, max_iface_index = sizeof(ifaces) / sizeof(ifaces[0]);

  char vdev_name[64];
  char vdev_args[64];

  for (i = 0; i < max_iface_index; i++)
  {
    if (!strcmp(ifaces[i], ""))
    {
      // printf("max_iface_at: %u\n",i);
      max_iface_index = i;
      ret = (int)i;
      break;
    }
    else
    {
      ret = -1;
    }
  }

  if (ret > 0)
  {
    for (i = 0; i < max_iface_index; i++)
    {
      printf("iface: %u %s\n", i, ifaces[i]);

      snprintf(vdev_name, sizeof(vdev_name), "net_pcap_%s", ifaces[i]);
      snprintf(vdev_args, sizeof(vdev_args), "iface=%s", ifaces[i]);

      if (rte_eal_hotplug_add("vdev", vdev_name, vdev_args) < 0)
      {
        rte_exit(EXIT_FAILURE, "vdev creation failed:%s:%d\n", __func__, __LINE__);
      }
    }
    return ret;
  }

  return ret;

  // printf("max_iface: %u\n",max_iface_index);
}

/* ************************************ */
#if 1

#define NUM_MBUFS 8191

int main(int argc, char *argv[])
{
  struct rte_mempool *mbuf_pool;
  uint16_t portid;
  unsigned nb_ports;

  int q, ret, i;
  unsigned lcore_id;
  struct ether_addr mac_addr;

  ret = rte_eal_init(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  ret = parse_args(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid ftflow_dpdk parameters\n");

  ret = add_interfaces();
  if (ret > 0)
  {
    num_ports = ret;
  }
  else
  {
    rte_exit(EXIT_FAILURE, "Invalid port\n");
  }
  
  printf("num_port %d\n", ret);
  printf("nb_lcore_params %ld\n", nb_lcore_params);

  // add_interfaces("enp7s0");

  // char portname[64];
  // uint8_t count_port=0;
  // rte_eth_dev_get_name_by_port(1,portname);
  // count_port = rte_eth_dev_count_total;
  // printf("count_port %u\n",count_port);

  // char vdev_name[64];
  // char vdev_args[64];

  // snprintf(vdev_name, sizeof(vdev_name),"net_pcap_%s_%d","0",0);

  // snprintf(vdev_args, sizeof(vdev_args),"iface=%s", "enp7s0");
  // if (rte_eal_hotplug_add("vdev", vdev_name, vdev_args) < 0) {
  // 	rte_exit(EXIT_FAILURE, "vdev creation failed:%s:%d\n", __func__, __LINE__);
  // }
  // // wlp8s0
  // snprintf(vdev_name, sizeof(vdev_name),"net_pcap_%s_%d","1",0);
  // snprintf(vdev_args, sizeof(vdev_args),"iface=%s", "wlp8s0");
  // if (rte_eal_hotplug_add("vdev", vdev_name, vdev_args) < 0) {
  // 	rte_exit(EXIT_FAILURE, "vdev creation failed:%s:%d\n", __func__, __LINE__);
  // }

  memset(stats, 0, sizeof(stats));

  // num_queues = rte_lcore_count();
  num_queues = nb_lcore_params; 

  // if (rte_lcore_count() > num_queues)
  //   printf("INFO: %u lcores enabled, only %u used\n", rte_lcore_count(), num_queues);

  
  // if (rte_lcore_count() < num_queues)
  // {
  //   num_queues = rte_lcore_count();
  //   printf("INFO: only %u lcores enabled, using %u queues\n", rte_lcore_count(), num_queues);
  //   return -1;
  // }
  
  printf("num_queues %d\n", num_queues);

  lcore_id = rte_lcore_id();
  printf("lcore_id %d\n", lcore_id);
  // unsigned lcore_index = rte_lcore_index(lcore_id);
  // u_int16_t queue_id = lcore_index;


  // if (port_init() != 0)
    // rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n", port);

  /* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
  printf("rte_eth_dev_count_avail >>> %u\n",nb_ports);
	// if (nb_ports < 2 || (nb_ports & 1))
	// 	rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

  /* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");


  /* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
    	if (port_init2(portid, mbuf_pool) != 0) {
          rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
    }
  }

  // if (compute_flows) {
  // for (q = 0; q < num_queues; q++) {
  for (i = 0; i < num_queues; i++) {
    // fts[i][q] = pfring_ft_create_table(ft_flags, 0, 0, 0, 0);
    userdata.port_id = i;
    userdata.fts[i] = pfring_ft_create_table(ft_flags, 0, 0, 0, 0);

    if (userdata.fts[i] == NULL)
    {
      fprintf(stderr, "pfring_ft_create_table error\n");
      return -1;
    }

    pfring_ft_set_flow_export_callback(userdata.fts[i], processFlow, &userdata);
    printf("pfring_ft_create_table >>> %u\n",i);
  }
 
  // }
  // }
  for (i = 0; i < num_ports; i++)
  {
    rte_eth_macaddr_get(i, &mac_addr);
    printf("Port %u MAC address: ", i);
    print_mac_addr(mac_addr);
    printf("\n");
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  rte_eal_mp_remote_launch(processing_thread, NULL, CALL_MASTER);

  RTE_LCORE_FOREACH_SLAVE(lcore_id)
  {
    rte_eal_wait_lcore(lcore_id);
  }

  for (q = 0; q < num_queues; q++) {
      pfring_ft_flush(userdata.fts[q]);
  }

  for (q = 0; q < num_queues; q++) {
      pfring_ft_destroy_table(userdata.fts[q]);
  }

  port_close();

  return 0;
}
#endif

/*  */
#if 0
#include "test.c"

int main(int argc, char **argv) {
	struct lcore_conf *qconf;
	int ret;
	uint8_t nb_ports, nb_rx_queue;
	uint8_t nb_ports_available;
	uint8_t portid, queueid, queue;
	char *publish_host;
	unsigned lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid DPDKLATENCY arguments\n");

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");


	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	/* create the mbuf pool */
	dpdklatency_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (dpdklatency_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

  ret = add_interfaces();
  if (ret > 0) {
    nb_ports = ret;
  } else {
    rte_exit(EXIT_FAILURE, "Could not add Ethernet ports - bye\n");
  }

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	qconf = NULL;
	
	nb_ports_available = nb_ports;

  printf("nb_ports: %u\n",nb_ports);
	/* Initialise each port */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		// if ((dpdklatency_enabled_port_mask & (1 << portid)) == 0) {
		// 	printf("Skipping disabled port %u\n", (unsigned) portid);
		// 	nb_ports_available--;
		// 	continue;
		// }

		/* init port */
		printf("Initializing port %d ... \n", portid );
		fflush(stdout);

		/* init port */
		nb_rx_queue = get_port_n_rx_queues(portid);
    printf("nb_rx_queue: %u\n",nb_rx_queue);
		ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
    
		if (ret < 0) 
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, (unsigned) portid);
		
		/* init one TX queue (queue id is 0) on each port */
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				NULL);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, (unsigned) portid);
	

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					(unsigned) portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

	}

	/* init hash */
	// ret = init_hash();
	// if (ret < 0)
	// 	rte_exit(EXIT_FAILURE, "init_hash failed\n");

	/* Init RX queues */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];	
    printf("Init RX queues >>>> qconf->n_rx_queue %u\n",qconf->n_rx_queue);
    
		for(queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			printf("setting up rx queue on port %u, queue %u\n", portid, queueid);	
			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
						     rte_eth_dev_socket_id(portid),
					     NULL,
					     dpdklatency_pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
					  ret, (unsigned) portid);
		}
	}

	for (portid = 0; portid < nb_ports; portid++) {
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

		/* initialize port stats */
		memset(&lcore_statistics, 0, sizeof(lcore_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask. %u\n", nb_ports_available);
	}

	check_all_ports_link_status(nb_ports, dpdklatency_enabled_port_mask);


	ret = 0;

	/* launch stats on core 0 */
	rte_eal_remote_launch((lcore_function_t *) dpdklatency_stats_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch((lcore_function_t *) dpdklatency_processing_loop, NULL, lcore_id);
	}

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
                        return -1;
		}
	}

	for (portid = 0; portid < nb_ports; portid++) {
		if ((dpdklatency_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	printf("Bye...\n");

	return ret;
}
#endif