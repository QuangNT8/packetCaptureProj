#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_errno.h>
#include <zmq.h>
	

static volatile bool force_quit;

/* Disabling forwarding */
static int forwarding = 0;

/* Debug mode */
static int debug = 0;

#define RTE_LOGTYPE_DPDKLATENCY RTE_LOGTYPE_USER1

#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256
#define NB_SOCKETS 8

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* mask of enabled ports */
static uint32_t dpdklatency_enabled_port_mask = 0;

struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

/* Magic hash key for symmetric RSS */
#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = { 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
	0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D,
	0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, };

/* Port configuration structure */
static const struct rte_eth_conf port_conf = {
    .link_speeds = ETH_LINK_SPEED_1G,
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN
	},
};

struct rte_mempool * dpdklatency_pktmbuf_pool = NULL;

/* Per-lcore (essentially queue) statistics struct */
struct dpdklatency_lcore_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct dpdklatency_lcore_statistics lcore_statistics[RTE_MAX_LCORE];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */
/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 10; /* default period is 10 seconds */

#define TIMESTAMP_HASH_ENTRIES 99999

typedef struct rte_hash lookup_struct_t;
static lookup_struct_t *ipv4_timestamp_lookup_struct[NB_SOCKETS];


#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#define CLOCK_PRECISION 1000000000L /* one billion */

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

#define MAX_LCORE_PARAMS 1024
struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

// Configure port-queue-lcore assigment here
static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 0},
	{0, 1, 1},
	{1, 2, 2},
	{1, 3, 3},
};

static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	void * zmq_client;
	void * zmq_client_header;
	lookup_struct_t * ipv4_lookup_struct;
} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE] __rte_cache_aligned;

static const char* publishto;

/* ************************************ */
/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("check_all_ports_link_status >>> done\n");
		}
	}
}
/* ************************************ */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
                signum);
        force_quit = true;
    }
}
/* ************************************ */
static uint8_t
get_port_n_rx_queues(const uint8_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port &&
				lcore_params[i].queue_id > queue)
			queue = lcore_params[i].queue_id;
	}
	return (uint8_t)(++queue);
}
/* ************************************ */
static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			printf("error: too many queues (%u) for lcore: %u\n",
				(unsigned)nb_rx_queue + 1, (unsigned)lcore);
			return -1;
		} else {
			
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				lcore_params[i].port_id;
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				lcore_params[i].queue_id;
			lcore_conf[lcore].n_rx_queue++;
			printf("lcore_conf[lcore].n_rx_queue++ >>>>> %u\n", lcore_conf[lcore].n_rx_queue++);
		}
	}
	return 0;
}
/* ************************************ */
/* Send the burst of packets on an output interface */
static int
dpdklatency_send_burst(struct lcore_conf *qconf, unsigned n, uint8_t port)
{
	struct rte_mbuf **m_table;
	unsigned ret;
	unsigned queueid = 0;
	unsigned lcore_id = rte_lcore_id();

	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	// TODO: change here is more than one TX queue per port is required
	ret = rte_eth_tx_burst(port, (uint16_t) queueid, m_table, (uint16_t) n);
	lcore_statistics[lcore_id].tx += ret;
	if (unlikely(ret < n)) {
		lcore_statistics[lcore_id].dropped += (n - ret);
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}
/* ************************************ */
static void
track_latency(struct rte_mbuf *m, uint64_t *ipv4_timestamp_syn, uint64_t *ipv4_timestamp_synack)
{
	struct ether_hdr *eth_hdr;
	struct tcp_hdr *tcp_hdr = NULL;
	struct ipv4_hdr* ipv4_hdr;
	uint16_t offset = 0;
	enum { URG_FLAG = 0x20, ACK_FLAG = 0x10, PSH_FLAG = 0x08, RST_FLAG = 0x04, SYN_FLAG = 0x02, FIN_FLAG = 0x01 };
	uint64_t key;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	//VLAN tagged frame
	// if (eth_hdr->ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)){
    //     	offset = get_vlan_offset(eth_hdr, &eth_hdr->ether_type);
	// }
	
	// // IPv4	
	// ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr)+offset);
	// if (ipv4_hdr->next_proto_id == IPPROTO_TCP){
	// 	tcp_hdr = rte_pktmbuf_mtod_offset(m, struct tcp_hdr *, 
	// 		sizeof(struct ipv4_hdr) + sizeof(struct ether_hdr) + offset);
	// 	switch (tcp_hdr->tcp_flags){ 
	// 		case SYN_FLAG:
	// 			key = (long long) m->hash.rss << 32 | rte_be_to_cpu_32(tcp_hdr->sent_seq);
	// 			track_latency_syn_v4( key, ipv4_timestamp_syn);
	// 			break;
	// 		case SYN_FLAG | ACK_FLAG:
	// 			key = (long long) m->hash.rss << 32 | (rte_be_to_cpu_32(tcp_hdr->recv_ack)- 1);
	// 			track_latency_synack_v4( key, ipv4_timestamp_synack);
	// 			break;	
	// 		case ACK_FLAG:
	// 			key = (long long) m->hash.rss << 32 | (rte_be_to_cpu_32(tcp_hdr->sent_seq) - 1 );
	// 			track_latency_ack_v4( key,
	// 				rte_be_to_cpu_32(ipv4_hdr->dst_addr),
	// 				rte_be_to_cpu_32(ipv4_hdr->src_addr),
	// 				ipv4_timestamp_syn,
	// 				ipv4_timestamp_synack);
	// 	}	
	// }
}
/* ************************************ */
static void
init_zmq_for_lcore(unsigned lcore_id){
	// void *context = zmq_ctx_new ();
	// void *requester = zmq_socket (context, ZMQ_PUB);
	// void *requester_headers = zmq_socket (context, ZMQ_PUB);
	// char hostname[28]; 
	// int rc;

	// if (lcore_id > 99){
	// 	rte_exit(EXIT_FAILURE, "Lcore %u is out of range", lcore_id);
	// }

	// //Starting port: 5550, 5551, 5552, etc.
	// if (publishto == NULL){
	// 	snprintf(hostname, 21, "tcp://127.0.0.1:55%.2d", lcore_id);	
	// 	printf("Setting up ZMQ from lcore %u on socket %s %lu \n", lcore_id, hostname, sizeof(hostname));
	// 	rc = zmq_bind (requester, hostname);
	// } else {
	// 	snprintf(hostname, 28, "tcp://%s:55%.2d", publishto, lcore_id);	
	// 	printf("Connecting ZMQ from lcore %u to publish to socket %s %lu \n", lcore_id, hostname, sizeof(hostname));
	// 	rc = zmq_connect (requester, hostname);
	// }
	
	// if (rc != 0 || requester == NULL) {
	// 	rte_exit(EXIT_FAILURE, "Unable to create zmq connection on lcore %u . Issue: %s", lcore_id, zmq_strerror (errno));
	// }	
	
	// lcore_conf[lcore_id].zmq_client = requester;
}
/* ************************************ */
/* Print out statistics on packets dropped */
static void
print_stats1(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned lcore_id;

	// TODO: dopped TX packets are not counted properly
	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nLcore statistics ====================================");

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		printf("\nStatistics for lcore %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   lcore_id,
			   lcore_statistics[lcore_id].tx,
			   lcore_statistics[lcore_id].rx,
			   lcore_statistics[lcore_id].dropped);

		total_packets_dropped += lcore_statistics[lcore_id].dropped;
		total_packets_tx += lcore_statistics[lcore_id].tx;
		total_packets_rx += lcore_statistics[lcore_id].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}
/* ************************************ */
/* stats loop */
static void
dpdklatency_stats_loop(void)
{
	printf("dpdklatency_stats_loop\n");
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	
	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, DPDKLATENCY, "entering stats loop on lcore %u\n", lcore_id);

	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			/* if timer is enabled */
			if (timer_period > 0) {
				/* advance the timer */
				timer_tsc += diff_tsc;
				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= (uint64_t) timer_period)) {
					print_stats1();
					/* reset the timer */
					timer_tsc = 0;
				}
			}
			prev_tsc = cur_tsc;
		}
	}
}
/* ************************************ */
/* packet processing loop */
static void
dpdklatency_processing_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	unsigned i, j, portid, queueid, nb_rx;
	struct lcore_conf *qconf;
	struct rte_mbuf *m;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	uint64_t ipv4_timestamp_syn[TIMESTAMP_HASH_ENTRIES] __rte_cache_aligned;
	uint64_t ipv4_timestamp_synack[TIMESTAMP_HASH_ENTRIES] __rte_cache_aligned;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	
	/* Init ZMQ */
	init_zmq_for_lcore(lcore_id);

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, DPDKLATENCY, "lcore %u has nothing to do - no RX queue assigned\n", lcore_id);
		return;
	}

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, DPDKLATENCY, " -- lcoreid=%u portid=%hhu "
			"rxqueueid=%hhu\n", lcore_id, portid, queueid);
	}

	while (!force_quit) {
		cur_tsc = rte_rdtsc();

		/* TX burst queue drain	 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				dpdklatency_send_burst(&lcore_conf[lcore_id],
						 qconf->tx_mbufs[portid].len,
						 (uint8_t) portid);
		
				qconf->tx_mbufs[portid].len = 0;
			}
			prev_tsc = cur_tsc;
		}
		
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;

			/* Reading from RX queue */
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
			//if (nb_rx > 0){
			//	printf("reading from portid %u, queueid %u\n", portid, queueid);
			//}
			lcore_statistics[lcore_id].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));

				// Call the latency tracker function for every packet
				track_latency(m, ipv4_timestamp_syn, ipv4_timestamp_synack);

				/* Forward packets if forwarding is enabled */	
				if (forwarding){
					dpdklatency_send_packet(m, (uint8_t) !portid);
				} else {
					// drop it like it's hot
					rte_pktmbuf_free(m);	
				}
			}
		}
	}
}
/* ************************************ */
// static const struct rte_eth_conf port_conf_default = {
// 	.rxmode = {
// 		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
// 	},
// };

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init2(uint16_t port, struct rte_mempool *mbuf_pool)
{
	#define RX_RING_SIZE 1024
	#define TX_RING_SIZE 1024
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
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
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
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
/* ************************************ */