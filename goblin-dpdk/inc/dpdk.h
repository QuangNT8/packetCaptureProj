#ifndef __DPDK_H__
#define __DPDK_H__

#include "ftutils.h"
#include "main.h"
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef RTE_ETHER_MAX_LEN
#define ether_header rte_ether_hdr
#define ether_addr rte_ether_addr
#define ETHER_MAX_LEN RTE_ETHER_MAX_LEN
#else
#define ether_header ether_hdr
#endif

#define NUM_MBUFS 8191
#define RX_RING_SIZE (1 * 1024)
#define TX_RING_SIZE (1 * 1024)
#define MBUF_CACHE_SIZE 256
/* ************************************ */
struct rte_mempool *mbuf_pool;
/* ************************************ */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = ETHER_MAX_LEN}};

/* ************************************ */
static u_int32_t rx_ring_size = RX_RING_SIZE;
static u_int32_t tx_ring_size = TX_RING_SIZE;
/* ************************************ */
/* ************************************ */
void print_help(void);
int parse_args(int argc, char **argv);
void create_mbuf_pool();
int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
void send_stats(uint8_t queuidx);
void print_stats(uint8_t index);
void sigproc(int sig);
void my_sigalarm(int sig);
void port_close(void);
u_int8_t getGolblinPort(void);
void setGolblinPort(u_int8_t portidx);
u_int8_t isGolblinDev(void);

static u_int16_t port_speed = 0;
static u_int8_t isgolbindev = 0;
static u_int8_t goblin_port = 0;

/* ************************************ */
#endif /* __DPDK_H__ */