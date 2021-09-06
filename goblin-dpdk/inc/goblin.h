#ifndef __GOBLIN_H__
#define __GOBLIN_H__

#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/if.h>
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

#include "pfring_ft.h"

#define MAX_PORT 10

/* ************************************ */
struct lcore_params
{
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 0}, {1, 1, 1},
    // {1, 2, 2},
    // {1, 3, 3},
};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params =
    sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);
/* ************************************ */
int num_ports;
char ifaces[MAX_PORT][64];
/* ************************************ */
/* ************************************ */
void getGoblinIfaces(uint8_t id, char *outiface, u_int8_t flag);
/* ************************************ */
/* ************************************ */
int add_interfaces();
/* ************************************ */
/* ************************************ */
#endif /* __GOBLIN_H__ */