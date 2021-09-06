#ifndef __FTULTILS_H__
#define __FTULTILS_H__

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

#include "db_zmq.h"
#include <net/if.h>

/* ******************************** */
// static pfring_ft_table *fts[RTE_MAX_LCORE] = { NULL };

extern pfring_ft_table *fts[RTE_MAX_LCORE];
uint8_t last_port_id;

/* ******************************** */
int initft(uint8_t nb_queu);
int uinitft(uint8_t nb_queu);
const char *action_to_string(pfring_ft_action action);
const char *status_to_string(pfring_ft_flow_status status);
void process_flow(pfring_ft_flow *flow, void *user);
void processFlow(pfring_ft_flow *flow, void *user);
void process_expired_flow(pfring_ft_flow *flow, void *user);
/* ******************************** */
#endif /* __FTULTILS_H__ */