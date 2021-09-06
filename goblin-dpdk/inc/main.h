#ifndef __MAIN_H__
#define __MAIN_H__

#include "dpdk.h"
#include "ftutils.h"
#include "goblin.h"
#include "stats.h"

#define ALARM_SLEEP 1

#define BURST_SIZE 64
#define PREFETCH_OFFSET 3

/* ************************************ */
static u_int8_t num_queues = 1;
static u_int8_t do_loop = 1;

struct capture_interfaces_info capture_info;

pfring_ft_table *fts[RTE_MAX_LCORE];
static u_int32_t ft_flags = 0;
/* ******************************** */

struct lcore_stats
{
    u_int64_t num_pkts;
    u_int64_t num_bytes;
    u_int64_t last_pkts;
    u_int64_t last_bytes;
} statistics[RTE_MAX_LCORE];

#endif /* __MAIN_H__ */