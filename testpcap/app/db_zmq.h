#ifndef __DB_ZMQ_H__
#define __DB_ZMQ_H__

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

#include <pfring_ft.h>
#include <zmq.h>

#include "../main.h"
#include "ndpi_api.h"
#include "ndpi_main.h"

#define DEFAULT_ZMQ_ENDPOINT "ipc:///tmp/zmq_server.ipc"

char *zmq_getendpoint();
void zmq_setendpoint(char *endpoint);

void *init_zmq_connection(void *ctx, const char *endpoint, uint16_t thread_id);

int flow2json(struct ndpi_detection_module_struct *ndpi_struct,
              struct ndpi_flow_struct *flow, char *community_id,
              u_int32_t tunnel_type, char *src_mac, char *dst_mac,
              pfring_ft_flow_dir_value *s2d, pfring_ft_flow_dir_value *d2s,
              const char *action, const char *status, u_int8_t ip_version,
              u_int8_t l4_protocol, u_int16_t vlan_id, u_int32_t src_v4,
              u_int32_t dst_v4, struct ndpi_in6_addr *src_v6,
              struct ndpi_in6_addr *dst_v6, u_int16_t src_port,
              u_int16_t dst_port, ndpi_protocol *l7_protocol,
              const char *ifname, ndpi_serializer *serializer);

int stats2json(struct capture_interfaces_info *if_info,
               ndpi_serializer *serializer);

int init_zmq(u_int8_t queues);
int uinit_zmq(u_int8_t queues);

void send_stats(uint8_t queuidx);
void send_msg_over_zmq(uint8_t queuidx, char *msg, u_int32_t buffer_len);

#endif /* __DB_ZMQ_H__ */
       /**<EOF*/