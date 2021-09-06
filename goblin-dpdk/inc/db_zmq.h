#ifndef __DB_ZMQ_H__
#define __DB_ZMQ_H__

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "ndpi_config.h"
//#include "ndpi_typedefs.h"
#include <assert.h>
#include <pfring_ft.h>
#include <zmq.h>

#include "ndpi_api.h"
#include "ndpi_main.h"
#include "stats.h"

void *ctx;
void **zmq_clients;

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

#endif /* __DB_ZMQ_H__ */
       /**<EOF*/