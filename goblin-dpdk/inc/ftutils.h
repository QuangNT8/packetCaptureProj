#ifndef __FTULTILS_H__
#define __FTULTILS_H__

#include "db_zmq.h"
#include "main.h"
#include "pfring_ft.h"
#include "pfring_utils.h"
#include <net/if.h>

/* ******************************** */
// static pfring_ft_table *fts[RTE_MAX_LCORE] = { NULL };

struct ndpi_detection_module_struct **ndpi_structs;
uint8_t last_port_id;

/* ******************************** */
const char *action_to_string(pfring_ft_action action);
const char *status_to_string(pfring_ft_flow_status status);
uint8_t update_IfName();
void process_expired_flow(pfring_ft_flow *flow, void *user);
void process_flow(pfring_ft_flow *flow, void *user);
void processFlow(pfring_ft_flow *flow, void *user);
int capture2ft(uint16_t portid, pfring_ft_table *ft);
/* ******************************** */
#endif /* __FTULTILS_H__ */