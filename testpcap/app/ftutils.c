
#include "ftutils.h"

#ifndef __USE_GNU
#define __USE_GNU
#endif

/* ******************************** */

struct ndpi_detection_module_struct **ndpi_structs;
pfring_ft_table *fts[RTE_MAX_LCORE];

/* ******************************** */
static char *etheraddr2string(const u_char *ep, char *buf)
{
    const char *hex = "0123456789ABCDEF";
    u_int i, j;
    char *cp;

    cp = buf;
    if ((j = *ep >> 4) != 0)
        *cp++ = hex[j];
    else
        *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];

    for (i = 5; (int)--i >= 0;)
    {
        *cp++ = ':';
        if ((j = *ep >> 4) != 0)
            *cp++ = hex[j];
        else
            *cp++ = '0';

        *cp++ = hex[*ep++ & 0xf];
    }

    *cp = '\0';
    return (buf);
}

/* *************************************** */

char *_intoa(unsigned int addr, char *buf, u_short bufLen)
{
    char *cp, *retStr;
    u_int byte;
    int n;

    cp = &buf[bufLen];
    *--cp = '\0';

    n = 4;
    do
    {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if (byte > 0)
        {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0)
                *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    retStr = (char *)(cp + 1);

    return (retStr);
}
/* ******************************** */
const char *action_to_string(pfring_ft_action action)
{
    switch (action)
    {
    case PFRING_FT_ACTION_FORWARD:
        return "forward";
    case PFRING_FT_ACTION_DISCARD:
        return "discard";
    case PFRING_FT_ACTION_DEFAULT:
        return "default";
    case PFRING_FT_ACTION_USER_1:
        return "user1";
    case PFRING_FT_ACTION_USER_2:
        return "user2";
    }
    return "";
}
/* ******************************** */
const char *status_to_string(pfring_ft_flow_status status)
{
    switch (status)
    {
    case PFRING_FT_FLOW_STATUS_ACTIVE:
        return "active";
    case PFRING_FT_FLOW_STATUS_IDLE_TIMEOUT:
        return "idle-timeout";
    case PFRING_FT_FLOW_STATUS_ACTIVE_TIMEOUT:
        return "active-timeout";
    case PFRING_FT_FLOW_STATUS_END_DETECTED:
        return "end-of-flow";
    case PFRING_FT_FLOW_STATUS_FORCED_END:
        return "forced-end";
    case PFRING_FT_FLOW_STATUS_SLICE_TIMEOUT:
        return "slice-timeout";
    case PFRING_FT_FLOW_STATUS_OVERFLOW:
        return "table-overflow";
    }
    return "";
}

/* *************************************** */

void process_flow(pfring_ft_flow *flow, void *user)
{
    unsigned lcore_id = rte_lcore_id();
    unsigned lcore_index = rte_lcore_index(lcore_id);

    pfring_ft_table *ft = (pfring_ft_table *)user;
    // i = get_user_data->queu_id;
    // printf("process_flow %u\n",get_user_data->port_id);
    pfring_ft_flow_key *k;
    pfring_ft_flow_value *v;

    ndpi_protocol ndpi_proto;
    ndpi_serializer serializer;

    u_int32_t buffer_len;

    char buf4[32], buf5[32];

    u_char community_id[64];

    int ret = -1;

    k = pfring_ft_flow_get_key(flow);
    v = pfring_ft_flow_get_value(flow);

    if (k->ip_version == 4)
    {
        ndpi_flowv4_flow_hash(
            k->protocol, ntohl(k->saddr.v4), ntohl(k->daddr.v4), k->sport,
            k->dport, v->l7_metadata.icmp.type, v->l7_metadata.icmp.code,
            community_id, sizeof(community_id));
    }
    else
    {
        ndpi_flowv6_flow_hash(k->protocol, (struct ndpi_in6_addr *)&k->saddr.v6,
                              (struct ndpi_in6_addr *)&k->daddr.v6, k->sport,
                              k->dport, v->l7_metadata.icmp.type,
                              v->l7_metadata.icmp.code, community_id,
                              sizeof(community_id));
    }

    struct ndpi_detection_module_struct *ndpi_struct =
        pfring_ft_get_ndpi_handle(ft);

    struct ndpi_flow_struct *ndpi_flow = pfring_ft_flow_get_ndpi_handle(flow);

    const char *status = status_to_string(v->status);
    const char *action = action_to_string(pfring_ft_flow_get_action(flow));

    ndpi_proto.master_protocol = v->l7_protocol.master_protocol;
    ndpi_proto.app_protocol = v->l7_protocol.app_protocol;
    ndpi_proto.category = v->l7_protocol.category;

    if (ndpi_struct == NULL)
    {
        return;
    }

    ret = flow2json(
        ndpi_struct, ndpi_flow, community_id, v->tunnel_type,
        etheraddr2string(k->smac, buf4), etheraddr2string(k->dmac, buf5),
        &v->direction[s2d_direction], &v->direction[d2s_direction], action,
        status, k->ip_version, k->protocol, k->vlan_id, ntohl(k->saddr.v4),
        ntohl(k->daddr.v4), (struct ndpi_in6_addr *)&k->saddr.v6,
        (struct ndpi_in6_addr *)&k->daddr.v6, k->sport, k->dport, &ndpi_proto,
        capture_info.ifname, &serializer);

    if (ret == 0)
    {
        char *msg = ndpi_serializer_get_buffer(&serializer, &buffer_len);
        send_msg_over_zmq(0, msg, buffer_len);
        ndpi_term_serializer(&serializer);
    }
}

/* ************************************ */
void processFlow(pfring_ft_flow *flow, void *user)
{
    pfring_ft_table *ft = (pfring_ft_table *)user;
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

    printf(
        "[Flow] "
        "srcIp: %s, dstIp: %s, srcPort: %u, dstPort: %u, protocol: %u, "
        "tcpFlags: 0x%02X, "
        "l7: %s, "
        "c2s: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
        "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }\n",
        ip1, ip2, k->sport, k->dport, k->protocol,
        v->direction[s2d_direction].tcp_flags |
            v->direction[d2s_direction].tcp_flags,
        pfring_ft_l7_protocol_name(ft, &v->l7_protocol, buf3, sizeof(buf3)),
        v->direction[s2d_direction].pkts, v->direction[s2d_direction].bytes,
        (u_int)v->direction[s2d_direction].first.tv_sec,
        (u_int)v->direction[s2d_direction].first.tv_usec,
        (u_int)v->direction[s2d_direction].last.tv_sec,
        (u_int)v->direction[s2d_direction].last.tv_usec,
        v->direction[d2s_direction].pkts, v->direction[d2s_direction].bytes,
        (u_int)v->direction[d2s_direction].first.tv_sec,
        (u_int)v->direction[d2s_direction].first.tv_usec,
        (u_int)v->direction[d2s_direction].last.tv_sec,
        (u_int)v->direction[d2s_direction].last.tv_usec);
}
/* ************************************ */
void process_expired_flow(pfring_ft_flow *flow, void *user)
{
    process_flow(flow, user);
    // printf("process_expired_flow");
    processFlow(flow, user);
    pfring_ft_flow_free(flow);
}
/* ************************************ */
int initft(uint8_t nb_queu)
{
    static u_int32_t ft_flags = 0;
    int ret = 0;
    uint8_t q;

    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;
    ft_flags |= PFRING_FT_DECODE_TUNNELS;
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI_EXTRA;
    ft_flags |= PF_RING_FT_FLOW_FLAGS_L7_GUESS;
    ft_flags |= PFRING_FT_IGNORE_HW_HASH; // ignore device an asymmetric hash

    ndpi_structs = calloc(nb_queu, sizeof(struct ndpi_detection_module_struct *));

    for (q = 0; q < nb_queu; q++)
    {
        printf("pfring_ft_create_table\n");
        fts[q] = pfring_ft_create_table(ft_flags, 0, 0, 0, 0);

        if (fts[q] == NULL)
        {
            // rte_exit(EXIT_FAILURE, "pfring_ft_create_table error\n");
            ret = -1;
        }

        pfring_ft_set_flow_export_callback(fts[q], process_expired_flow, fts[q]);
    }

    return ret;
}
/* ************************************ */
int uinitft(uint8_t nb_queu)
{
    uint8_t i;
    for (i = 0; i < nb_queu; i++)
    {
        pfring_ft_flush(fts[i]);
        printf("pfring_ft_flush queue : %u\n", i);
        pfring_ft_destroy_table(fts[i]);
        printf("pfring_ft_destroy_table queue : %u\n", i);
    }
}
