
#include "../inc/ftutils.h"

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
uint8_t update_IfName()
{
    uint8_t i, port_idx = 0;
    uint64_t tmp = capture_info.last_actflows[port_idx];

    for (i = 1; i < num_ports; i++)
    {
        if (tmp < capture_info.last_actflows[i])
        {
            port_idx = i;
            tmp = capture_info.last_actflows[port_idx];
        }
    }

    if (port_idx == getGolblinPort())
    {
        getGoblinIfaces(getGolblinPort(), capture_info.ifname, isGolblinDev());
    }
    else
    {
        memset(capture_info.ifname, 0, sizeof capture_info.ifname);
        strncpy(capture_info.ifname, ifaces[port_idx],
                strlen(ifaces[port_idx]));
    }

    return port_idx;
}
/* *************************************** */
void process_expired_flow(pfring_ft_flow *flow, void *user)
{
    if (num_ports > 1)
    {
        if (strlen(capture_info.ifname) > 0)
        {
            if (capture_info.last_actflows[last_port_id] == 0)
            {
                last_port_id = update_IfName();
            }
        }
        else
        {
            last_port_id = update_IfName();
        }
    }

    // printf("process_expired_flow by port id: %u iface : %s\n", last_port_id, capture_info.ifname);

    process_flow(flow, user);
    // processFlow(flow, user);
    pfring_ft_flow_free(flow);
}

/* *************************************** */

void process_flow(pfring_ft_flow *flow, void *user)
{
    unsigned lcore_id = rte_lcore_id();
    unsigned lcore_index = rte_lcore_index(lcore_id);

    pfring_ft_table *ft = fts[lcore_index];
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
        zmq_send(zmq_clients[lcore_index], msg, buffer_len, 0);
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

int capture2ft(uint16_t portid, pfring_ft_table *ft)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    pfring_ft_pcap_pkthdr h;
    pfring_ft_ext_pkthdr ext_hdr = {0};
    uint16_t num, i;

    // ft = userdata.fts[portid];

    num = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

    if (unlikely(num == 0))
    {
        pfring_ft_housekeeping(ft, time(NULL));
        return num;
    }

    for (i = 0; i < PREFETCH_OFFSET && i < num; i++)
    {
        rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
    }

    for (i = 0; i < num; i++)
    {
        char *data = rte_pktmbuf_mtod(bufs[i], char *);
        int len = rte_pktmbuf_pkt_len(bufs[i]);

        h.len = h.caplen = len;
        gettimeofday(&h.ts, NULL);

        pfring_ft_process(ft, (const u_char *)data, &h, &ext_hdr);

        statistics[portid].num_pkts++;
        statistics[portid].num_bytes += len + 24;

        rte_pktmbuf_free(bufs[i]);
    }

    return num;
}

/* ************************************ */
