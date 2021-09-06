#include "../inc/db_zmq.h"

#define TICK_RESOLUTION 1000000
char *zmq_endpoint = NULL;

const char *name_flow_risk(ndpi_risk_enum risk)
{
    switch (risk)
    {
    case NDPI_URL_POSSIBLE_XSS:
        return ("url_possible_xss");

    case NDPI_URL_POSSIBLE_SQL_INJECTION:
        return ("url_possible_sql_injection");

    case NDPI_URL_POSSIBLE_RCE_INJECTION:
        return ("url_possible_rce_injection");

    case NDPI_BINARY_APPLICATION_TRANSFER:
        return ("binary_application_transfer");

    case NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT:
        return ("known_protocol_on_non_standard_port");

    case NDPI_TLS_SELFSIGNED_CERTIFICATE:
        return ("tls_selfsigned_certificate");

    case NDPI_TLS_OBSOLETE_VERSION:
        return ("tls_obsolete_version");

    case NDPI_TLS_WEAK_CIPHER:
        return ("tls_weak_cipher");

    case NDPI_TLS_CERTIFICATE_EXPIRED:
        return ("tls_certificate_expired");

    case NDPI_TLS_CERTIFICATE_MISMATCH:
        return ("tls_certificate_mismatch");

    case NDPI_HTTP_SUSPICIOUS_USER_AGENT:
        return ("http_suspicious_user_agent");

    case NDPI_HTTP_NUMERIC_IP_HOST:
        return ("http_numeric_ip_host");

    case NDPI_HTTP_SUSPICIOUS_URL:
        return ("http_suspicious_url");

    case NDPI_HTTP_SUSPICIOUS_HEADER:
        return ("http_suspicious_header");

    case NDPI_TLS_NOT_CARRYING_HTTPS:
        return ("tls_not_carrying_https");

    case NDPI_SUSPICIOUS_DGA_DOMAIN:
        return ("suspicious_dga_domain");

    case NDPI_MALFORMED_PACKET:
        return ("malformed_packet");

    case NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER:
        return ("ssh_obsolete_client_version_or_cipher");

    case NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER:
        return ("ssh_obsolete_server_version_or_cipher");

    case NDPI_SMB_INSECURE_VERSION:
        return ("smb_insecure_version");

    case NDPI_TLS_SUSPICIOUS_ESNI_USAGE:
        return ("tls_suspicious_esni_usage");

    case NDPI_UNSAFE_PROTOCOL:
        return ("unsafe_protocol");

    case NDPI_DNS_SUSPICIOUS_TRAFFIC:
        return ("dns_suspicious_traffic"); /* Exfiltration ? */

    case NDPI_TLS_MISSING_SNI:
        return ("tls_missing_sni");

    case NDPI_HTTP_SUSPICIOUS_CONTENT:
        return ("http_suspicious_content");

    case NDPI_RISKY_ASN:
        return ("risky_asn");

    case NDPI_RISKY_DOMAIN:
        return ("risky_domain");

    case NDPI_MALICIOUS_JA3:
        return ("malicious_ja3");

    default:
        return ("unknown");
    }
}

void *init_zmq_connection(void *ctx, const char *endpoint, uint16_t thread_id)
{
    int rc;
    void *client;

    client = zmq_socket(ctx, ZMQ_DEALER);
    if (client == NULL)
    {
        printf("Unable to create ZMQ_DEALER socket\n");
        return NULL;
    }

    int zmq_linger = 3000;
    int zmq_hwm = 10000000;
    zmq_setsockopt(client, ZMQ_LINGER, &zmq_linger, sizeof(int));
    zmq_setsockopt(client, ZMQ_SNDHWM, &zmq_hwm, sizeof(int));
    zmq_setsockopt(client, ZMQ_IDENTITY, &thread_id, sizeof(int));

    printf("zmq_connect %s\n", endpoint);
    rc = zmq_connect(client, endpoint);

    if (rc != 0)
    {
        printf("Unable to connect to %s\n", endpoint);
        return (NULL);
    }

    return client;
}

// convert timeval to human-readable https://tools.ietf.org/html/rfc3339
// https://medium.com/easyread/understanding-about-rfc-3339-for-datetime-formatting-in-software-engineering-940aa5d5f68a
static char *get_time(struct timeval tv, char *buf)
{
    char tmpbuf[64];
    if (tv.tv_sec == 0)
    {
        gettimeofday(&tv, NULL);
    }
    struct tm *ptm = gmtime(&tv.tv_sec);
    strftime(tmpbuf, sizeof(tmpbuf), "%Y-%m-%dT%H:%M:%S", ptm);
    snprintf(buf, 64, "%s.%06ldZ", tmpbuf, tv.tv_usec);
    return buf;
}

// get micro-seconds
uint64_t get_time_ms(struct timeval ts)
{
    if (ts.tv_sec == 0)
        gettimeofday(&ts, NULL);
    return ((uint64_t)ts.tv_sec) * TICK_RESOLUTION + ts.tv_usec;
}

int flow2json(struct ndpi_detection_module_struct *ndpi_struct,
              struct ndpi_flow_struct *flow, char *community_id,
              u_int32_t tunnel_type, char *src_mac, char *dst_mac,
              pfring_ft_flow_dir_value *s2d, pfring_ft_flow_dir_value *d2s,
              const char *action, const char *status, u_int8_t ip_version,
              u_int8_t l4_protocol, u_int16_t vlan_id, u_int32_t src_v4,
              u_int32_t dst_v4, struct ndpi_in6_addr *src_v6,
              struct ndpi_in6_addr *dst_v6, u_int16_t src_port,
              u_int16_t dst_port, ndpi_protocol *l7_protocol,
              const char *ifname, ndpi_serializer *serializer)
{
    char buf[64], src_name[32], dst_name[32];
    u_int64_t total_packet = 0;

    if (flow == NULL)
    {
        // ndpi_serialize_end_of_block(serializer);
        return (-1);
    }

    if (ndpi_init_serializer(serializer, ndpi_serialization_format_json) ==
        -1)
    {
        return (-1);
    }

    if (s2d)
    {
        total_packet += s2d->pkts;
    }

    if (d2s)
    {
        total_packet += d2s->pkts;
    }

    // need more investigate why come here
    if (total_packet < 1)
    {
        return (-1);
    }

    if (ip_version == 4)
    {
        inet_ntop(AF_INET, &src_v4, src_name, sizeof(src_name));
        inet_ntop(AF_INET, &dst_v4, dst_name, sizeof(dst_name));
    }
    else
    {
        inet_ntop(AF_INET6, src_v6, src_name, sizeof(src_name));
        inet_ntop(AF_INET6, dst_v6, dst_name, sizeof(dst_name));
        /* For consistency across platforms replace :0: with :: */
        ndpi_patchIPv6Address(src_name), ndpi_patchIPv6Address(dst_name);
    }

    ndpi_serialize_start_of_block(serializer, "flow");
    if (ifname)
    {
        ndpi_serialize_string_string(serializer, "ifname", ifname);
    }

    if (community_id)
    {
        ndpi_serialize_string_string(serializer, "community_id", community_id);
    }

    if (tunnel_type)
    {
        ndpi_serialize_string_uint32(serializer, "tunnel_type", tunnel_type);
    }

    if (vlan_id)
    {
        ndpi_serialize_string_uint32(serializer, "vlan_id", vlan_id);
    }

    if (src_mac)
    {
        ndpi_serialize_string_string(serializer, "src_mac", src_mac);
    }

    if (dst_mac)
    {
        ndpi_serialize_string_string(serializer, "dst_mac", dst_mac);
    }

    ndpi_serialize_string_string(serializer, "src_ip", src_name);
    ndpi_serialize_string_string(serializer, "dest_ip", dst_name);

    if (src_port)
    {
        ndpi_serialize_string_uint32(serializer, "src_port", src_port);
    }

    if (dst_port)
    {
        ndpi_serialize_string_uint32(serializer, "dst_port", dst_port);
    }

    ndpi_serialize_string_uint32(serializer, "proto", l4_protocol);
    ndpi_serialize_string_string(serializer, "action", action);
    ndpi_serialize_string_string(serializer, "status", status);

    // s2d_direction
    ndpi_serialize_start_of_block(serializer, "s2d");

    if (s2d)
    {
        ndpi_serialize_string_uint64(serializer, "pkts", s2d->pkts);
        ndpi_serialize_string_uint64(serializer, "bytes", s2d->bytes);
        ndpi_serialize_string_uint32(serializer, "tcp_flags", s2d->tcp_flags);
        ndpi_serialize_string_uint64(serializer, "first_seen",
                                     get_time_ms(s2d->first));
        ndpi_serialize_string_uint64(serializer, "last_seen",
                                     get_time_ms(s2d->last));
    }

    ndpi_serialize_end_of_block(serializer);

    // d2s_direction
    ndpi_serialize_start_of_block(serializer, "d2s");

    if (d2s)
    {
        ndpi_serialize_string_uint64(serializer, "pkts", d2s->pkts);
        ndpi_serialize_string_uint64(serializer, "bytes", d2s->bytes);
        ndpi_serialize_string_uint32(serializer, "tcp_flags", d2s->tcp_flags);
        ndpi_serialize_string_uint64(serializer, "first_seen",
                                     get_time_ms(d2s->first));
        ndpi_serialize_string_uint64(serializer, "last_seen",
                                     get_time_ms(d2s->last));
    }

    ndpi_serialize_end_of_block(serializer);

    ndpi_serialize_start_of_block(serializer, "ndpi");

    ndpi_serialize_string_string(
        serializer, "proto",
        ndpi_protocol2name(ndpi_struct, *l7_protocol, buf, sizeof(buf)));

    if (l7_protocol->category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    {
        ndpi_serialize_string_string(
            serializer, "category",
            ndpi_category_get_name(ndpi_struct, l7_protocol->category));
    }

    ndpi_serialize_end_of_block(serializer);

    if (flow == NULL)
    {
        // ndpi_serialize_end_of_block(serializer);
        return (-1);
    }

    if (flow->risk)
    {
        u_int i;

        ndpi_serialize_start_of_block(serializer, "flow_risks");

        for (i = 0; i < NDPI_MAX_RISK; i++)
        {
            if (NDPI_ISSET_BIT(flow->risk, i))
            {
                ndpi_serialize_string_string(serializer, name_flow_risk(i),
                                             ndpi_risk2str(i));
            }
        }
        ndpi_serialize_end_of_block(serializer);
    }

    switch (l7_protocol->master_protocol ? l7_protocol->master_protocol
                                         : l7_protocol->app_protocol)
    {
    case NDPI_PROTOCOL_DHCP:
        ndpi_serialize_start_of_block(serializer, "dhcp");
        ndpi_serialize_string_string(serializer, "fingerprint",
                                     flow->protos.dhcp.fingerprint);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_BITTORRENT:
    {
        u_int i, j, n = 0;
        char bittorent_hash[sizeof(flow->protos.bittorrent.hash) * 2 + 1];
        // char bittorent_hash[32];

        for (i = 0, j = 0; j < sizeof(bittorent_hash) - 1; i++)
        {
            sprintf(&bittorent_hash[j], "%02x",
                    flow->protos.bittorrent.hash[i]);

            j += 2, n += flow->protos.bittorrent.hash[i];
        }

        if (n == 0)
            bittorent_hash[0] = '\0';

        ndpi_serialize_start_of_block(serializer, "bittorrent");
        ndpi_serialize_string_string(serializer, "hash", bittorent_hash);
        ndpi_serialize_end_of_block(serializer);
    }
    break;

    case NDPI_PROTOCOL_DNS:
        ndpi_serialize_start_of_block(serializer, "dns");
        if (flow->host_server_name[0] != '\0')
            ndpi_serialize_string_string(
                serializer, "query", (const char *)flow->host_server_name);
        ndpi_serialize_string_uint32(serializer, "num_queries",
                                     flow->protos.dns.num_queries);
        ndpi_serialize_string_uint32(serializer, "num_answers",
                                     flow->protos.dns.num_answers);
        ndpi_serialize_string_uint32(serializer, "reply_code",
                                     flow->protos.dns.reply_code);
        ndpi_serialize_string_uint32(serializer, "query_type",
                                     flow->protos.dns.query_type);
        ndpi_serialize_string_uint32(serializer, "rsp_type",
                                     flow->protos.dns.rsp_type);

        inet_ntop(AF_INET, &flow->protos.dns.rsp_addr, buf, sizeof(buf));
        ndpi_serialize_string_string(serializer, "rsp_addr", buf);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_MDNS:
        ndpi_serialize_start_of_block(serializer, "mdns");
        ndpi_serialize_string_string(serializer, "answer",
                                     (const char *)flow->host_server_name);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_UBNTAC2:
        ndpi_serialize_start_of_block(serializer, "ubntac2");
        ndpi_serialize_string_string(serializer, "version",
                                     flow->protos.ubntac2.version);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_KERBEROS:
        ndpi_serialize_start_of_block(serializer, "kerberos");
        ndpi_serialize_string_string(serializer, "hostname",
                                     flow->protos.kerberos.hostname);
        ndpi_serialize_string_string(serializer, "domain",
                                     flow->protos.kerberos.domain);
        ndpi_serialize_string_string(serializer, "username",
                                     flow->protos.kerberos.username);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_TELNET:
        ndpi_serialize_start_of_block(serializer, "telnet");
        ndpi_serialize_string_string(serializer, "username",
                                     flow->protos.telnet.username);
        ndpi_serialize_string_string(serializer, "password",
                                     flow->protos.telnet.password);
        ndpi_serialize_end_of_block(serializer);
        break;
    // bug here
    case NDPI_PROTOCOL_HTTP:
        // printf("NDPI_PROTOCOL_HTTP %u %d\n", 3,serializer);
        ndpi_serialize_start_of_block(serializer, "http");

        if ((&flow->host_server_name[0] != NULL) &&
            (flow->host_server_name[0] != '\0'))
        {
            ndpi_serialize_string_string(
                serializer, "hostname",
                (const char *)flow->host_server_name);
        }

        // printf("&flow->host_server_name[0] >>>>>> %d \n",
        // &flow->host_server_name[0]);
        // printf("&flow->initial_binary_bytes[0] >>>>>> %d \n",
        // &flow->initial_binary_bytes[0]); printf("&flow->http.url[0]
        // >>>>>> %d \n", &flow->http.url[0]); printf("flow->http.url[0]
        // >>>>>>> %s\n",flow->http.url[0]);

        if (&flow->http.url[0] > &flow->host_server_name[0])
        {
            // printf("flow->http.url[0] > NULL %d\n", &flow->http.url[0]);
            ndpi_serialize_string_string(serializer, "url", flow->http.url);
            ndpi_serialize_string_uint32(serializer, "code",
                                         flow->http.response_status_code);
            ndpi_serialize_string_string(serializer, "content_type",
                                         flow->http.content_type);
            ndpi_serialize_string_string(serializer, "user_agent",
                                         flow->http.user_agent);
            ndpi_serialize_string_uint32(serializer, "method",
                                         flow->http.method);
            ndpi_serialize_string_string(
                serializer, "detected_os",
                (const char *)flow->http.detected_os);
            ndpi_serialize_string_string(
                serializer, "nat_ip",
                (const char *)flow->protos.http.nat_ip);
        }

        ndpi_serialize_end_of_block(serializer);

        break;

    case NDPI_PROTOCOL_MAIL_IMAP:
        ndpi_serialize_start_of_block(serializer, "imap");
        ndpi_serialize_string_string(
            serializer, "user", flow->protos.ftp_imap_pop_smtp.username);
        ndpi_serialize_string_string(
            serializer, "password",
            flow->protos.ftp_imap_pop_smtp.password);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_MAIL_POP:
        ndpi_serialize_start_of_block(serializer, "pop");
        ndpi_serialize_string_string(
            serializer, "user", flow->protos.ftp_imap_pop_smtp.username);
        ndpi_serialize_string_string(
            serializer, "password",
            flow->protos.ftp_imap_pop_smtp.password);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_MAIL_SMTP:
        ndpi_serialize_start_of_block(serializer, "smtp");
        ndpi_serialize_string_string(
            serializer, "user", flow->protos.ftp_imap_pop_smtp.username);
        ndpi_serialize_string_string(
            serializer, "password",
            flow->protos.ftp_imap_pop_smtp.password);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_FTP_CONTROL:
        ndpi_serialize_start_of_block(serializer, "ftp");
        ndpi_serialize_string_string(
            serializer, "user", flow->protos.ftp_imap_pop_smtp.username);
        ndpi_serialize_string_string(
            serializer, "password",
            flow->protos.ftp_imap_pop_smtp.password);
        ndpi_serialize_string_uint32(
            serializer, "auth_failed",
            flow->protos.ftp_imap_pop_smtp.auth_failed);
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_SSH:
        ndpi_serialize_start_of_block(serializer, "ssh");
        ndpi_serialize_string_string(serializer, "client_signature",
                                     flow->protos.ssh.client_signature);
        ndpi_serialize_string_string(serializer, "server_signature",
                                     flow->protos.ssh.server_signature);
        ndpi_serialize_string_string(serializer, "hassh_client",
                                     flow->protos.ssh.hassh_client);
        ndpi_serialize_string_string(serializer, "hassh_server",
                                     flow->protos.ssh.hassh_server);
        ndpi_serialize_end_of_block(serializer);
        break;
    // testing
    case NDPI_PROTOCOL_QUIC:
        ndpi_serialize_start_of_block(serializer, "quic");
        if (flow->protos.tls_quic_stun.tls_quic
                .client_requested_server_name[0] != '\0')
            ndpi_serialize_string_string(serializer,
                                         "client_requested_server_name",
                                         flow->protos.tls_quic_stun.tls_quic
                                             .client_requested_server_name);
        if (flow->http.user_agent)
            ndpi_serialize_string_string(serializer, "user_agent",
                                         flow->http.user_agent);
        if (flow->protos.tls_quic_stun.tls_quic.ssl_version)
        {
            u_int8_t unknown_tls_version;
            char *version = ndpi_ssl_version2str(
                flow, flow->protos.tls_quic_stun.tls_quic.ssl_version,
                &unknown_tls_version);

            if (!unknown_tls_version)
                ndpi_serialize_string_string(serializer, "version",
                                             version);
            if (flow->protos.tls_quic_stun.tls_quic.alpn)
                ndpi_serialize_string_string(
                    serializer, "alpn",
                    flow->protos.tls_quic_stun.tls_quic.alpn);
            ndpi_serialize_string_string(
                serializer, "ja3",
                flow->protos.tls_quic_stun.tls_quic.ja3_client);
            if (flow->protos.tls_quic_stun.tls_quic.tls_supported_versions)
                ndpi_serialize_string_string(
                    serializer, "tls_supported_versions",
                    flow->protos.tls_quic_stun.tls_quic
                        .tls_supported_versions);
        }
        ndpi_serialize_end_of_block(serializer);
        break;

    case NDPI_PROTOCOL_TLS:
        if (flow->protos.tls_quic_stun.tls_quic.ssl_version)
        {
            char notBefore[32], notAfter[32];
            struct tm a, b, *before = NULL, *after = NULL;
            u_int i, off;
            u_int8_t unknown_tls_version;
            char *version = ndpi_ssl_version2str(
                flow, flow->protos.tls_quic_stun.tls_quic.ssl_version,
                &unknown_tls_version);

            if (flow->protos.tls_quic_stun.tls_quic.notBefore)
                before = gmtime_r((const time_t *)&flow->protos
                                      .tls_quic_stun.tls_quic.notBefore,
                                  &a);
            if (flow->protos.tls_quic_stun.tls_quic.notAfter)
                after = gmtime_r((const time_t *)&flow->protos.tls_quic_stun
                                     .tls_quic.notAfter,
                                 &b);

            if (!unknown_tls_version)
            {
                ndpi_serialize_start_of_block(serializer, "tls");
                ndpi_serialize_string_string(serializer, "version",
                                             version);
                ndpi_serialize_string_string(
                    serializer, "client_requested_server_name",
                    flow->protos.tls_quic_stun.tls_quic
                        .client_requested_server_name);
                if (flow->protos.tls_quic_stun.tls_quic.server_names)
                    ndpi_serialize_string_string(
                        serializer, "server_names",
                        flow->protos.tls_quic_stun.tls_quic.server_names);

                if (before)
                {
                    strftime(notBefore, sizeof(notBefore),
                             "%Y-%m-%d %H:%M:%S", before);
                    ndpi_serialize_string_string(serializer, "notbefore",
                                                 notBefore);
                }

                if (after)
                {
                    strftime(notAfter, sizeof(notAfter),
                             "%Y-%m-%d %H:%M:%S", after);
                    ndpi_serialize_string_string(serializer, "notafter",
                                                 notAfter);
                }
                ndpi_serialize_string_string(
                    serializer, "ja3",
                    flow->protos.tls_quic_stun.tls_quic.ja3_client);
                ndpi_serialize_string_string(
                    serializer, "ja3s",
                    flow->protos.tls_quic_stun.tls_quic.ja3_server);
                ndpi_serialize_string_uint32(
                    serializer, "unsafe_cipher",
                    flow->protos.tls_quic_stun.tls_quic
                        .server_unsafe_cipher);
                ndpi_serialize_string_string(
                    serializer, "cipher",
                    ndpi_cipher2str(
                        flow->protos.tls_quic_stun.tls_quic.server_cipher));

                if (flow->protos.tls_quic_stun.tls_quic.issuerDN)
                    ndpi_serialize_string_string(
                        serializer, "issuerDN",
                        flow->protos.tls_quic_stun.tls_quic.issuerDN);

                if (flow->protos.tls_quic_stun.tls_quic.subjectDN)
                    ndpi_serialize_string_string(
                        serializer, "subjectDN",
                        flow->protos.tls_quic_stun.tls_quic.subjectDN);

                if (flow->protos.tls_quic_stun.tls_quic.alpn)
                    ndpi_serialize_string_string(
                        serializer, "alpn",
                        flow->protos.tls_quic_stun.tls_quic.alpn);

                if (flow->protos.tls_quic_stun.tls_quic
                        .tls_supported_versions)
                    ndpi_serialize_string_string(
                        serializer, "tls_supported_versions",
                        flow->protos.tls_quic_stun.tls_quic
                            .tls_supported_versions);

                if (flow->protos.tls_quic_stun.tls_quic
                        .sha1_certificate_fingerprint[0] != '\0')
                {
                    for (i = 0, off = 0; i < 20; i++)
                    {
                        int rc = snprintf(
                            &buf[off], sizeof(buf) - off, "%s%02X",
                            (i > 0) ? ":" : "",
                            flow->protos.tls_quic_stun.tls_quic
                                    .sha1_certificate_fingerprint[i] &
                                0xFF);

                        if (rc <= 0)
                            break;
                        else
                            off += rc;
                    }

                    ndpi_serialize_string_string(serializer, "fingerprint",
                                                 buf);
                }

                ndpi_serialize_end_of_block(serializer);
            }
        }
        break;
    } /* switch */

    ndpi_serialize_end_of_block(serializer);

    return (0);
}

int stats2json(struct capture_interfaces_info *if_info,
               ndpi_serializer *serializer)
{
    if (ndpi_init_serializer(serializer, ndpi_serialization_format_json) == -1)
        return (-1);

    ndpi_serialize_start_of_block(serializer, "interface");

    /* Traffic stats*/
    ndpi_serialize_string_string(serializer, "ifname", if_info->ifname);
    ndpi_serialize_string_uint64(serializer, "mtu", if_info->mtu);
    ndpi_serialize_string_uint64(serializer, "speed", if_info->speed);
    ndpi_serialize_string_uint64(serializer, "rx_thoughput",
                                 if_info->rx_thoughput);
    ndpi_serialize_string_uint64(serializer, "tx_thoughput",
                                 if_info->tx_thoughput);
    ndpi_serialize_string_uint64(serializer, "tot_pkts", if_info->tot_pkts);
    ndpi_serialize_string_uint64(serializer, "tot_rx_pkts", if_info->recv_pkts);
    ndpi_serialize_string_uint64(serializer, "tot_tx_pkts", if_info->sent_pkts);
    ndpi_serialize_string_uint64(serializer, "drop_pkts", if_info->drop_pkts);
    ndpi_serialize_string_uint64(serializer, "tot_rx_bytes",
                                 if_info->recv_bytes);
    ndpi_serialize_string_uint64(serializer, "tot_tx_bytes",
                                 if_info->sent_bytes);
    ndpi_serialize_string_uint64(serializer, "tot_bytes", if_info->tot_bytes);
    ndpi_serialize_string_uint64(serializer, "drop_bytes", if_info->drop_bytes);

    /* Flow stats on an interface */
    ndpi_serialize_string_uint64(serializer, "num_act_flows",
                                 if_info->act_flows);
    ndpi_serialize_string_uint64(serializer, "num_flows", if_info->tot_flows);
    ndpi_serialize_string_uint64(serializer, "num_threads",
                                 if_info->tot_threads);
    ndpi_serialize_string_uint64(serializer, "num_errors",
                                 if_info->tot_err_flows);

    ndpi_serialize_end_of_block(serializer);

    return (0);
}

int init_zmq(u_int8_t queues)
{
    int i;
    printf("init_zmq %u\n", queues);

    if (zmq_endpoint == NULL)
    {
        zmq_endpoint = DEFAULT_ZMQ_ENDPOINT;
    }

    zmq_clients = calloc(queues + 1, sizeof(void *));
    ctx = zmq_ctx_new();
    assert(ctx);
    zmq_ctx_set(ctx, ZMQ_IO_THREADS, queues);

    assert(zmq_ctx_get(ctx, ZMQ_IO_THREADS) == queues);

    for (i = 0; i <= queues; i++)
    {
        zmq_clients[i] = init_zmq_connection(ctx, zmq_endpoint, i);
        if (zmq_clients[i] == NULL)
        {
            // trace(TRACE_ERROR, "Could not connect to server: %s\n",
            // zmq_endpoint);
            return (-1);
        }
    }

    return 0;
}

char *zmq_getendpoint() { return zmq_endpoint; }

void zmq_setendpoint(char *endpoint)
{
    zmq_endpoint = endpoint;
    printf("zmq_setendpoint %s\n", zmq_endpoint);
}

/*EOF*/