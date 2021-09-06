#include "inc/main.h"

/* ************************************ */
static int processing_thread(__attribute__((unused)) void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    unsigned lcore_index = rte_lcore_index(lcore_id);
    u_int16_t queue_id = lcore_index;
    u_int16_t num;

    if (lcore_index >= nb_lcore_params)
    {
        return (-1);
    }

    printf("Capturing from queue %u Num Port: %u ...\n", queue_id, num_ports);

    while (do_loop)
    {
        num = capture2ft(lcore_params[lcore_index].port_id, fts[lcore_index]);
        if (num == 0)
        {
            continue;
        }
    } /* while */

    return 0;
}

/* ************************************ */
void sigproc(int sig)
{
    static int called = 0;

    fprintf(stderr, "Leaving...\n");
    if (called)
        return;
    else
        called = 1;

    do_loop = 0;
}
/* ************************************ */
void my_sigalarm(int sig)
{

    int i;
    if (!do_loop)
        return;

    for (i = 0; i < num_queues; i++)
    {
        print_stats(i);

        if (lcore_params[i].port_id == last_port_id)
        {
            send_stats(i);
        }
    }

    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}
/* ************************************ */
int main(int argc, char *argv[])
{
    uint16_t portid;
    int ret;
    long q;
    unsigned lcore_id;

    ret = rte_eal_init(argc, argv);

    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "vdev creation failed:%s:%d\n", __func__,
                 __LINE__);
    }

    argc -= ret;
    argv += ret;

    ret = parse_args(argc, argv);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "Invalid goblin_dpdk parameters\n");
    }

    ret = add_interfaces();
    if (ret > 0)
    {
        num_ports = ret;
    }
    else
    {
        rte_exit(EXIT_FAILURE, "Invalid port\n");
    }

    num_queues = nb_lcore_params;

    if (num_ports == 1)
    {
        printf("INFO: Just %u Port enabled, Number queues %u, Please Reconfigure The lcore_params_array_default! \n",
               num_ports, num_queues);
        num_queues = 1;
        setGolblinPort(0);
        getGoblinIfaces(getGolblinPort(), capture_info.ifname, isGolblinDev());
    }

    capture_info.port_id = goblin_port;
    capture_info.speed = 10;
    capture_info.act_flows = 0;
    capture_info.tot_flows = 0;
    capture_info.tot_err_flows = 0;
    capture_info.tot_threads = num_queues;
    capture_info.tot_bytes = 0;
    capture_info.tot_pkts = 0;
    capture_info.recv_bytes = 0;
    capture_info.recv_pkts = 0;
    capture_info.sent_bytes = 0;
    capture_info.sent_pkts = 0;
    capture_info.drop_bytes = 0;
    capture_info.drop_pkts = 0;

    memset(statistics, 0, sizeof(statistics));

    if (rte_lcore_count() > num_queues)
    {
        printf("INFO: %u lcores enabled, only %u used\n", rte_lcore_count(),
               num_queues);
        return -1;
    }

    if (rte_lcore_count() < num_queues)
    {
        num_queues = rte_lcore_count();
        printf("INFO: only %u lcores enabled, using %u queues\n",
               rte_lcore_count(), num_queues);
        return -1;
    }

    create_mbuf_pool();

    /* Initialize all ports. */
    RTE_ETH_FOREACH_DEV(portid)
    {
        if (port_init(portid, mbuf_pool) != 0)
        {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
        }
    }

    printf("Number Port: %d/%d num_queues : %u\n", ret, MAX_PORT, num_queues);

    if (init_zmq(num_queues) < 0)
    {
        rte_exit(EXIT_FAILURE, "Could not connect to server: %s\n",
                 zmq_getendpoint());
    }
    else
    {
        printf("connected to %s\n", zmq_getendpoint());
    }

    /************************ PFRING FT Init **************************/
    // ft_init(num_queues);
    ndpi_structs =
        calloc(num_queues, sizeof(struct ndpi_detection_module_struct *));
    /************************ PFRING FT **************************/
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;
    ft_flags |= PFRING_FT_DECODE_TUNNELS;
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI_EXTRA;
    ft_flags |= PF_RING_FT_FLOW_FLAGS_L7_GUESS;
    ft_flags |= PFRING_FT_IGNORE_HW_HASH; // ignore device an asymmetric hash

    for (q = 0; q < num_queues; q++)
    {
        fts[q] = pfring_ft_create_table(ft_flags, 0, 0, 0, 0);

        if (fts[q] == NULL)
        {
            fprintf(stderr, "pfring_ft_create_table error\n");
            return -1;
        }

        pfring_ft_set_flow_export_callback(fts[q], process_expired_flow,
                                           fts[q]);
    }

    /************************ PFRING FT End init **********************/

    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);

    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);

    rte_eal_mp_remote_launch(processing_thread, NULL, CALL_MAIN);

    RTE_LCORE_FOREACH_WORKER(lcore_id) { rte_eal_wait_lcore(lcore_id); }

    for (q = 0; q < num_queues; q++)
    {
        pfring_ft_flush(fts[q]);
        pfring_ft_destroy_table(fts[q]);
        zmq_close(zmq_clients[q]);
    }

    zmq_ctx_destroy(ctx);
    printf("zmq destroy ok \n");

    port_close();

    return 0;
}
