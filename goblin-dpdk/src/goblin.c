

#include "../inc/goblin.h"

#include <net/if.h>

#include "../inc/pfring_utils.h"

#define VDEV_NAME "net_pcap_%s_%d"
#define VDEV_IFACE_ARGS "iface=%s"
/* ************************************ */

/* ************************************ */
void getGoblinIfaces(uint8_t id, char *outiface, u_int8_t flag)
{
    if (flag == 0)
    {
        snprintf(outiface, 64, ifaces[id]);
    }
    else
    {
        snprintf(outiface, 64, "goblin(%s)", ifaces[id]);
    }
}

/* ************************************ */
int add_interfaces()
{
    int ret = 0;
    uint8_t i, max_iface_index = sizeof(ifaces) / sizeof(ifaces[0]);

    char vdev_name[64];
    char vdev_args[64];

    for (i = 0; i < max_iface_index; i++)
    {
        if (!strcmp(ifaces[i], ""))
        {
            // printf("max_iface_at: %u\n",i);
            max_iface_index = i;
            ret = (int)i;
            break;
        }
        else
        {
            ret = -1;
        }
    }

    if (ret > 0)
    {
        for (i = 0; i < max_iface_index; i++)
        {
            printf("iface: %u %s\n", i, ifaces[i]);

            snprintf(vdev_name, sizeof(vdev_name), "net_pcap_%s", ifaces[i]);
            snprintf(vdev_args, sizeof(vdev_args), "iface=%s", ifaces[i]);

            if (rte_eal_hotplug_add("vdev", vdev_name, vdev_args) < 0)
            {
                rte_exit(EXIT_FAILURE, "vdev creation failed:%s:%d\n", __func__,
                         __LINE__);
            }
        }
        return ret;
    }

    return ret;

    // printf("max_iface: %u\n",max_iface_index);
}
/* ************************************ */