//#define _GNU_SOURCE
#ifdef linux
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h> /* for CPU_XXXX */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef HAVE_DPDK
#include <netinet/if_ether.h>
#else
#define ETH_ALEN 6
#endif

#include "pfring.h"
#include "pfring_zc.h"

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

#define POW2(n) ((n & (n - 1)) == 0)

#define MAX_NUM_OPTIONS 64

#define DEFAULT_CLUSTER_ID 99

typedef u_int64_t ticks;

double delta_time(struct timeval *now,
                  struct timeval *before);

char *_intoa(unsigned int addr, char *buf, u_short bufLen);

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

/** EOF **/
