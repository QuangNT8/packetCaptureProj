/*
 * (C) 2003-2020 - ntop
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include "../inc/pfring_utils.h"

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time(struct timeval *now, struct timeval *before)
{
    time_t delta_seconds;
    time_t delta_microseconds;

    /*
     * compute delta in second, 1/10's and 1/1000's second units
     */
    delta_seconds = now->tv_sec - before->tv_sec;
    delta_microseconds = now->tv_usec - before->tv_usec;

    if (delta_microseconds < 0)
    {
        /* manually carry a one from the seconds field */
        delta_microseconds += 1000000; /* 1e6 */
        --delta_seconds;
    }
    return ((double)(delta_seconds * 1000) + (double)delta_microseconds / 1000);
}

/* *************************************** */

#define MSEC_IN_DAY (1000 * 60 * 60 * 24)
#define MSEC_IN_HOUR (1000 * 60 * 60)
#define MSEC_IN_MINUTE (1000 * 60)
#define MSEC_IN_SEC (1000)

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

/* EOF */
