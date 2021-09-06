APP = goblin_dpdk

PKGCONF = pkg-config

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

PFRINGDIR  = ../../system/PF_RING/userland/lib
PFRING_KERNEL=../../system/PF_RING/kernel
# LIBPFRING  = ${PFRINGDIR}/libpfring.a
LIBPFRINGFT = ${PFRINGDIR}/libs/libpfring_ft_x86_64_dl.a

#
# PF_RING aware libpcap
#

EXTRA_LIBS = 
PCAPDIR    = ../PF_RING/userland/libpcap
LIBPCAP    = ${PCAPDIR}/libpcap.a  ${EXTRA_LIBS}


#
# Search directories
#
INCLUDE    = -I${PFRING_KERNEL} -I${PFRINGDIR} -I${PCAPDIR} -Ithird-party `../../system/PF_RING/userland/lib/pfring_config --include` -I/usr/local/include/ndpi

# C compiler and flags
#
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
#
CC         = ${CROSS_COMPILE}gcc -std=gnu99 #--platform=native
WFLAGS     = -Wall -Wno-unused-function -Wno-format-truncation -Wno-address-of-packed-member
CFLAGS     = -g -O3  ${INCLUDE} ${WFLAGS} $(shell $(PKGCONF) --cflags libdpdk) -D HAVE_PF_RING_FT -D HAVE_NDPI -D HAVE_DPDK

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)

#
# User and System libraries
#
LIBS += ${LIBPFRINGFT} $(shell $(PKGCONF) --libs libdpdk) -lpthread -lrt -ldl -L/usr/local/lib -lndpi -lrt -lm -lzmq

# all source are stored in SRCS-y
SRCS-y := main.c
SRCS-y += src/db_zmq.c
SRCS-y += src/dpdk.c
SRCS-y += src/ftutils.c
SRCS-y += src/goblin.c
SRCS-y += src/pfring_utils.c  
# *******************************


all: ${APP}

$(APP): $(SRCS-y) Makefile $(PC_FILE) 
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LIBS)

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp $(APP) $(DESTDIR)/usr/bin/

clean:
	rm -f $(APP)
