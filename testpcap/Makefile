# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2016 Intel Corporation

# binary name
APP = testpcap

PKGCONF ?= pkg-config
# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

# all source are stored in SRCS-y
SRCS-y := main.c 
SRCS-y +=util.c 
SRCS-y +=config.c 
SRCS-y +=parameters.c 
# sample application files
SRCS-y +=sample_app/flowgen.c 
SRCS-y +=sample_app/icmpecho.c 
SRCS-y +=sample_app/iofwd.c 
SRCS-y +=sample_app/rxonly.c 
SRCS-y +=sample_app/txonly.c 
# application files
SRCS-y +=app/goblin.c 
SRCS-y +=app/ftutils.c
SRCS-y +=app/db_zmq.c 

# ********************* PFRING lib ********************************
# 
PFRINGDIR  = ../../system/PF_RING/userland/lib
PFRING_KERNEL=../../system/PF_RING/kernel
# LIBPFRING  = ${PFRINGDIR}/libpfring.a
LIBPFRINGFT = ${PFRINGDIR}/libs/libpfring_ft_x86_64_dl.a
#
# PF_RING aware libpcap
#
PCAPDIR    = ../PF_RING/userland/libpcap
LIBPCAP    = ${PCAPDIR}/libpcap.a  ${EXTRA_LIBS}
INCLUDEPFRING    = -I${PFRING_KERNEL} -I${PFRINGDIR} -I${PCAPDIR} -Ithird-party `../../system/PF_RING/userland/lib/pfring_config --include` -I/usr/local/include/ndpi

#
# User and System libraries
#
USERLIBS += ${LIBPFRINGFT} $(shell $(PKGCONF) --libs libdpdk) -lpthread -lrt -ldl -L/usr/local/lib -lndpi -lrt -lm -lzmq

# *****************************************************************

all: shared

shared: build/$(APP)
	# ln -sf $(APP) build/$(APP)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk) ${INCLUDEPFRING}
# Added for 'rte_eth_link_to_str()'
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -Wno-deprecated-declarations
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
# LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)


build/$(APP): $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) $(USERLIBS)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)
	rm -f *.pcap
	test -d build && rmdir -p build || true
