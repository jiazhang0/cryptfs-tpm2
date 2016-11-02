CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
AR := $(CROSS_COMPILE)ar
INSTALL ?= install

EXTRA_CFLAGS ?=
EXTRA_LDFLAGS ?=

DEBUG_BUILD ?=
DESTDIR ?=
prefix ?= /usr/local
libdir ?= $(prefix)/lib
sbindir ?= $(prefix)/sbin
includedir ?= $(prefix)/include

tpm2_tss_includedir ?= $(includedir)
tpm2_tss_libdir ?= $(libdir)

LDFLAGS := --warn-common --no-undefined --fatal-warnings \
	   $(patsubst $(join -Wl,,)%,%,$(EXTRA_LDFLAGS))
CFLAGS := -D_GNU_SOURCE -std=gnu99 -O2 -Wall -Werror \
	  $(addprefix -I, $(TOPDIR)/src/include \
	  $(tpm2_tss_includedir)) \
	  -L$(tpm2_tss_libdir) -lsapi -ltcti-socket \
	  $(EXTRA_CFLAGS) $(addprefix $(join -Wl,,),$(LDFLAGS))

ifneq ($(DEBUG_BUILD),)
	CFLAGS += -ggdb -DDEBUG
endif