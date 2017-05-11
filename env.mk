CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
AR := $(CROSS_COMPILE)ar
INSTALL ?= install

EXTRA_CFLAGS ?=
EXTRA_LDFLAGS ?=

DEBUG_BUILD ?=
prefix ?= /usr/local
libdir ?= $(prefix)/lib
sbindir ?= $(prefix)/sbin
includedir ?= $(prefix)/include

tpm2_tss_includedir ?= $(includedir)
tpm2_tss_libdir ?= $(libdir)

# For the installation
DESTDIR ?=
LIBDIR ?= $(libdir)
SBINDIR ?= $(sbindir)

# The authorization password for the primary key
primary_key_secret ?= H31i05
# The authorization password for the passphrase
passphrase_secret ?= h31i05
# The byte code used to encrypt/decrypt secrets
secret_xor_byte_code ?= 0x48

LDFLAGS := --warn-common --no-undefined --fatal-warnings \
	   $(patsubst $(join -Wl,,)%,%,$(EXTRA_LDFLAGS))
CFLAGS := -D_GNU_SOURCE -std=gnu99 -O2 -Wall -Werror \
	  $(addprefix -I, $(TOPDIR)/src/include \
	  $(tpm2_tss_includedir)) \
	  $(addprefix $(join -L,),$(tpm2_tss_libdir)) \
	  -lsapi -ltcti-socket \
	  $(EXTRA_CFLAGS) $(addprefix $(join -Wl,,),$(LDFLAGS))

ifneq ($(DEBUG_BUILD),)
	CFLAGS += -ggdb -DDEBUG
endif
