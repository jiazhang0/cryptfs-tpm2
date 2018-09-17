CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
CCLD := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
INSTALL ?= install
PKG_CONFIG ?= pkg-config

EXTRA_CFLAGS ?=
EXTRA_LDFLAGS ?=

DEBUG_BUILD ?=
TSS2_VER ?= 2
prefix ?= /usr/local
libdir ?= $(prefix)/lib
sbindir ?= $(prefix)/sbin
includedir ?= $(prefix)/include

tpm2_tss_includedir ?= $(includedir)
tpm2_tss_libdir ?= $(libdir)

tpm2_tabrmd_includedir ?= $(includedir)

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
	    $(tpm2_tss_includedir) $(tpm2_tabrmd_includedir) \
            $(glib_includedir)) \
	  $(addprefix $(join -L,), $(tpm2_tss_libdir)) \
	  `$(PKG_CONFIG) --cflags glib-2.0` \
	  `$(PKG_CONFIG) --libs glib-2.0` \
	  $(EXTRA_CFLAGS) $(addprefix $(join -Wl,,),$(LDFLAGS))

ifneq ($(TSS2_VER), 1)
	CFLAGS += -ldl -ltss2-sys -ltss2-tcti-mssim -ltss2-tcti-device
else
	CFLAGS += -ldl -lsapi -ltcti-socket -ltcti-device -DTSS2_LEGACY_V1
endif

ifneq ($(DEBUG_BUILD),)
	CFLAGS += -ggdb -DDEBUG
endif
