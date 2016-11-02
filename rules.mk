include $(TOPDIR)/version.mk

LIB_NAME := libcryptfs-tpm2

LDFLAGS +=
CFLAGS += -DVERSION=\"$(VERSION)\"

.DEFAULT_GOAL := all
.PHONE: all clean install