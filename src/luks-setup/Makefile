include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

BIN_NAME := luks-setup

all: $(BIN_NAME).sh Makefile

clean:

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 700 $(BIN_NAME).sh $(DESTDIR)$(SBINDIR)/$(BIN_NAME)
