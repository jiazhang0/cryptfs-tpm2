include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

SCRIPT_NAME := luks-setup.sh

all: $(SCRIPT_NAME) Makefile

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(sbindir)
	$(INSTALL) -m 700 $(SCRIPT_NAME) $(DESTDIR)$(sbindir)

clean:
