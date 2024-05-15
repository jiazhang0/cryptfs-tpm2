include $(TOPDIR)/version.mk

SUBDIRS := lib cryptfs-tpm2 tcti-probe luks-setup

.DEFAULT_GOAL := all
.PHONE: all clean install

all clean install:
	@for x in $(SUBDIRS); do $(MAKE) -C $$x $@ || exit $?; done
