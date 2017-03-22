include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

all: luks-setup.sh encrypt_secret.py Makefile

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(sbindir)
	$(INSTALL) -m 700 luks-setup.sh $(DESTDIR)$(sbindir)

clean:
	@$(RM) -f encrypt_secret.py

encrypt_secret.py: encrypt_secret.py.in
	@sed -e "s/@@CRYPTFS_TPM2_SECRET_XOR_BYTE_CODE@@/$(secret_xor_byte_code)/" \
	    < $< > $@
	@chmod +x $@
