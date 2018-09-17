include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

LIB_NAME := libcryptfs-tpm2

LIB_TARGETS := $(LIB_NAME).so $(LIB_NAME).a

OBJS_$(LIB_NAME) = \
		   init.o \
		   tss2.o \
		   option.o \
		   subcommand.o \
		   util.o \
		   tcti.o \
		   build_info.o \
		   secret_area.o \
		   secret.o \
		   session.o \
		   evict.o \
		   random.o \
		   create.o \
		   unseal.o \
		   policy.o \
		   pcr.o \
		   hash.o \
		   capability.o \
		   da.o

CFLAGS += -fpic

all: $(LIB_TARGETS) Makefile

clean:
	@$(RM) $(LIB_TARGETS) $(OBJS_$(LIB_NAME)) \
	    $(addsuffix .*, $(LIB_TARGETS)) \
	    build_info.c secret.c \
	    *.secret

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 755 $(LIB_NAME).a $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 755 $(LIB_NAME).so $(DESTDIR)$(LIBDIR)/$(LIB_NAME).so.$(VERSION)
	$(foreach x, $(LIB_NAME).so, ln -sfn $(x).$(VERSION) $(DESTDIR)$(LIBDIR)/$(patsubst %,%.$(MAJOR_VERSION).$(MINOR_VERSION),$(x)); \
		ln -sfn $(x).$(MAJOR_VERSION).$(MINOR_VERSION) $(DESTDIR)$(LIBDIR)/$(patsubst %,%.$(MAJOR_VERSION),$(x));)

$(LIB_NAME).so: $(OBJS_$(LIB_NAME))
	$(CCLD) $^ -o $@ $(CFLAGS) -shared -Wl,-soname,$(patsubst %.$(VERSION),%,$@)

$(LIB_NAME).a: $(filter-out init.o,$(OBJS_$(LIB_NAME)))
	$(AR) rcs $@ $^

define encrypt_secret
	$(TOPDIR)/scripts/encrypt_secret.py -i "$(1)" > "$(2)" || exit 1
endef

build_info.c: build_info.c.in
	sed -e "s~@@CRYPTFS_TPM2_GIT_COMMIT@@~$(shell if [ -d $(TOPDIR)/.git ]; then git log -1 --pretty=format:%H | tr -d '\n'; elif [ -f $(TOPDIR)/commit ]; then cat $(TOPDIR)/commit | tr -d '\n'; else echo -n ???????; fi)~" \
	    -e "s~@@CRYPTFS_TPM2_BUILD_MACHINE@@~$(shell bash -c 'whoami | tr -d "\n"; echo -n @; uname=`uname -a`; echo -n $${uname//\~/_} | tr -d "\n"')~" \
	    < $< > $@

secret_area.S: primary_key.secret passphrase.secret

primary_key.secret: $(TOPDIR)/scripts/encrypt_secret.py
	$(call encrypt_secret,$(primary_key_secret),$@)

passphrase.secret: $(TOPDIR)/scripts/encrypt_secret.py
	$(call encrypt_secret,$(passphrase_secret),$@)

secret.c: secret.c.in
	sed -e "s/@@CRYPTFS_TPM2_SECRET_XOR_BYTE_CODE@@/$(secret_xor_byte_code)/" \
	    < $< > $@
