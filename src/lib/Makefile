include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

LIB_NAME := libcryptfs-tpm2

LIB_TARGETS := $(LIB_NAME).so $(LIB_NAME).a

OBJS_$(LIB_NAME) = \
		   init.o \
		   build_info.o \
		   linux.o \
		   subcommand.o \
		   util.o \
		   session.o \
		   evict.o \
		   random.o \
		   create.o \
		   unseal.o

CFLAGS += -fpic

all: $(LIB_TARGETS) Makefile

clean:
	@$(RM) $(LIB_TARGETS) $(OBJS_$(LIB_NAME)) $(addsuffix .*, $(LIB_TARGETS)) cryptfs_tpm2_build_info.c

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(INSTALL) -m 755 $(LIB_NAME).a $(DESTDIR)$(libdir)
	$(INSTALL) -m 755 $(LIB_NAME).so $(DESTDIR)$(libdir)/$(LIB_NAME).so.$(VERSION)
	$(foreach x, $(LIB_NAME).so, ln -sfn $(x).$(VERSION) $(DESTDIR)$(libdir)/$(patsubst %,%.$(MAJOR_VERSION).$(MINOR_VERSION),$(x)); \
		ln -sfn $(x).$(MAJOR_VERSION).$(MINOR_VERSION) $(DESTDIR)$(libdir)/$(patsubst %,%.$(MAJOR_VERSION),$(x));)

$(LIB_NAME).so: $(OBJS_$(LIB_NAME))
	$(CC) $^ -o $@ $(CFLAGS) -shared -Wl,-soname,$(patsubst %.$(VERSION),%,$@)

$(LIB_NAME).a: $(OBJS_$(LIB_NAME))
	$(AR) rcs $@ $^

build_info.c: build_info.c.in
	sed -e "s~@@CRYPTFS_TPM2_GIT_COMMIT@@~$(shell if [ -d $(TOPDIR)/.git ]; then git log -1 --pretty=format:%H | tr -d '\n'; elif [ -f $(TOPDIR)/commit ]; then cat $(TOPDIR)/commit | tr -d '\n'; else echo -n ???????; fi)~" \
		-e "s~@@CRYPTFS_TPM2_BUILD_MACHINE@@~$(shell whoami | tr -d '\n'; echo -n @; uname -a | tr -d '\n')~" < $^ > $@