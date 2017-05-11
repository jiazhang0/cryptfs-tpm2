include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

BIN_NAME := cryptfs-tpm2

OBJS_$(BIN_NAME) := \
		    main.o \
		    subcmd_help.o \
		    subcmd_evict.o \
		    subcmd_seal.o \
		    subcmd_unseal.o

all: $(BIN_NAME) Makefile

$(BIN_NAME): $(OBJS_$(BIN_NAME)) $(TOPDIR)/src/lib/$(LIB_NAME).so
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	@$(RM) $(OBJS_$(BIN_NAME)) $(BIN_NAME)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 700 $(BIN_NAME) $(DESTDIR)$(SBINDIR)
