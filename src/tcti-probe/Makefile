include $(TOPDIR)/env.mk
include $(TOPDIR)/rules.mk

BIN_NAME := tcti-probe

OBJS_$(BIN_NAME) := \
		    main.o \
		    subcmd_help.o \
		    subcmd_wait.o

all: $(BIN_NAME) Makefile

$(BIN_NAME): $(OBJS_$(BIN_NAME)) $(TOPDIR)/src/lib/$(LIB_NAME).a
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	@$(RM) $(OBJS_$(BIN_NAME)) $(BIN_NAME)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 700 $(BIN_NAME) $(DESTDIR)$(SBINDIR)
