CFLAGS=-Wall -Wextra -pedantic -O3 -Ilibelfctx
LDFLAGS=

EXECUTABLE?=lself
LIBELFCTX?=libelfctx.a

AUTOCOMPLETION_SCRIPT=$(EXECUTABLE)_completion.bash
AUTOCOMPLETION_SCRIPT_IN=completion.bash.in

INSTALL=install
PREFIX?=/usr

ifeq ($(V),1)
	Q =
else
	Q = @
endif

.PHONY: all clean install

all: $(EXECUTABLE) $(AUTOCOMPLETION_SCRIPT)

install: all
	@echo "INSTALLING..."
	$(Q)$(INSTALL) -v -Dm755 $(EXECUTABLE) $(PREFIX)/bin/$(EXECUTABLE)
	$(Q)$(INSTALL) -v -Dm755 $(AUTOCOMPLETION_SCRIPT) $(PREFIX)/share/bash-completion/completions/$(EXECUTABLE)


#Replace %EXECUTABLE% with $(EXECUTABLE) in the input file to generate the autocompletion script
$(AUTOCOMPLETION_SCRIPT): $(AUTOCOMPLETION_SCRIPT_IN)
	$(Q)sed "s/%EXECUTABLE%/$(EXECUTABLE)/g" $(AUTOCOMPLETION_SCRIPT_IN) > $(AUTOCOMPLETION_SCRIPT)
	$(Q)chmod +x $(AUTOCOMPLETION_SCRIPT)

$(LIBELFCTX): libelfctx/*.c libelfctx/*.h
	@echo "BUILDING $@"
	$(Q)$(CC) $(CFLAGS) -c libelfctx/*.c -o libelfctx/libelfctx.o
	$(Q)ar rcs $@ libelfctx/*.o
	

$(EXECUTABLE): lself.c $(LIBELFCTX)
	@echo "LINK $@"
	$(Q)$(CC) $(CFLAGS) lself.c -o $@ $(LDFLAGS) $(LIBELFCTX)

clean:
	$(Q)rm -v -f $(EXECUTABLE) $(AUTOCOMPLETION_SCRIPT) libelfctx/*.o $(LIBELFCTX)
