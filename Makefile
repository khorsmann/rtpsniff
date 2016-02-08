# vim:ts=8:noet
#
# Makefile for rtpsniff.
# By Walter Doekes, 2009,2014.

ifeq ($(CFLAGS),)
    CFLAGS = -Wall
endif
ifeq ($(LDFLAGS),)
    # -lslowpoll goes first
    LDFLAGS = -Wall -L./bin
endif
ifeq ($(LDLIBS),)
    LDLIBS = -lslowpoll -lpthread -lpcap -ljson
endif
ifeq ($(PREFIX),)
    PREFIX = /usr/local
endif


.PHONY: all clean distclean variables \
	rtpsniff rtpsniff-debug rtpsniff-verbose

all: rtpsniff rtpsniff-debug

clean:
	$(RM) -r bin

distclean: clean

variables:
	@if test -z "$(MOD_OUT)"; then \
	    echo 'Please select output module through MOD_OUT:' >&2; \
	    echo '  make MOD_OUT=out_console  # for console output' >&2; \
	    echo '  make MOD_OUT=out_syslog   # for syslog output' >&2; \
	    echo '  make MOD_OUT=out_json     # for json output' >&2; \
	    false; fi

rtpsniff: variables
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS) -DNDEBUG" \
	CFLAGS="$(CFLAGS) -g -O3" LDFLAGS="$(LDFLAGS) -g -O3" \
	MODULES="rtpsniff sniff_rtp $(MOD_OUT) timer_interval util" \
	$(MAKE) bin/$@
	@#strip bin/$@

rtpsniff-debug: variables
	APPNAME="$@" CPPFLAGS="$(CPPFLAGS)" \
	CFLAGS="$(CFLAGS) -g -O0" LDFLAGS="$(LDFLAGS) -g" \
	MODULES="rtpsniff sniff_rtp $(MOD_OUT) timer_interval util" \
	$(MAKE) bin/$@



.PHONY: install uninstall

install: bin/rtpsniff bin/libslowpoll.so
	install -DT -m 644 bin/libslowpoll.so $(PREFIX)/lib/libslowpoll.so
	install -DT -m 755 bin/rtpsniff $(PREFIX)/sbin/rtpsniff
	-ldconfig
uninstall:
	$(RM) $(PREFIX)/lib/libslowpoll.so $(PREFIX)/sbin/rtpsniff
	-ldconfig


$(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES))): Makefile endian.h rtpsniff.h

bin/libslowpoll.so: slowpoll.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -D_GNU_SOURCE -fPIC -ldl -shared -o $@ $<

bin/.$(APPNAME)/%.o: %.c
	@mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@
bin/$(APPNAME): bin/libslowpoll.so $(addprefix bin/.$(APPNAME)/, $(addsuffix .o, $(MODULES)))
	$(LINK.o) -L./bin $(filter-out bin/libslowpoll.so, $^) $(LDLIBS) -o $@
