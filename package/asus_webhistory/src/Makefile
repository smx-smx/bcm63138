-include $(TOP_DIR)/.config

CFLAGS += -fPIC $(EXTRACFLAGS)
LDFLAGS += -lasusnvram -L. -L$(TOPDIR)/extern/arc-release/usr/lib -larcgpl -ldisk

all: lib webhistory

lib: webhistory.o
	$(CC) $(LDFLAGS) -shared -fPIC -o libwebhistory.so $^

webhistory: webhistory.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ webhistory.o

clean:
	rm -f webhistory
	rm -f *.o libwebhistory.so

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<

install: all
	install -D webhistory $(INSTALLDIR)/bin/webhistory
	install -D libwebhistory.so $(INSTALLDIR)/lib/libwebhistory.so
	$(STRIP) $(INSTALLDIR)/bin/webhistory
