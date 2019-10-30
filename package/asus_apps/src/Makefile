-include $(TOP_DIR)/.config

CFLAGS:=-g -I/usr/include
LDFLAGS:=-L/usr/lib 

CLI_CFLAGS  = $(CFLAGS)
CLI_LDFLAGS = $(LDFLAGS)

CFGCLI_OBJ = main.o
#CFGCLI_SRC := $(CFGCLI_OBJ:.o=.c)

all: lib asus_nvram asus_rc

lib: asus_nvram.o
	$(CC) $(CLI_LDFLAGS) -shared -fPIC -o libasusnvram.so $^

asus_nvram: $(CFGCLI_OBJ)
	$(CC) $(CLI_LDFLAGS) -o nvram $(CFGCLI_OBJ) -L. -L$(TOPDIR)/extern/arc-release/usr/lib -lasusnvram -larcgpl -lc 

asus_rc: asus_rc.o pids.o
	$(CC) $(CLI_LDFLAGS) -o rc $^ -L. -L$(TOPDIR)/extern/arc-release/usr/lib -larcgpl -lc 

.c.o:
	$(CC) $(CLI_CFLAGS) -fPIC -c -o $@ $<

clean:
	rm -f nvram
	find . -name "*.[oa]" | xargs rm -f 
