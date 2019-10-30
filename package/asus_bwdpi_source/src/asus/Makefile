#include ../../common.mak
-include $(TOP_DIR)/.config

CFLAGS += -Os -Wall $(EXTRACFLAGS) -fPIC
#CFLAGS += -I. -I$(TOP)/shared -I$(TOP)/nvram$(BCMEX)$(EX7) -I$(SRCBASE)/include -I$(TOP)/httpd
CFLAGS += -I. -I$(TOPDIR)/package/arcadyan-utility/httpd/src -I$(TOPDIR)/package/libdisk/src -I$(TOPDIR)/package/asus_apps/src
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/src/tdts_udb_sample
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/src/tdts_udb_sample/linux
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/include
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/asus_include

#LDFLAGS += -L$(TOP)/nvram$(BCMEX)$(EX7) -lnvram -L$(TOP)/shared -lshared
LDFLAGS += -lasusnvram -larcgpl -ldisk -lcrypto -lssl

# for QCA toolchain compile issue, xxxx-ld has no pthead and dl in openwrt-toolchain
ifeq ($(RTCONFIG_QCA),y)
EXTRACC += -lpthread -ldl
EXTRALD =
else
EXTRACC = 
EXTRALD = 
endif

LD1 += $(LDFLAGS) $(EXTRACC)
LD2 += $(LDFLAGS) $(EXTRALD)

# ASUSWRT
OBJS += shared_api.o iqos.o wrs.o stat.o dpi.o wrs_app.o data_collect.o watchdog_check.o

# TrendMicro
OBJS += ioc_wrs.o conf_app.o ioc_common.o ioc_anomaly.o ioc_patrol_tq.o ioc_vp.o ioc_qos.o ioc_internal.o bwdpi_utils.o mac_name_tab.o

ifeq ($(RTCONFIG_BCMARM),y)
vpath %.c $(SRCBASE)/shared
endif

vpath %.c $(TOPDIR)/package/asus_bwdpi_source/src/src/tdts_udb_sample

all: hwinfo libbwdpi.so bwdpi bwdpi_wred_alive rsasign_sig_check check_sig_version

libbwdpi.so: $(OBJS)
	echo " [bwdpi] LD $@"
	$(LD) $(LD2) -shared -o $@ $^
	install -m 755 libbwdpi.so $(TOPDIR)/package/asus_bwdpi_source/src/asus

hwinfo: hwinfo.o
	$(CC) -o $@ $^ $(LD1) -L. -lgcc_s

bwdpi: bwdpi.o
	$(CC) -o $@ $^ $(LD1) -L. -lgcc_s -lbwdpi

bwdpi_wred_alive: bwdpi_wred_alive.o
	$(CC) -o $@ $^ $(LD1) -L. -lgcc_s -lbwdpi

rsasign_sig_check: rsasign_sig_check.o
	$(CC) -o $@ $^ $(LD1) -L. -lgcc_s -lbwdpi

check_sig_version: check_sig_version.o
	$(CC) -o $@ $^ $(LD1) -L. -lgcc_s -lbwdpi

# this command is for debug only
bwdpi_cmd: main.o $(OBJS)
	echo " [bwdpi] CC $@"
	$(CC) -o $@ $^ $(LD1) -L. -lgcc_s
	$(STRIP) bwdpi_cmd

#install: all
#	echo "[bwdpi] Installing..."
#	install -d $(INSTALLDIR)/asus_bwdpi_source/usr/lib
#	install -m 755 libbwdpi.so $(INSTALLDIR)/asus_bwdpi_source/usr/lib
#	$(STRIP) $(INSTALLDIR)/asus_bwdpi_source/usr/lib/libbwdpi.so
#	install -d $(INSTALLDIR)/asus_bwdpi_source/usr/sbin
#	install -m 755 hwinfo $(INSTALLDIR)/asus_bwdpi_source/usr/sbin/hwinfo
#	$(STRIP) $(INSTALLDIR)/asus_bwdpi_source/usr/sbin/hwinfo
#	install -m check_sig_version $(INSTALLDIR)/bin/check_sig_version
#	$(STRIP) $(INSTALLDIR)/asus_bwdpi_source/usr/sbin/check_sig_version

%.o: %.c
	echo " [bwdpi] CC $@"
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.so *.o hwinfo bwdpi_cmd
