#-include $(TOPDIR)/.config
#DEPENDS:=+libarcgpl +asus-apps +libdisk +libsqlite3
$(warning allen_waring.arc--..LDFLAGS:$(LDFLAGS))
OBJ = arc_bwdpideamon

 
CFLAGS += -I. -I$(TOPDIR)/package/arcadyan-utility/httpd/src -I$(TOPDIR)/package/libdisk/src -I$(TOPDIR)/package/asus_apps/src -I$(TOPDIR)/package/asus_bwdpi_source/src/asus_include
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/src/tdts_udb_sample
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/src/tdts_udb_sample/linux
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/include
CFLAGS += -I$(TOPDIR)/package/asus_bwdpi_source/src/asus_include

LDFLAGS +=  -L$(TOPDIR)/package/asus_bwdpi_source/src/asus  -lasusnvram -larcgpl -ldisk -lbwdpi


ARCFW_SRC = arc_bwdpi.c

all: $(OBJ)

arc_bwdpideamon: $(ARCFW_SRC)
	$(CC)  $(CFLAGS) $(LDFLAGS) $< -o $@

#install:
#	$(INSTALL_DIR) $(CONFIG_PREFIX)/sbin
#	$(INSTALL_BIN) ./arc_bwdpidaemon $(CONFIG_PREFIX)/sbin/arc_bwdpidaemon
#	$(INSTALL_BIN) ./arc_bwdpi.sh $(CONFIG_PREFIX)/sbin/arc_bwdpi

clean:
	rm -rf *.o $(OBJ)

.PHONY : all clean
