#include ../common.mak
-include $(TOP_DIR)/.config

all: tm_build_src asus_build asus_sql_build

tm_build_src:
	cd src/tdts_shell/ && $(MAKE)
	if test -e ./src/tdts_shell/tdts.ko; \
	then echo "Compile tdts_shell success"; \
	else echo "Compile tdts_shell error!"; exit 1; \
	fi
	cd src/tdts_udb_sample/ && $(MAKE)
	if test -e ./src/tdts_udb_sample/sample.bin; \
	then echo "Compile tdts_udb_sample success"; \
	else echo "Compile tdts_udb_sample error!"; exit 1; \
	fi
	cd src/tdts_udb_shell/ && $(MAKE)
	if test -e ./src/tdts_udb_shell/tdts_udb.ko; \
	then echo "Compile tdts_udb_shell success"; \
	else echo "Compile tdts_udb_shell error!"; exit 1; \
	fi
	cd src/tdts_udbfw/ && $(MAKE)
	if test -e ./src/tdts_udbfw/tdts_udbfw.ko; \
	then echo "Compile tdts_udbfw success"; \
	else echo "Compile tdts_udbfw error!"; exit 1; \
	fi

asus_build:
	cd asus/ && $(MAKE)

asus_sql_build:
	cd asus_sql/ && $(MAKE)

#install:
#	# asus function here
#	cd asus/ && $(MAKE) install
#	cd asus_sql/ && $(MAKE) install
#	# [INSTALL] PREPARE asus_bwdpi_source/RC_INDEP/
#	rm -rf RC_INDEP
#	mkdir RC_INDEP
#	tar -xf bin/dcd.tar -C RC_INDEP/.
#	tar -xf bin/shn_ctrl.tar -C RC_INDEP/.
#	tar -xf bin/tdts_wred.tar -C RC_INDEP/.
#	cp -f bin/libshn_*.so RC_INDEP
#	cp -f bin/rule.trf RC_INDEP
#	cp -f bin/tdts_rule_agent RC_INDEP
#	cp -f bin/tcd RC_INDEP
#	rm -f RC_INDEP/*.sh
#	rm -f RC_INDEP/*.conf
#	cp -f modules/* RC_INDEP/
#ifeq ($(HND_ROUTER),y)
#	echo "start to install asus_bwdpi_source into 94908HND"
#	install -d $(INSTALLDIR)/usr/bwdpi/
#	cp -f $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/*.so $(INSTALLDIR)/usr/lib/
#	cp -f $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/*.ko $(INSTALLDIR)/usr/bwdpi/
#	cp -f $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/*.trf $(INSTALLDIR)/usr/bwdpi/
#	cp -f $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/*.cert $(INSTALLDIR)/usr/bwdpi/
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/wred $(INSTALLDIR)/usr/sbin/wred
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/wred_set_conf $(INSTALLDIR)/usr/sbin/wred_set_conf
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/wred_set_wbl $(INSTALLDIR)/usr/sbin/wred_set_wbl
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/dcd $(INSTALLDIR)/usr/sbin/dcd
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/tcd $(INSTALLDIR)/usr/sbin/tcd
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/shn_ctrl $(INSTALLDIR)/usr/sbin/shn_ctrl
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/tdts_rule_agent $(INSTALLDIR)/usr/sbin/tdts_rule_agent
#	install -D $(TOPDIR)/package/asus_bwdpi_source/src/RC_INDEP/sample.bin $(INSTALLDIR)/usr/sbin/sample.bin
#endif

clean:
	# asus function here
	cd asus && $(MAKE) clean
	cd asus_sql && $(MAKE) clean
	$(CC) -C ./src/tdts_shell clean
	$(CC) -C ./src/tdts_udbfw clean
	$(CC) -C ./src/tdts_udb_shell clean
	$(CC) -C ./src/tdts_udb_sample clean
	rm -rf $(1)/usr/bin/bwdpi
	rm -rf $(1)/usr/bwdpi
	rm -f $(1)/usr/lib/libshn_*
