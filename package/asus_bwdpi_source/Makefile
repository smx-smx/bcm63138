include $(TOPDIR)/rules.mk

PKG_NAME:=asus-bwdpi
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

MKDIR:=mkdir -p
RM:=rm -rf

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SUBMENU:=Utilities
	SECTION:=utils
	CATEGORY:=Arcadyan
	TITLE:=Support DPI engine based function.
	DEPENDS:=+libarcgpl +asus-apps +libdisk +libsqlite3 +libpthread +libopenssl +librt
endef

define Package/$(PKG_NAME)/description
	Support DPI engine based function.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./files $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/libbwdpi.so $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus_sql/libbwdpi_sql.so $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/include
endef
	
define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/hwinfo $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/bwdpi $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/check_sig_version $(1)/sbin
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/bwdpi_check $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/bwdpi_wred_alive $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/rsasign_sig_check $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus_sql/bwdpi_sqlite $(1)/sbin
	$(INSTALL_DIR) $(1)/usr/bin
	ln -s /sbin/hwinfo $(1)/usr/bin/hwinfo
	ln -s /sbin/bwdpi $(1)/usr/bin/bwdpi
	ln -s /sbin/check_sig_version $(1)/usr/bin/check_sig_version
	#ln -s /sbin/bwdpi_check $(1)/usr/bin/bwdpi_check
	ln -s /sbin/bwdpi_wred_alive $(1)/usr/bin/bwdpi_wred_alive
	ln -s /sbin/rsasign_sig_check $(1)/usr/bin/rsasign_sig_check
	ln -s /sbin/bwdpi_sqlite $(1)/usr/bin/bwdpi_sqlite
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/bwdpi_script/* $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus/libbwdpi.so $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/asus_sql/libbwdpi_sql.so $(1)/usr/lib
	#router/bwdpi_script/Makefile
	# [INSTALL] PREPARE asus_bwdpi_source/RC_INDEP/
	rm -rf $(PKG_BUILD_DIR)/RC_INDEP
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/RC_INDEP
	tar -xf $(PKG_BUILD_DIR)/bin/dcd.tar -C $(PKG_BUILD_DIR)/RC_INDEP/.
	tar -xf $(PKG_BUILD_DIR)/bin/shn_ctrl.tar -C $(PKG_BUILD_DIR)/RC_INDEP/.
	tar -xf $(PKG_BUILD_DIR)/bin/tdts_wred.tar -C $(PKG_BUILD_DIR)/RC_INDEP/.
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/tdts_udb_sample/sample.bin $(PKG_BUILD_DIR)/RC_INDEP
	$(CP) $(PKG_BUILD_DIR)/bin/libshn_*.so $(PKG_BUILD_DIR)/RC_INDEP
	$(CP) $(PKG_BUILD_DIR)/bin/rule.trf $(PKG_BUILD_DIR)/RC_INDEP
	$(CP) $(PKG_BUILD_DIR)/bin/tdts_rule_agent $(PKG_BUILD_DIR)/RC_INDEP
	$(CP) $(PKG_BUILD_DIR)/bin/tcd $(PKG_BUILD_DIR)/RC_INDEP
	rm -f $(PKG_BUILD_DIR)/RC_INDEP/*.sh
	rm -f $(PKG_BUILD_DIR)/RC_INDEP/*.conf
	#install kernel module
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/tdts_shell/tdts.ko $(PKG_BUILD_DIR)/modules/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/tdts_udbfw/tdts_udbfw.ko $(PKG_BUILD_DIR)/modules/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/tdts_udb_shell/tdts_udb.ko $(PKG_BUILD_DIR)/modules/
	$(CP) $(PKG_BUILD_DIR)/modules/* $(PKG_BUILD_DIR)/RC_INDEP/
	#router/Makefile
	$(INSTALL_DIR) $(1)/usr/bwdpi
	$(CP) $(PKG_BUILD_DIR)/RC_INDEP/*.so $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/RC_INDEP/*.ko $(1)/usr/bwdpi/
	$(CP) $(PKG_BUILD_DIR)/RC_INDEP/*.trf $(1)/usr/bwdpi/
	$(CP) $(PKG_BUILD_DIR)/RC_INDEP/*.cert $(1)/usr/bwdpi/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/RC_INDEP/wred $(1)/usr/sbin/wred
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/RC_INDEP/wred_set_conf $(1)/usr/sbin/wred_set_conf
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/RC_INDEP/wred_set_wbl $(1)/usr/sbin/wred_set_wbl
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/RC_INDEP/dcd $(1)/usr/sbin/dcd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/RC_INDEP/tcd $(1)/usr/sbin/tcd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/RC_INDEP/shn_ctrl $(1)/usr/sbin/shn_ctrl
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/RC_INDEP/tdts_rule_agent $(1)/usr/sbin/tdts_rule_agent
	#$(INSTALL_BIN) $(STAGING_DIR)/root-brcm63xx/lib/librt.so.0 $(1)/lib/librt.so.0
endef

define Build/$(PKG_NAME)/clean
	@- [ -e $(PKG_BUILD_DIR)/src/Makefile ] && $(MAKE) -C $(PKG_BUILD_DIR)/src clean
	$(call Build/Clean/Default)
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
