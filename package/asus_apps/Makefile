# 
# Copyright (C) 2011 Arcadyan
#
#

include $(TOPDIR)/rules.mk

PKG_NAME:=asus-apps
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
	TITLE:=Asus apps install layers.
	URL:=http://www.arcadyan.com/
	DEPENDS:=libarcgpl
endef

define Package/$(PKG_NAME)/description
	Middle layer for nvram.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./files $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

#### Target Rules ###############################
define Build/Compile
	if [ "$(CLANG_ANALYZE)" = "yes" ] ; then \
		mkdir -p $(SCAN_REPORT_DIR)/$(PKG_NAME); \
		$(CLANG_BUILD) -o $(SCAN_REPORT_DIR)/$(PKG_NAME) $(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(CLANG_CC)" CCC_CC="$(TARGET_CC)"	\
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		TOP_DIR="$(TOPDIR)"; \
	else \
		$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		TOP_DIR="$(TOPDIR)"; \
	fi
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libasusnvram.so $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/asus_nvram.h $(1)/usr/include
endef
	
define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/apps_script/arc_app_restart $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nvram $(1)/sbin
	$(INSTALL_DIR) $(1)/usr/bin
	ln -s /sbin/nvram $(1)/usr/bin/nvram 
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rc $(1)/sbin
	ln -s /sbin/rc $(1)/sbin/get_apps_name
	ln -s /sbin/rc $(1)/sbin/chk_app_state
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/apps_script/*.sh $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/rom
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/apps_script/asusrouter $(1)/rom/.asusrouter
	$(CP) $(PKG_BUILD_DIR)/files/ipks/* $(1)/rom
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libasusnvram.so $(1)/usr/lib
endef

define Build/$(PKG_NAME)/clean
	@- [ -e $(PKG_BUILD_DIR)/src/Makefile ] && $(MAKE) -C $(PKG_BUILD_DIR)/src clean
	$(call Build/Clean/Default)
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
