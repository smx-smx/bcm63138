include $(TOPDIR)/rules.mk

PKG_NAME:=asus-webhistory
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
	TITLE:=A web history with USB auto-backup tool.
	DEPENDS:=+libarcgpl +asus-apps +libdisk
endef

define Package/$(PKG_NAME)/description
	Web History with save to USB disk feature.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libwebhistory.so $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/webhistory.h $(1)/usr/include
endef
	
define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/webhistory $(1)/sbin
	$(INSTALL_DIR) $(1)/usr/bin
	ln -s /sbin/webhistory $(1)/usr/bin/webhistory 
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libwebhistory.so $(1)/usr/lib
endef

define Build/$(PKG_NAME)/clean
	@- [ -e $(PKG_BUILD_DIR)/src/Makefile ] && $(MAKE) -C $(PKG_BUILD_DIR)/src clean
	$(call Build/Clean/Default)
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
