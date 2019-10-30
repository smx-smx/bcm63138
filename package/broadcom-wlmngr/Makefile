#
# Copyright (C) 2014 Jingwei Liang <jingwei_liang@sva-arcadyan.com.cn>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=broadcom-wlmngr
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

PKG_FILE_DEPENDS := $(shell grep '^	*$$(CP).*$$(PKG_BUILD_DIR)' $(TOPDIR)/package/$(PKG_NAME)/Makefile | awk '{print $$2}' | sed 's@$$(TOPDIR)@$(TOPDIR)@g')

include $(INCLUDE_DIR)/package.mk

define Package/broadcom-wlmngr
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=Broadcom proprietary wlmngr
  MAINTAINER:=Jingwei Liang <jingwei_liang@sva-arcadyan.com.cn>
  DEPENDS:=@TARGET_brcm63xx +libpthread +nvram +broadcom-wlctl +broadcom-libwlcsm +broadcom-libcms +broadcom-libethswctl +broadcom-libhomeplugctl +broadcom-libnanoxml +broadcom-libpwrctl +atmctl +rdpactl +tmctl +vlanctl +xdslctl +PACKAGE_broadcom-bridgeutil:broadcom-bridgeutil +PACKAGE_broadcom-snoopctl:broadcom-snoopctl
endef

define Package/broadcom-wlmngr/description
 This package contains the proprietary wlmngr application on Broadcom based devices.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
	$(CP) $(TOPDIR)/extern/target-install/bin/wlconf $(PKG_BUILD_DIR)
	$(CP) $(TOPDIR)/extern/target-install/lib/libwlmngr.so $(PKG_BUILD_DIR)
	if [ "$(CONFIG_ARCADYAN_TARGET_telmex_PRV3399B-BH-TE)" = "y" ] ; then \
		$(CP) $(TOPDIR)/extern/target-install/lib/private/libeponctl.so $(PKG_BUILD_DIR); \
		$(CP) $(TOPDIR)/extern/target-install/lib/private/libgponctl.so $(PKG_BUILD_DIR); \
		$(CP) $(TOPDIR)/extern/target-install/lib/private/libgponif.so $(PKG_BUILD_DIR); \
		$(CP) $(TOPDIR)/extern/target-install/lib/private/libomci.so $(PKG_BUILD_DIR); \
		$(CP) $(TOPDIR)/extern/target-install/lib/private/libomcipm_drv.so $(PKG_BUILD_DIR); \
	fi
endef

define Build/InstallDev
endef

define Package/broadcom-wlmngr/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/lib
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlmngr $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlconf $(1)/bin/
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/wlevt  $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libwlmngr.so $(1)/lib/
	if [ "$(CONFIG_ARCADYAN_TARGET_telmex_PRV3399B-BH-TE)" = "y" ] ; then \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/libeponctl.so  $(1)/lib/; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/libgponctl.so  $(1)/lib/; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/libgponif.so  $(1)/lib/; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/libomci.so  $(1)/lib/; \
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/libomcipm_drv.so  $(1)/lib/; \
	fi
endef

$(eval $(call BuildPackage,broadcom-wlmngr))
