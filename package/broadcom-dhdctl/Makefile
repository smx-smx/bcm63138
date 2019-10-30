#
# Copyright (C) 2014 Jingwei Liang <jingwei_liang@sva-arcadyan.com.cn>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=broadcom-dhdctl
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

PKG_FILE_DEPENDS := $(shell grep '^	*$$(CP).*$$(PKG_BUILD_DIR)' $(TOPDIR)/package/$(PKG_NAME)/Makefile | awk '{print $$2}' | sed 's@$$(TOPDIR)@$(TOPDIR)@g')

include $(INCLUDE_DIR)/package.mk

define Package/broadcom-dhdctl
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=Broadcom proprietary dhdctl
  MAINTAINER:=Jingwei Liang <jingwei_liang@sva-arcadyan.com.cn>
  DEPENDS:=@TARGET_brcm63xx
endef

define Package/broadcom-dhdctl/description
 This package contains the proprietary dhdctl application on Broadcom based devices.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
	$(CP) $(TOPDIR)/extern/target-install/bin/dhdctl $(PKG_BUILD_DIR)

endef

define Build/InstallDev
endef

define Package/broadcom-dhdctl/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dhdctl $(1)/bin/
	ln -sf dhdctl $(1)/bin/dhd
endef

$(eval $(call BuildPackage,broadcom-dhdctl))
