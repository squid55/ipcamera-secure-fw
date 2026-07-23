################################################################################
# cctv-secd — 보안 데몬 (PoC)
################################################################################
CCTV_SECD_VERSION = 0.1.0
CCTV_SECD_SITE = $(BR2_EXTERNAL_IPCAMERA_SECURE_PATH)/package/cctv-secd/src
CCTV_SECD_SITE_METHOD = local
CCTV_SECD_DEPENDENCIES = openssl crypto-hal
CCTV_SECD_LICENSE = MIT

define CCTV_SECD_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall -o $(@D)/cctv-secd \
		$(@D)/main.c $(@D)/auth.c $(@D)/audit.c \
		$(@D)/session.c $(@D)/mgmt.c $(@D)/config_store.c $(@D)/provision.c $(@D)/selftest.c $(@D)/logsink.c \
		$(TARGET_LDFLAGS) -lcrypto_hal -lssl -lcrypto
endef

define CCTV_SECD_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/cctv-secd $(TARGET_DIR)/usr/sbin/cctv-secd
	$(INSTALL) -D -m 0755 $(CCTV_SECD_PKGDIR)/S60cctv-secd $(TARGET_DIR)/etc/init.d/S60cctv-secd
endef

$(eval $(generic-package))
