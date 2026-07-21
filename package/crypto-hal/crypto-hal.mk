################################################################################
# crypto-hal — 암호 추상화 계층 (헤더 + OpenSSL 백엔드 스텁)
################################################################################
CRYPTO_HAL_VERSION = 0.1.0
CRYPTO_HAL_SITE = $(BR2_EXTERNAL_IPCAMERA_SECURE_PATH)/package/crypto-hal/src
CRYPTO_HAL_SITE_METHOD = local
CRYPTO_HAL_DEPENDENCIES = openssl
CRYPTO_HAL_INSTALL_STAGING = YES
CRYPTO_HAL_LICENSE = MIT

define CRYPTO_HAL_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) -I$(CRYPTO_HAL_PKGDIR)/include -fPIC -shared \
		-o $(@D)/libcrypto_hal.so $(@D)/crypto_hal_openssl.c -lcrypto
endef

define CRYPTO_HAL_INSTALL_STAGING_CMDS
	$(INSTALL) -D -m 0644 $(CRYPTO_HAL_PKGDIR)/include/crypto_hal.h $(STAGING_DIR)/usr/include/crypto_hal.h
	$(INSTALL) -D -m 0755 $(@D)/libcrypto_hal.so $(STAGING_DIR)/usr/lib/libcrypto_hal.so
endef

define CRYPTO_HAL_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/libcrypto_hal.so $(TARGET_DIR)/usr/lib/libcrypto_hal.so
endef

$(eval $(generic-package))
