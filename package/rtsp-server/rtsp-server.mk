################################################################################
# rtsp-server — mediamtx (prebuilt) + 하드닝 설정
#   SFR:1.1.1 사용자 인증  SFR:1.2.1 RTSPS 암호전송
################################################################################
RTSP_SERVER_VERSION = 1.9.3
RTSP_SERVER_SITE = https://github.com/bluenviron/mediamtx/releases/download/v$(RTSP_SERVER_VERSION)
RTSP_SERVER_SOURCE = mediamtx_v$(RTSP_SERVER_VERSION)_linux_arm64v8.tar.gz
RTSP_SERVER_LICENSE = MIT
RTSP_SERVER_LICENSE_FILES = LICENSE

# prebuilt 바이너리 배포판 → 빌드 단계 없음
define RTSP_SERVER_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/mediamtx $(TARGET_DIR)/usr/bin/mediamtx
	$(INSTALL) -D -m 0600 $(RTSP_SERVER_PKGDIR)/mediamtx.yml $(TARGET_DIR)/etc/mediamtx.yml
	$(INSTALL) -D -m 0755 $(RTSP_SERVER_PKGDIR)/S65rtsp-server $(TARGET_DIR)/etc/init.d/S65rtsp-server
endef

$(eval $(generic-package))
