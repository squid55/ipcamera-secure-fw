# 모든 커스텀 패키지 .mk 자동 포함
include $(sort $(wildcard $(BR2_EXTERNAL_IPCAMERA_SECURE_PATH)/package/*/*.mk))
