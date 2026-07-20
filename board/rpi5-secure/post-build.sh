#!/bin/sh
# post-build: rootfs 하드닝 마감 (읽기전용 이미지에 굽기 전 최종 조정)
set -e
TARGET="$1"

# 10.3.1 불필요 서비스 제거 / 미기재 접속경로 차단
rm -f  "$TARGET"/etc/init.d/S*telnet* 2>/dev/null || true
rm -f  "$TARGET"/etc/init.d/S*ftp*    2>/dev/null || true
rm -f  "$TARGET"/usr/sbin/telnetd "$TARGET"/usr/bin/telnet 2>/dev/null || true

# root 직접 로그인 차단 (SSH 키기반 admin 만)
sed -i 's/^root:[^:]*:/root:!:/' "$TARGET/etc/shadow" 2>/dev/null || true

# 3.4.2 최초 부팅 강제 PW 변경 플래그 (firstboot 프로비저닝 트리거)
touch "$TARGET/etc/.factory-state"

echo "[post-build] hardening applied"
