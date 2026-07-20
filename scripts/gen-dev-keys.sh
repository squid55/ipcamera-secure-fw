#!/bin/sh
# gen-dev-keys.sh — 개발용 서명 키 생성 (실서비스 키 아님)
#   - RAUC 서명 개인키 + 공개 인증서(keyring) : 서명 업데이트 검증(SFR:6.1.1)
#   개인키는 keys/(gitignore)에만, 공개 인증서는 이미지 overlay 로 복사.
set -e

HERE=$(cd "$(dirname "$0")/.." && pwd)
KEYS="$HERE/keys"
RAUC_OVERLAY="$HERE/board/rpi5-secure/rootfs-overlay/etc/rauc"
mkdir -p "$KEYS" "$RAUC_OVERLAY"

if [ ! -f "$KEYS/rauc-dev.key.pem" ]; then
	echo "[RAUC] 개발용 서명 키/인증서 생성 (RSA-4096, 10년)"
	openssl req -x509 -newkey rsa:4096 -nodes \
		-keyout "$KEYS/rauc-dev.key.pem" \
		-out    "$KEYS/rauc-dev.cert.pem" \
		-subj "/CN=ipcamera-secure-fw development" -days 3650 2>/dev/null
	chmod 600 "$KEYS/rauc-dev.key.pem"
else
	echo "[RAUC] 기존 키 재사용: keys/rauc-dev.key.pem"
fi

# 공개 인증서만 이미지에 포함(검증용). 개인키는 keys/ 에만 보관.
cp "$KEYS/rauc-dev.cert.pem" "$RAUC_OVERLAY/keyring.pem"
echo "  → overlay/etc/rauc/keyring.pem (공개 인증서, 이미지 포함)"
echo "  → keys/rauc-dev.key.pem (개인키, 미커밋 — 빌드 서버 보관)"
echo
echo "업데이트 번들 서명 예:"
echo "  rauc bundle --cert=keys/rauc-dev.cert.pem --key=keys/rauc-dev.key.pem <input-dir> update.raucb"
echo
echo "⚠ 이 키는 개발용입니다. 실제 납품 제품은 HSM/안전 저장소의 운영 키로 서명하세요."
