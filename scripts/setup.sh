#!/bin/sh
# setup.sh — Buildroot 체크아웃(고정) + raspberrypi5_defconfig + 우리 보안 fragment 병합
# 사용: ./scripts/setup.sh   그다음:  make -C buildroot BR2_EXTERNAL=$PWD
set -e

HERE=$(cd "$(dirname "$0")/.." && pwd)   # 저장소 루트
BR_TAG="${BR_TAG:-2025.02}"              # 재현성 위해 LTS 태그 고정
BR_DIR="${BR_DIR:-$HERE/buildroot}"
FRAGMENT="$HERE/configs/ipcamera_secure.fragment"

echo "[1/4] Buildroot 체크아웃 ($BR_TAG)"
if [ ! -d "$BR_DIR/.git" ]; then
	git clone https://gitlab.com/buildroot.org/buildroot.git "$BR_DIR"
fi
git -C "$BR_DIR" fetch --tags --quiet
git -C "$BR_DIR" checkout --quiet "$BR_TAG"

echo "[2/4] 베이스 defconfig 로드 (raspberrypi5_defconfig)"
make -C "$BR_DIR" BR2_EXTERNAL="$HERE" raspberrypi5_defconfig >/dev/null

echo "[3/4] 보안 fragment 병합"
# .config 뒤에 우리 옵션을 덧붙이고 olddefconfig 로 의존성 해소(후행 값이 우선).
cat "$FRAGMENT" >> "$BR_DIR/.config"
make -C "$BR_DIR" BR2_EXTERNAL="$HERE" olddefconfig >/dev/null

echo "[4/4] RAUC 개발 키 확인"
if [ ! -f "$HERE/keys/rauc-dev.cert.pem" ]; then
	echo "  키 없음 → ./scripts/gen-dev-keys.sh 를 먼저 실행하세요(서명 업데이트 사용 시)."
fi

echo
echo "완료. 이제 빌드:"
echo "  make -C \"$BR_DIR\" BR2_EXTERNAL=\"$HERE\""
echo "산출물: $BR_DIR/output/images/  (rootfs.squashfs 등)"
echo "A/B sdcard.img 조립은 BUILD.md 참고(옵트인)."
