#!/bin/sh
# post-image: (옵트인) dm-verity 해시 생성 후 genimage 로 A/B SD 이미지 조립.
#   fragment 에서 BR2_ROOTFS_POST_IMAGE_SCRIPT 로 지정 시 실행됨.
#   ⚠ RPi5 부트 레이아웃(부트로더/DTB)·roothash cmdline 주입은 BUILD.md 참고해 맞출 것.
set -e
BOARD_DIR="$(dirname "$0")"
GENIMAGE_CFG="$BOARD_DIR/genimage.cfg"
BINARIES_DIR="${1:-$BINARIES_DIR}"
: "${BINARIES_DIR:?BINARIES_DIR 미설정}"

SQUASHFS="$BINARIES_DIR/rootfs.squashfs"

# SFR:5.2.1 dm-verity: rootfs 무결성 해시트리 생성 + root hash 추출
if command -v veritysetup >/dev/null 2>&1 && [ -f "$SQUASHFS" ]; then
	echo "[post-image] dm-verity 해시 생성"
	veritysetup format "$SQUASHFS" "$BINARIES_DIR/rootfs.verity" | tee "$BINARIES_DIR/verity.log"
	awk '/Root hash:/ { print $3 }' "$BINARIES_DIR/verity.log" > "$BINARIES_DIR/verity.roothash"
	echo "[post-image] root hash → verity.roothash"
	# TODO(하드웨어): verity.roothash 를 cmdline.txt 의 dm-mod.create=... 또는
	#   U-Boot 부트스크립트에 주입해 커널이 verify 하도록 연결(온보드 검증 필요).
else
	echo "[post-image] veritysetup 없음/squashfs 없음 → dm-verity 건너뜀"
fi

# genimage 로 파티션 이미지(sdcard.img) 조립
GTMP="$(mktemp -d)"
genimage \
	--config "$GENIMAGE_CFG" \
	--inputpath "$BINARIES_DIR" \
	--outputpath "$BINARIES_DIR" \
	--rootpath "$GTMP" \
	--tmppath "$GTMP/tmp"
rm -rf "$GTMP"

echo "[post-image] $BINARIES_DIR/sdcard.img (A/B) 생성 완료"
