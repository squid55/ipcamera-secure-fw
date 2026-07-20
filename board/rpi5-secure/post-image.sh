#!/bin/sh
# post-image: dm-verity 해시 생성(5.2.1) 후 genimage 로 A/B SD 이미지 조립
set -e
BOARD_DIR="$(dirname "$0")"
GENIMAGE_CFG="$BOARD_DIR/genimage.cfg"
BINARIES_DIR="$1"

# TODO(무결성): rootfs.squashfs 에 대해 veritysetup format 로 해시트리 생성,
#   root hash 를 커널 cmdline(dm-verity)·서명에 반영. 프로토타입 단계 스텁.
# veritysetup format "$BINARIES_DIR/rootfs.squashfs" "$BINARIES_DIR/rootfs.verity" > "$BINARIES_DIR/verity.roothash"

genimage --config "$GENIMAGE_CFG" \
	--inputpath "$BINARIES_DIR" --outputpath "$BINARIES_DIR" \
	--rootpath "$(mktemp -d)"

echo "[post-image] sdcard.img (A/B) 생성 완료"
