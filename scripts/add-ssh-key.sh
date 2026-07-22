#!/bin/sh
# add-ssh-key.sh — admin 계정 authorized_keys 에 SSH 공개키 주입(빌드 전 실행)
# 사용: ./scripts/add-ssh-key.sh ~/.ssh/id_ed25519.pub
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
KEY="${1:-$HOME/.ssh/id_ed25519.pub}"
[ -f "$KEY" ] || { echo "공개키 파일 없음: $KEY"; exit 1; }
DEST="$HERE/board/rpi5-secure/rootfs-overlay/home/admin/.ssh"
mkdir -p "$DEST"
cat "$KEY" > "$DEST/authorized_keys"
chmod 644 "$DEST/authorized_keys"
echo "admin authorized_keys 설치: $KEY"
echo "→ users.txt(admin 사용자)와 함께 빌드되면 'ssh admin@<ip>' 로 접속 가능"
