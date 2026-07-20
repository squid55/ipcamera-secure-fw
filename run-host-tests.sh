#!/bin/sh
# 플랫폼 독립 보안 로직을 호스트(gcc + libcrypto)에서 빌드·검증한다.
# Buildroot/하드웨어 없이 crypto_hal·auth·audit 로직을 단위 테스트.
# 사용: ./run-host-tests.sh   (libssl-dev 필요)
set -e
cd "$(dirname "$0")"
CH=package/crypto-hal
SD=package/cctv-secd
CFLAGS="-Wall -Wextra -I $CH/include -I $SD/src"
OUT=$(mktemp -d)

echo "== 데몬 전체 컴파일 확인 =="
gcc $CFLAGS $SD/src/main.c $SD/src/auth.c $SD/src/audit.c \
	$CH/src/crypto_hal_openssl.c -lcrypto -o "$OUT/cctv-secd"
echo "  ok: cctv-secd 링크 성공"

echo "== crypto_hal 테스트 =="
gcc $CFLAGS $CH/test/test_crypto.c $CH/src/crypto_hal_openssl.c -lcrypto -o "$OUT/test_crypto"
"$OUT/test_crypto"

echo "== auth + audit 테스트 =="
gcc $CFLAGS $SD/test/test_secd.c $SD/src/auth.c $SD/src/audit.c \
	$CH/src/crypto_hal_openssl.c -lcrypto -o "$OUT/test_secd"
"$OUT/test_secd"

rm -rf "$OUT"
echo "== 전체 호스트 테스트 통과 =="
