/* crypto_hal 호스트 테스트 — gcc + libcrypto 로 빌드해 로직 검증
 * 빌드: gcc -I../include test_crypto.c ../src/crypto_hal_openssl.c -lcrypto -o test_crypto */
#include "crypto_hal.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("  FAIL: %s\n", msg); fails++; } else printf("  ok: %s\n", msg); } while (0)

int main(void) {
	printf("[1] 백엔드 자체시험(KAT)\n");
	CHECK(crypto_hal_init() == CH_OK, "crypto_hal_init KAT 통과");

	printf("[2] AEAD 라운드트립 (ARIA-256-GCM)\n");
	ch_key *k;
	CHECK(crypto_hal_key_generate(256, &k) == CH_OK, "키 생성(256)");
	const uint8_t pt[] = "감사로그와 설정값을 보호하는 평문";
	const uint8_t aad[] = "context-v1";
	uint8_t nonce[CH_AEAD_NONCE_LEN], ct[64], tag[CH_AEAD_TAG_LEN], out[64];
	size_t n = sizeof(pt);
	ch_rc rc = crypto_hal_aead_seal(CH_AEAD_ARIA256_GCM, k, nonce, aad, sizeof(aad), pt, n, ct, tag);
	CHECK(rc == CH_OK, "seal");
	memset(out, 0, sizeof(out));
	rc = crypto_hal_aead_open(CH_AEAD_ARIA256_GCM, k, nonce, aad, sizeof(aad), ct, n, tag, out);
	CHECK(rc == CH_OK && memcmp(pt, out, n) == 0, "open → 평문 복원");

	printf("[3] 변조 탐지 (태그/AAD 위조 시 CH_EAUTH)\n");
	uint8_t badtag[CH_AEAD_TAG_LEN]; memcpy(badtag, tag, CH_AEAD_TAG_LEN); badtag[0] ^= 0x80;
	CHECK(crypto_hal_aead_open(CH_AEAD_ARIA256_GCM, k, nonce, aad, sizeof(aad), ct, n, badtag, out) == CH_EAUTH,
	      "변조된 태그 거부");
	CHECK(crypto_hal_aead_open(CH_AEAD_ARIA256_GCM, k, nonce, (const uint8_t*)"other", 5, ct, n, tag, out) == CH_EAUTH,
	      "잘못된 AAD 거부");

	printf("[4] nonce 유일성 (동일 평문 2회 seal → nonce·ct 다름, 고정 IV 재사용 없음)\n");
	uint8_t n1[CH_AEAD_NONCE_LEN], n2[CH_AEAD_NONCE_LEN], c1[64], c2[64], t1[16], t2[16];
	crypto_hal_aead_seal(CH_AEAD_ARIA256_GCM, k, n1, NULL, 0, pt, n, c1, t1);
	crypto_hal_aead_seal(CH_AEAD_ARIA256_GCM, k, n2, NULL, 0, pt, n, c2, t2);
	CHECK(memcmp(n1, n2, CH_AEAD_NONCE_LEN) != 0, "nonce 매번 다름");
	CHECK(memcmp(c1, c2, n) != 0, "동일 평문이라도 암호문 다름");

	printf("[5] HMAC-SHA256 (설정 무결성)\n");
	uint8_t mac[64]; size_t ml = 0;
	CHECK(crypto_hal_hmac(CH_HASH_SHA256, k, pt, n, mac, &ml) == CH_OK && ml == 32, "HMAC-SHA256 길이 32");

	printf("[6] 키 파기\n");
	CHECK(crypto_hal_key_destroy(k) == CH_OK, "key_destroy");

	printf("\n%s (실패 %d)\n", fails ? "❌ 테스트 실패" : "✅ 전체 통과", fails);
	return fails ? 1 : 0;
}
