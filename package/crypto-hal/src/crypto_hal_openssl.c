/*
 * crypto_hal OpenSSL 백엔드 (실구현). 양산 시 KCMVP 검증필 모듈로 교체.
 * ARIA-GCM 1순위, AES-GCM 폴백. nonce 내부 생성으로 고정 IV 재사용 차단.
 */
#include "crypto_hal.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

struct ch_key { uint8_t *buf; size_t len; };  /* 원시 키는 이 안에만 존재 */

static const EVP_CIPHER *aead_cipher(ch_aead_alg a, size_t *keylen) {
	switch (a) {
	case CH_AEAD_ARIA128_GCM: *keylen = 16; return EVP_aria_128_gcm();
	case CH_AEAD_ARIA256_GCM: *keylen = 32; return EVP_aria_256_gcm();
	case CH_AEAD_AES128_GCM:  *keylen = 16; return EVP_aes_128_gcm();
	case CH_AEAD_AES256_GCM:  *keylen = 32; return EVP_aes_256_gcm();
	default: return NULL;
	}
}
static const EVP_MD *hash_md(ch_hash_alg h) {
	switch (h) {
	case CH_HASH_SHA256: return EVP_sha256();
	case CH_HASH_SHA384: return EVP_sha384();
	case CH_HASH_SHA512: return EVP_sha512();
	default: return NULL;
	}
}

/* SFR:9.3.1 키 저장(핸들) */
ch_rc crypto_hal_key_import(const uint8_t *raw, size_t len, ch_key **out) {
	if (!raw || !out || (len != 16 && len != 32)) return CH_EINVAL;
	ch_key *k = calloc(1, sizeof(*k));
	if (!k) return CH_EBACKEND;
	k->buf = malloc(len);
	if (!k->buf) { free(k); return CH_EBACKEND; }
	memcpy(k->buf, raw, len);
	k->len = len;
	*out = k;
	return CH_OK;
}
/* SFR:9.2.1 키 생성(안전 난수 CSPRNG) */
ch_rc crypto_hal_key_generate(size_t bits, ch_key **out) {
	if (bits != 128 && bits != 256) return CH_EINVAL;
	size_t len = bits / 8;
	uint8_t tmp[32];
	if (RAND_bytes(tmp, (int)len) != 1) return CH_EBACKEND;
	ch_rc rc = crypto_hal_key_import(tmp, len, out);
	OPENSSL_cleanse(tmp, sizeof(tmp));
	return rc;
}
/* SFR:9.4.1 키 파기 — 0x00/0xFF/난수 3회 덮어쓰기 후 해제 */
ch_rc crypto_hal_key_destroy(ch_key *k) {
	if (!k) return CH_OK;
	if (k->buf) {
		memset(k->buf, 0x00, k->len);
		memset(k->buf, 0xFF, k->len);
		RAND_bytes(k->buf, (int)k->len);
		OPENSSL_cleanse(k->buf, k->len);
		free(k->buf);
	}
	free(k);
	return CH_OK;
}

ch_rc crypto_hal_aead_seal(ch_aead_alg alg, ch_key *k,
                           uint8_t nonce_out[CH_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct_out, uint8_t tag_out[CH_AEAD_TAG_LEN]) {
	size_t need; const EVP_CIPHER *c = aead_cipher(alg, &need);
	if (!c || !k || !nonce_out || !ct_out || !tag_out) return CH_EINVAL;
	if (k->len != need) return CH_EINVAL;
	if (RAND_bytes(nonce_out, CH_AEAD_NONCE_LEN) != 1) return CH_EBACKEND;  /* 매번 새 nonce */

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return CH_EBACKEND;
	ch_rc rc = CH_EBACKEND; int len;
	if (EVP_EncryptInit_ex(ctx, c, NULL, k->buf, nonce_out) != 1) goto out;
	if (aad && aad_len && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
	if (EVP_EncryptUpdate(ctx, ct_out, &len, pt, (int)pt_len) != 1) goto out;
	if (EVP_EncryptFinal_ex(ctx, ct_out + len, &len) != 1) goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CH_AEAD_TAG_LEN, tag_out) != 1) goto out;
	rc = CH_OK;
out:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

ch_rc crypto_hal_aead_open(ch_aead_alg alg, ch_key *k,
                           const uint8_t nonce[CH_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[CH_AEAD_TAG_LEN],
                           uint8_t *pt_out) {
	size_t need; const EVP_CIPHER *c = aead_cipher(alg, &need);
	if (!c || !k || !nonce || !ct || !tag || !pt_out) return CH_EINVAL;
	if (k->len != need) return CH_EINVAL;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return CH_EBACKEND;
	ch_rc rc = CH_EBACKEND; int len;
	if (EVP_DecryptInit_ex(ctx, c, NULL, k->buf, nonce) != 1) goto out;
	if (aad && aad_len && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
	if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1) goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CH_AEAD_TAG_LEN, (void *)tag) != 1) goto out;
	/* 태그 검증 실패 시 Final 이 0 반환 → 인증 실패(변조 탐지) */
	rc = (EVP_DecryptFinal_ex(ctx, pt_out + len, &len) == 1) ? CH_OK : CH_EAUTH;
out:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

ch_rc crypto_hal_hmac(ch_hash_alg alg, ch_key *k,
                      const uint8_t *msg, size_t len, uint8_t *mac_out, size_t *mac_len) {
	const EVP_MD *md = hash_md(alg);
	if (!md || !k || !mac_out) return CH_EINVAL;
	unsigned int ml = 0;
	if (!HMAC(md, k->buf, (int)k->len, msg, len, mac_out, &ml)) return CH_EBACKEND;
	if (mac_len) *mac_len = ml;
	return CH_OK;
}

/* SFR:9.1.1 초기화 + 자체시험(KAT): ARIA·AES round-trip + 변조 탐지 확인 */
ch_rc crypto_hal_init(void) {
	static const uint8_t kv[32] = {0};           /* KAT 전용 고정 키 */
	static const uint8_t pt[16] = "selftest-vector";
	const ch_aead_alg algs[] = { CH_AEAD_ARIA256_GCM, CH_AEAD_AES256_GCM };
	for (unsigned i = 0; i < 2; i++) {
		ch_key *k; if (crypto_hal_key_import(kv, 32, &k) != CH_OK) return CH_ESELFTEST;
		uint8_t nonce[CH_AEAD_NONCE_LEN], ct[16], tag[CH_AEAD_TAG_LEN], out[16];
		ch_rc rc = crypto_hal_aead_seal(algs[i], k, nonce, NULL, 0, pt, 16, ct, tag);
		if (rc == CH_OK) rc = crypto_hal_aead_open(algs[i], k, nonce, NULL, 0, ct, 16, tag, out);
		int ok = (rc == CH_OK) && (memcmp(pt, out, 16) == 0);
		/* 변조 탐지: 태그 1비트 뒤집으면 CH_EAUTH 여야 함 */
		if (ok) { uint8_t bad[CH_AEAD_TAG_LEN]; memcpy(bad, tag, CH_AEAD_TAG_LEN); bad[0] ^= 1;
			ok = (crypto_hal_aead_open(algs[i], k, nonce, NULL, 0, ct, 16, bad, out) == CH_EAUTH); }
		crypto_hal_key_destroy(k);
		if (!ok) return CH_ESELFTEST;
	}
	return CH_OK;
}
