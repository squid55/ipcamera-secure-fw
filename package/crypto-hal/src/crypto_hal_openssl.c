/*
 * crypto_hal OpenSSL 백엔드 (실구현). 양산 시 KCMVP 검증필 모듈로 교체.
 * ARIA-GCM 1순위, AES-GCM 폴백. nonce 내부 생성으로 고정 IV 재사용 차단.
 */
#include "crypto_hal.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
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

/* SFR:9.3.1 키 저장(핸들). HMAC 키 등 다양한 길이 허용(AEAD는 seal/open에서 16/32 재검증) */
ch_rc crypto_hal_key_import(const uint8_t *raw, size_t len, ch_key **out) {
	if (!raw || !out || len == 0 || len > 64) return CH_EINVAL;
	ch_key *k = calloc(1, sizeof(*k));
	if (!k) return CH_EBACKEND;
	k->buf = malloc(len);
	if (!k->buf) { free(k); return CH_EBACKEND; }
	memcpy(k->buf, raw, len);
	k->len = len;
	*out = k;
	return CH_OK;
}
/* SFR:9.2.1 안전 난수(CSPRNG). 양산 백엔드에선 KCMVP 검증필 DRBG 로 교체 */
ch_rc crypto_hal_random(uint8_t *out, size_t len) {
	if (!out || len == 0) return CH_EINVAL;
	if (RAND_bytes(out, (int)len) != 1) return CH_EBACKEND;
	return CH_OK;
}
/* SFR:9.2.1 키 생성(안전 난수 CSPRNG). 대칭키는 128/256bit */
ch_rc crypto_hal_key_generate(size_t bits, ch_key **out) {
	if (bits != 128 && bits != 256) return CH_EINVAL;
	size_t len = bits / 8;
	uint8_t tmp[32];
	if (RAND_bytes(tmp, (int)len) != 1) return CH_EBACKEND;
	ch_rc rc = crypto_hal_key_import(tmp, len, out);
	OPENSSL_cleanse(tmp, sizeof(tmp));
	return rc;
}
/* SFR:9.4.1 키 파기 — 0x00/0xFF/난수 3회 덮어쓰기(각 패스 cleanse로 최적화 제거 방지) 후 해제 */
ch_rc crypto_hal_key_destroy(ch_key *k) {
	if (!k) return CH_OK;
	if (k->buf) {
		memset(k->buf, 0x00, k->len); OPENSSL_cleanse(k->buf, k->len);
		memset(k->buf, 0xFF, k->len); OPENSSL_cleanse(k->buf, k->len);
		if (RAND_bytes(k->buf, (int)k->len) != 1) memset(k->buf, 0x5A, k->len);
		OPENSSL_cleanse(k->buf, k->len);
		free(k->buf);
	}
	OPENSSL_cleanse(k, sizeof(*k));
	free(k);
	return CH_OK;
}

/* 내부: 주어진 nonce 로 AEAD 암호화(KAT·seal 공용) */
static ch_rc aead_encrypt(ch_aead_alg alg, ch_key *k, const uint8_t *nonce,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *pt, size_t pt_len,
                          uint8_t *ct_out, uint8_t *tag_out) {
	size_t need; const EVP_CIPHER *c = aead_cipher(alg, &need);
	if (!c || !k || k->len != need) return CH_EINVAL;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return CH_EBACKEND;
	ch_rc rc = CH_EBACKEND; int len;
	if (EVP_EncryptInit_ex(ctx, c, NULL, k->buf, nonce) != 1) goto out;
	if (aad && aad_len && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto out;
	if (EVP_EncryptUpdate(ctx, ct_out, &len, pt, (int)pt_len) != 1) goto out;
	if (EVP_EncryptFinal_ex(ctx, ct_out + len, &len) != 1) goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CH_AEAD_TAG_LEN, tag_out) != 1) goto out;
	rc = CH_OK;
out:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

ch_rc crypto_hal_aead_seal(ch_aead_alg alg, ch_key *k,
                           uint8_t nonce_out[CH_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct_out, uint8_t tag_out[CH_AEAD_TAG_LEN]) {
	if (!nonce_out || !ct_out || !tag_out) return CH_EINVAL;
	if (RAND_bytes(nonce_out, CH_AEAD_NONCE_LEN) != 1) return CH_EBACKEND;  /* 매번 새 nonce */
	return aead_encrypt(alg, k, nonce_out, aad, aad_len, pt, pt_len, ct_out, tag_out);
}

ch_rc crypto_hal_aead_open(ch_aead_alg alg, ch_key *k,
                           const uint8_t nonce[CH_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[CH_AEAD_TAG_LEN],
                           uint8_t *pt_out) {
	size_t need; const EVP_CIPHER *c = aead_cipher(alg, &need);
	if (!c || !k || !nonce || !ct || !tag || !pt_out || k->len != need) return CH_EINVAL;

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
	/* 인증 실패/오류 시 미인증 평문을 즉시 제로화(RUP 방지) */
	if (rc != CH_OK) OPENSSL_cleanse(pt_out, ct_len);
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

/* ── 자체시험 (SFR:9.1.1): 표준/실측 시험벡터 기반 KAT ── */
static const uint8_t KAT_KEY32[32] = {0};
static const uint8_t KAT_NONCE[12] = {0};
static const uint8_t KAT_PT16[16]  = {0};
/* AES-256-GCM (K=0^256, IV=0^96, PT=0^128) — NIST 벡터 */
static const uint8_t KAT_AES_CT[16]  = {0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18};
static const uint8_t KAT_AES_TAG[16] = {0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19};
/* ARIA-256-GCM (동일 입력) — 실측 벡터 */
static const uint8_t KAT_ARIA_CT[16]  = {0x28,0x20,0xd0,0x7c,0x95,0x3b,0x76,0x78,0x49,0x45,0x88,0x23,0x3b,0x38,0xad,0xcc};
static const uint8_t KAT_ARIA_TAG[16] = {0x30,0xaa,0xbf,0x0a,0x98,0xc6,0x73,0x6a,0xd0,0xd4,0xf2,0x29,0x30,0x1c,0x96,0x29};
/* HMAC-SHA256 RFC4231 TC1: key=0x0b*20, msg="Hi There" */
static const uint8_t KAT_HMAC_KEY[20] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
static const uint8_t KAT_HMAC_MAC[32] = {0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7};

static int aead_kat(ch_aead_alg alg, const uint8_t *exp_ct, const uint8_t *exp_tag) {
	ch_key *k; if (crypto_hal_key_import(KAT_KEY32, 32, &k) != CH_OK) return -1;
	uint8_t ct[16], tag[16], out[16];
	int ok = (aead_encrypt(alg, k, KAT_NONCE, NULL, 0, KAT_PT16, 16, ct, tag) == CH_OK)
	         && memcmp(ct, exp_ct, 16) == 0 && memcmp(tag, exp_tag, 16) == 0;
	/* open 왕복 + 변조 탐지 */
	if (ok) ok = (crypto_hal_aead_open(alg, k, KAT_NONCE, NULL, 0, ct, 16, tag, out) == CH_OK)
	             && memcmp(out, KAT_PT16, 16) == 0;
	if (ok) { uint8_t bad[16]; memcpy(bad, tag, 16); bad[0] ^= 1;
		ok = (crypto_hal_aead_open(alg, k, KAT_NONCE, NULL, 0, ct, 16, bad, out) == CH_EAUTH); }
	crypto_hal_key_destroy(k);
	return ok ? 0 : -1;
}

ch_rc crypto_hal_init(void) {
	/* AEAD KAT: ARIA-256-GCM, AES-256-GCM */
	if (aead_kat(CH_AEAD_ARIA256_GCM, KAT_ARIA_CT, KAT_ARIA_TAG) != 0) return CH_ESELFTEST;
	if (aead_kat(CH_AEAD_AES256_GCM,  KAT_AES_CT,  KAT_AES_TAG)  != 0) return CH_ESELFTEST;
	/* HMAC-SHA256 KAT (RFC4231 TC1) — auth/audit/무결성 근간 */
	ch_key *hk; if (crypto_hal_key_import(KAT_HMAC_KEY, 20, &hk) != CH_OK) return CH_ESELFTEST;
	uint8_t mac[64]; size_t ml = 0;
	int hok = (crypto_hal_hmac(CH_HASH_SHA256, hk, (const uint8_t *)"Hi There", 8, mac, &ml) == CH_OK)
	          && ml == 32 && memcmp(mac, KAT_HMAC_MAC, 32) == 0;
	crypto_hal_key_destroy(hk);
	return hok ? CH_OK : CH_ESELFTEST;
}
