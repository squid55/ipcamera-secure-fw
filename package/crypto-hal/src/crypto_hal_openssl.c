/* crypto_hal OpenSSL 백엔드 (프로토타입 스텁). 양산 시 KCMVP 백엔드로 교체. */
#include "crypto_hal.h"

/* SFR:9.1.1 초기화 + 백엔드 자체시험(KAT) */
ch_rc crypto_hal_init(void) { /* TODO: OpenSSL 초기화 + ARIA/AES-GCM KAT */ return CH_OK; }

ch_rc crypto_hal_aead_seal(ch_aead_alg a, ch_key *k, const uint8_t *aad, size_t al,
                           const uint8_t *pt, size_t pl, uint8_t *ct, uint8_t *tag) {
	(void)a;(void)k;(void)aad;(void)al;(void)pt;(void)pl;(void)ct;(void)tag; /* TODO */ return CH_OK;
}
ch_rc crypto_hal_hmac(ch_hash_alg h, ch_key *k, const uint8_t *m, size_t l, uint8_t *mac) {
	(void)h;(void)k;(void)m;(void)l;(void)mac; /* TODO */ return CH_OK;
}
ch_rc crypto_hal_key_generate(size_t bits, ch_key **out) { (void)bits;(void)out; /* TODO DRBG */ return CH_OK; }
ch_rc crypto_hal_key_destroy(ch_key *k) { (void)k; /* TODO 3회 덮어쓰기 */ return CH_OK; }
