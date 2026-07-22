/*
 * crypto_hal.h — 암호 추상화 계층 (프로토타입 OpenSSL ↔ 양산 KCMVP 백엔드 교체)
 * 화이트리스트만 노출 → 금지 알고리즘(ECB·TDES·MD5·SHA-1·고정IV)은 API에 아예 없음.
 * AEAD는 nonce를 내부 생성/출력해 고정 IV 재사용을 원천 차단한다.
 */
#ifndef CRYPTO_HAL_H
#define CRYPTO_HAL_H
#include <stdint.h>
#include <stddef.h>

typedef enum { CH_OK = 0, CH_EINVAL, CH_EALG_FORBIDDEN, CH_EBACKEND,
               CH_ESELFTEST, CH_EAUTH } ch_rc;

#define CH_AEAD_NONCE_LEN 12   /* GCM 96-bit nonce */
#define CH_AEAD_TAG_LEN   16   /* GCM 128-bit tag  */

/* SFR:9.1.1 권고 알고리즘(112bit+). 국산 ARIA 1순위, AES 폴백 */
typedef enum { CH_AEAD_ARIA128_GCM, CH_AEAD_ARIA256_GCM,
               CH_AEAD_AES128_GCM,  CH_AEAD_AES256_GCM } ch_aead_alg;
typedef enum { CH_HASH_SHA256, CH_HASH_SHA384, CH_HASH_SHA512 } ch_hash_alg;

typedef struct ch_key ch_key;   /* 불투명 키 핸들 — 원시 바이트 미노출(SFR:9.3.1) */

/* 초기화 + 백엔드 자체시험(KAT). 실패 시 CH_ESELFTEST */
ch_rc crypto_hal_init(void);

/* SFR:9.2.1 안전 난수(CSPRNG/DRBG). salt·임시 PW·nonce 생성용. 프로토타입=OpenSSL RAND, 양산=KCMVP DRBG */
ch_rc crypto_hal_random(uint8_t *out, size_t len);

/* SFR:9.2.1 키 생성(안전 난수)  SFR:9.3.1 저장(핸들)  SFR:9.4.1 파기(덮어쓰기) */
ch_rc crypto_hal_key_generate(size_t bits, ch_key **out);
ch_rc crypto_hal_key_import(const uint8_t *raw, size_t len, ch_key **out);
ch_rc crypto_hal_key_destroy(ch_key *k);

/* SFR:4.2.1 저장 암호화 / SFR:1.2.1·4.1.1 전송 보호. nonce는 seal이 생성·출력 */
ch_rc crypto_hal_aead_seal(ch_aead_alg alg, ch_key *k,
                           uint8_t nonce_out[CH_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct_out, uint8_t tag_out[CH_AEAD_TAG_LEN]);
ch_rc crypto_hal_aead_open(ch_aead_alg alg, ch_key *k,
                           const uint8_t nonce[CH_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[CH_AEAD_TAG_LEN],
                           uint8_t *pt_out);

/* HMAC (설정 무결성 검증 등, SFR:5.2.1). mac_out 은 최소 64바이트 버퍼 */
ch_rc crypto_hal_hmac(ch_hash_alg alg, ch_key *k,
                      const uint8_t *msg, size_t len, uint8_t *mac_out, size_t *mac_len);

#endif
