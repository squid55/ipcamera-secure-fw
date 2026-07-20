/*
 * crypto_hal.h — 암호 추상화 계층 (프로토타입 OpenSSL ↔ 양산 KCMVP 백엔드 교체)
 * 화이트리스트만 노출 → 금지 알고리즘(ECB·TDES·MD5·SHA-1·고정IV)은 API에 아예 없음.
 */
#ifndef CRYPTO_HAL_H
#define CRYPTO_HAL_H
#include <stdint.h>
#include <stddef.h>

typedef enum { CH_OK = 0, CH_EINVAL, CH_EALG_FORBIDDEN, CH_EBACKEND, CH_ESELFTEST } ch_rc;

/* SFR:9.1.1 권고 알고리즘(112bit+). 국산 ARIA 1순위, AES 폴백 */
typedef enum { CH_AEAD_ARIA128_GCM, CH_AEAD_ARIA256_GCM,
               CH_AEAD_AES128_GCM,  CH_AEAD_AES256_GCM } ch_aead_alg;
typedef enum { CH_HASH_SHA256, CH_HASH_SHA384, CH_HASH_SHA512 } ch_hash_alg;

typedef struct ch_key ch_key;   /* 불투명 키 핸들 — 원시 바이트 미노출(SFR:9.3.1) */

ch_rc crypto_hal_init(void);                                   /* 백엔드 초기화+자체시험 */
/* SFR:4.2.1 저장 암호화 / SFR:1.2.1·4.1.1 전송 보호에 사용 */
ch_rc crypto_hal_aead_seal(ch_aead_alg, ch_key*, const uint8_t *aad, size_t,
                           const uint8_t *pt, size_t, uint8_t *ct, uint8_t *tag);
ch_rc crypto_hal_hmac(ch_hash_alg, ch_key*, const uint8_t*, size_t, uint8_t *mac);
/* SFR:9.2.1 키 생성(DRBG/PBKDF)  SFR:9.3.1 저장  SFR:9.4.1 파기(3회 덮어쓰기) */
ch_rc crypto_hal_key_generate(size_t bits, ch_key **out);
ch_rc crypto_hal_key_destroy(ch_key *k);

#endif
