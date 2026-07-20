/* config_store.h — 저장 설정값 보호 (암호화 + 접근제어 + 무결성) */
#ifndef CONFIG_STORE_H
#define CONFIG_STORE_H
#include <stdint.h>
#include <stddef.h>

typedef enum { CFG_OK = 0, CFG_DENIED, CFG_TAMPER, CFG_ERR, CFG_EMPTY } cfg_rc;

#define CFG_MAX 512

void   config_store_init(void);
/* SFR:4.2.2 인가 관리자(ADMIN)만 설정 저장, crypto_hal AEAD 로 암호화 저장 */
cfg_rc config_set(const char *user, const uint8_t *plain, size_t len);
/* SFR:4.2.2 인가 관리자만 조회  SFR:5.2.1 무결성 검증 실패 시 CFG_TAMPER */
cfg_rc config_get(const char *user, uint8_t *out, size_t *len);
/* 테스트 전용: 저장된 암호문 1바이트 변조 */
void   config_test_tamper(void);

#endif
