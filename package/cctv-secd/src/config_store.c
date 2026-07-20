/* config_store.c — 설정값 암호화 저장 + RBAC 접근제어 + AEAD 무결성 */
#include "config_store.h"
#include "mgmt.h"
#include "crypto_hal.h"
#include <string.h>

static struct {
	uint8_t nonce[CH_AEAD_NONCE_LEN];
	uint8_t ct[CFG_MAX];
	uint8_t tag[CH_AEAD_TAG_LEN];
	size_t  len;
	bool    present;
} blob;

static ch_key *cfg_key(void) {
	static ch_key *k = NULL;
	if (!k) {
		/* 양산: KEK로 감싼 DEK를 프로비저닝 주입. 여기선 고정 placeholder. */
		static const uint8_t kb[32] = "cctv-config-DEK-placeholder-0001";
		crypto_hal_key_import(kb, 32, &k);
	}
	return k;
}

void config_store_init(void) { memset(&blob, 0, sizeof(blob)); }

cfg_rc config_set(const char *user, const uint8_t *plain, size_t len) {
	if (!mgmt_can_manage(user)) return CFG_DENIED;      /* SFR:4.2.2 */
	if (!plain || len == 0 || len > CFG_MAX) return CFG_ERR;
	ch_rc rc = crypto_hal_aead_seal(CH_AEAD_ARIA256_GCM, cfg_key(),
	                                blob.nonce, (const uint8_t *)"config-v1", 9,
	                                plain, len, blob.ct, blob.tag);
	if (rc != CH_OK) return CFG_ERR;
	blob.len = len;
	blob.present = true;
	return CFG_OK;
}

cfg_rc config_get(const char *user, uint8_t *out, size_t *len) {
	if (!mgmt_can_manage(user)) return CFG_DENIED;      /* SFR:4.2.2 */
	if (!blob.present) return CFG_EMPTY;
	if (!out || !len || *len < blob.len) return CFG_ERR;
	ch_rc rc = crypto_hal_aead_open(CH_AEAD_ARIA256_GCM, cfg_key(),
	                                blob.nonce, (const uint8_t *)"config-v1", 9,
	                                blob.ct, blob.len, blob.tag, out);
	if (rc == CH_EAUTH) return CFG_TAMPER;              /* SFR:5.2.1 무결성 실패 */
	if (rc != CH_OK) return CFG_ERR;
	*len = blob.len;
	return CFG_OK;
}

void config_test_tamper(void) { if (blob.present) blob.ct[0] ^= 0x01; }
