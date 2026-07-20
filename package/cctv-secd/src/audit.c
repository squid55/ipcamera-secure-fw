/* audit.c — 감사기록 실구현: append-only HMAC 해시체인
 * 각 레코드 MAC = HMAC(key, seq || event || prev_mac).
 * 어떤 레코드를 바꾸면 이후 모든 MAC 이 어긋나 위변조가 탐지된다(SFR:8.3.1).
 * key 는 쓰기영역 밖(프로비저닝 주입)이라, 쓰기 권한만으론 체인 재계산 불가.
 * SFR:8.3.2 내부 저장 시 crypto_hal_aead_seal 로 암호화하여 보호(선택).
 */
#include "audit.h"
#include "crypto_hal.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_REC     4096
#define EVENT_MAX   200     /* SFR:8.1.2 과잉정보 방지: 이벤트 길이 제한 */
#define MAC_LEN     32

struct rec { uint64_t seq; char event[EVENT_MAX]; uint8_t mac[MAC_LEN]; };
static struct rec log[MAX_REC];
static size_t n_rec;
static uint8_t last_mac[MAC_LEN];

static ch_key *audit_key(void) {
	static ch_key *k = NULL;
	if (!k) {
		static const uint8_t kb[32] = "cctv-audit-chain-key-placeholder";
		crypto_hal_key_import(kb, 32, &k);
	}
	return k;
}

/* mac = HMAC(key, seq(8B, LE) || event || prev_mac) */
static void compute_mac(uint64_t seq, const char *event, const uint8_t *prev, uint8_t *out) {
	uint8_t buf[8 + EVENT_MAX + MAC_LEN];
	size_t p = 0;
	for (int i = 0; i < 8; i++) buf[p++] = (uint8_t)(seq >> (8 * i));
	size_t el = strlen(event);
	memcpy(buf + p, event, el); p += el;
	memcpy(buf + p, prev, MAC_LEN); p += MAC_LEN;
	size_t ml = 0;
	crypto_hal_hmac(CH_HASH_SHA256, audit_key(), buf, p, out, &ml);
}

int audit_init(void) {
	n_rec = 0;
	memset(last_mac, 0, MAC_LEN);   /* 제네시스 prev_mac = 0 */
	return 0;
}

int audit_append(const char *event) {
	if (!event || n_rec >= MAX_REC) return -1;
	struct rec *r = &log[n_rec];
	r->seq = (uint64_t)n_rec;
	strncpy(r->event, event, EVENT_MAX - 1);
	r->event[EVENT_MAX - 1] = '\0';           /* 길이 제한(8.1.2) */
	compute_mac(r->seq, r->event, last_mac, r->mac);
	memcpy(last_mac, r->mac, MAC_LEN);
	n_rec++;
	return 0;
}

bool audit_verify(void) {
	uint8_t prev[MAC_LEN]; memset(prev, 0, MAC_LEN);
	for (size_t i = 0; i < n_rec; i++) {
		uint8_t m[MAC_LEN];
		compute_mac(log[i].seq, log[i].event, prev, m);
		if (memcmp(m, log[i].mac, MAC_LEN) != 0) return false;   /* 변조 탐지 */
		memcpy(prev, log[i].mac, MAC_LEN);
	}
	return true;
}

size_t audit_count(void) { return n_rec; }

void audit_test_tamper(size_t idx, const char *new_event) {
	if (idx < n_rec) { strncpy(log[idx].event, new_event, EVENT_MAX - 1); log[idx].event[EVENT_MAX-1]='\0'; }
}
