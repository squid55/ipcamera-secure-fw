/* audit.c — 감사기록 실구현: append-only HMAC 해시체인
 * 각 레코드 MAC = HMAC(key, seq || event || prev_mac).
 * 어떤 레코드를 바꾸면 이후 모든 MAC 이 어긋나 위변조가 탐지된다(SFR:8.3.1).
 * SFR:8.3.2 내부 저장 시 crypto_hal_aead_seal 로 암호화하여 보호(선택).
 *
 * [알려진 한계 — 인증 정직성]
 * - 체인 키가 프로토타입에서 소스 상수(placeholder)라, 이미지를 추출할 수 있는 공격자는
 *   키로 체인 재계산이 가능하다. 양산은 이 키를 하드웨어 신뢰루트/프로비저닝 주입으로 교체해야
 *   위변조 탐지(8.3.1)가 실효를 가진다.
 * - 현재 저장은 프로세스 인메모리이며 영속화(디스크/외부 로그서버)는 미구현(TODO).
 */
#include "audit.h"
#include "crypto_hal.h"
#include <string.h>
#include <stdint.h>

#define MAX_REC     4096
#define EVENT_MAX   200     /* SFR:8.1.2 과잉정보 방지: 이벤트 길이 제한 */
#define MAC_LEN     32

struct rec { uint64_t seq; char event[EVENT_MAX]; uint8_t mac[MAC_LEN]; };
static struct rec log[MAX_REC];
static size_t n_rec;
static uint8_t last_mac[MAC_LEN];
static uint8_t genesis_mac[MAC_LEN];   /* 현재 세그먼트 첫 레코드의 prev(회전 시 이전 세그먼트 최종 MAC) */

static ch_key *audit_key(void) {
	static ch_key *k = NULL;
	if (!k) {
		static const uint8_t kb[32] = "cctv-audit-chain-key-placeholder";
		if (crypto_hal_key_import(kb, 32, &k) != CH_OK) k = NULL;
	}
	return k;
}

/* mac = HMAC(key, seq(8B, LE) || event || prev_mac). 반환 0=성공, 비-0=실패(fail-closed) */
static int compute_mac(uint64_t seq, const char *event, const uint8_t *prev, uint8_t *out) {
	ch_key *k = audit_key();
	if (!k) return -1;
	uint8_t buf[8 + EVENT_MAX + MAC_LEN];
	size_t p = 0;
	for (int i = 0; i < 8; i++) buf[p++] = (uint8_t)(seq >> (8 * i));
	size_t el = strlen(event);
	memcpy(buf + p, event, el); p += el;
	memcpy(buf + p, prev, MAC_LEN); p += MAC_LEN;
	size_t ml = 0;
	if (crypto_hal_hmac(CH_HASH_SHA256, k, buf, p, out, &ml) != CH_OK) return -1;
	if (ml != MAC_LEN) return -1;
	return 0;
}

int audit_init(void) {
	n_rec = 0;
	memset(last_mac, 0, MAC_LEN);       /* 제네시스 prev_mac = 0 */
	memset(genesis_mac, 0, MAC_LEN);
	return 0;
}

int audit_append(const char *event) {
	if (!event || n_rec >= MAX_REC) return -1;
	struct rec *r = &log[n_rec];
	r->seq = (uint64_t)n_rec;
	strncpy(r->event, event, EVENT_MAX - 1);
	r->event[EVENT_MAX - 1] = '\0';                    /* 길이 제한(8.1.2) */
	if (compute_mac(r->seq, r->event, last_mac, r->mac) != 0)
		return -1;                                     /* HMAC 실패 시 기록 거부(fail-closed) */
	memcpy(last_mac, r->mac, MAC_LEN);
	n_rec++;
	return 0;
}

bool audit_verify(void) {
	uint8_t prev[MAC_LEN];
	memcpy(prev, genesis_mac, MAC_LEN);                /* 세그먼트 제네시스에서 시작 */
	for (size_t i = 0; i < n_rec; i++) {
		uint8_t m[MAC_LEN];
		if (compute_mac(log[i].seq, log[i].event, prev, m) != 0) return false;
		if (memcmp(m, log[i].mac, MAC_LEN) != 0) return false;   /* 변조 탐지 */
		memcpy(prev, log[i].mac, MAC_LEN);
	}
	return true;
}

size_t audit_count(void) { return n_rec; }

/* SFR:8.2.1/8.2.2 substr 필터 + seq 정렬 조회 */
size_t audit_query(const char *substr, int ascending, size_t *idx_out, size_t max) {
	size_t m = 0;
	for (size_t i = 0; i < n_rec; i++) {
		size_t idx = ascending ? i : (n_rec - 1 - i);
		if (substr && substr[0] && !strstr(log[idx].event, substr)) continue;
		if (idx_out && m < max) idx_out[m] = idx; else if (idx_out) break;
		m++;
	}
	return m;
}

/* SFR:8.4.1/8.5.1 용량 도달 시 (아카이브 후) 세그먼트 회전 — 체인 연속성 유지 */
int audit_capacity_guard(size_t high_water) {
	if (n_rec >= high_water) {
		/* TODO(영속성): 현재 세그먼트를 audit_verify 로 검증 후 서명·암호화하여
		 *   외부 로그서버/영속 저장으로 전송(성공 확인 후에만 회전). 미구현 시 인메모리 소실. */
		memcpy(genesis_mac, last_mac, MAC_LEN);        /* 새 세그먼트 prev = 이전 세그먼트 최종 MAC */
		n_rec = 0;
		return 1;
	}
	return 0;
}

#ifdef AUDIT_TEST
void audit_test_tamper(size_t idx, const char *new_event) {
	if (idx < n_rec) { strncpy(log[idx].event, new_event, EVENT_MAX - 1); log[idx].event[EVENT_MAX-1] = '\0'; }
}
#endif
