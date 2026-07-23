/* audit.c — 감사기록 실구현: 파일 영속 append-only HMAC 해시체인
 * 각 레코드 MAC = HMAC(key, seq || ts || event || prev_mac).
 * 어떤 레코드를 바꾸면 이후 모든 MAC 이 어긋나 위변조가 탐지된다(SFR:8.3.1).
 *
 * 영속(SFR:8.1.1): <dir>/current.log 에 append + fsync → 재부팅에도 보존.
 *   파일 형식: 첫 줄 "GENESIS|<hex>" + 레코드 줄 "<seq>|<ts>|<event>|<mac_hex>".
 *   부팅 시 로드하여 seq/last_mac/genesis 를 이어받아 체인 연속성 유지.
 * 회전(SFR:8.4.1/8.5.1): 임계 도달 시 current.log 검증→archive-<seq>.log 로 보관→새 세그먼트.
 * 신뢰 시간(SFR:8.1.3): 레코드에 타임스탬프(time()) 기록, MAC 이 ts 까지 보호.
 *
 * [체인 키] 프로비저닝이 생성한 per-device 키(<keyfile>, root 600)를 우선 사용.
 *   없으면 소스 상수 placeholder 로 폴백(호스트 테스트/미프로비저닝). 양산은 하드웨어 신뢰루트.
 * [남은 한계] 외부 로그서버 전송(off-box 사본)은 후속 — 로컬 영속까지 구현.
 */
#include "audit.h"
#include "crypto_hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_REC     4096
#define EVENT_MAX   200     /* SFR:8.1.2 과잉정보 방지: 이벤트 길이 제한 */
#define MAC_LEN     32
#define LINE_MAX    512

struct rec { uint64_t seq; uint64_t ts; char event[EVENT_MAX]; uint8_t mac[MAC_LEN]; };
static struct rec log[MAX_REC];
static size_t   n_rec;
static uint64_t next_seq;                 /* 영속 단조증가 seq(회전·재부팅 넘어 연속) */
static uint8_t  last_mac[MAC_LEN];
static uint8_t  genesis_mac[MAC_LEN];     /* 현재 세그먼트 첫 레코드의 prev */

static char audit_dir[256] = "/data/audit";
static char keyfile[256]   = "/data/cred/audit.key";
static FILE *fp;                          /* current.log append 핸들 */
static int (*g_forward)(const char *);    /* off-box 전송 훅(8.3.1) */

void audit_set_dir(const char *dir) {
	if (!dir) return;
	snprintf(audit_dir, sizeof(audit_dir), "%s", dir);
}
void audit_set_forward(int (*fn)(const char *line)) { g_forward = fn; }

/* ---- 16진 ---- */
static void tohex(const uint8_t *in, size_t n, char *out) {
	static const char h[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[2*i] = h[in[i] >> 4]; out[2*i+1] = h[in[i] & 15]; }
	out[2*n] = 0;
}
static int hexv(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}
static int fromhex(const char *s, uint8_t *out, size_t n) {
	for (size_t i = 0; i < n; i++) {
		int hi = hexv(s[2*i]), lo = hexv(s[2*i+1]);
		if (hi < 0 || lo < 0) return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

/* per-device 키 우선, 없으면 placeholder */
static ch_key *audit_key(void) {
	static ch_key *k = NULL;
	if (k) return k;
	uint8_t kb[32];
	FILE *kf = fopen(keyfile, "rb");
	if (kf) {
		size_t rd = fread(kb, 1, sizeof(kb), kf);
		fclose(kf);
		if (rd == sizeof(kb)) { crypto_hal_key_import(kb, 32, &k); return k; }
	}
	static const uint8_t ph[32] = "cctv-audit-chain-key-placeholder";
	crypto_hal_key_import(ph, 32, &k);
	return k;
}

/* mac = HMAC(key, seq(8,LE) || ts(8,LE) || event || prev_mac). 0=성공, 비-0=실패(fail-closed) */
static int compute_mac(uint64_t seq, uint64_t ts, const char *event, const uint8_t *prev, uint8_t *out) {
	ch_key *k = audit_key();
	if (!k) return -1;
	uint8_t buf[8 + 8 + EVENT_MAX + MAC_LEN];
	size_t p = 0;
	for (int i = 0; i < 8; i++) buf[p++] = (uint8_t)(seq >> (8 * i));
	for (int i = 0; i < 8; i++) buf[p++] = (uint8_t)(ts  >> (8 * i));
	size_t el = strlen(event);
	memcpy(buf + p, event, el); p += el;
	memcpy(buf + p, prev, MAC_LEN); p += MAC_LEN;
	size_t ml = 0;
	if (crypto_hal_hmac(CH_HASH_SHA256, k, buf, p, out, &ml) != CH_OK) return -1;
	return ml == MAC_LEN ? 0 : -1;
}

/* '|' 와 개행은 저장 구분자와 충돌 → 치환(과잉정보 없이 안전 저장) */
static void sanitize(char *s) {
	for (; *s; s++) if (*s == '|' || *s == '\n' || *s == '\r') *s = '_';
}

static void path_current(char *out, size_t n) { snprintf(out, n, "%s/current.log", audit_dir); }

/* 새 세그먼트 파일 생성: GENESIS 헤더 기록 후 append 핸들 유지 */
static int open_new_segment(void) {
	char cur[512]; path_current(cur, sizeof(cur));
	fp = fopen(cur, "w");
	if (!fp) return -1;
	char gh[2*MAC_LEN + 1]; tohex(genesis_mac, MAC_LEN, gh);
	if (fprintf(fp, "GENESIS|%s\n", gh) < 0) { fclose(fp); fp = NULL; return -1; }
	fflush(fp); fsync(fileno(fp));
	return 0;
}

/* current.log 로드: GENESIS + 레코드들을 메모리로 복원(체인 이어감) */
static int load_segment(void) {
	char cur[512]; path_current(cur, sizeof(cur));
	FILE *r = fopen(cur, "r");
	if (!r) return 1;   /* 없음 → 신규 */
	char line[LINE_MAX];
	if (!fgets(line, sizeof(line), r)) { fclose(r); return 1; }
	if (strncmp(line, "GENESIS|", 8) == 0) {
		line[strcspn(line, "\r\n")] = 0;
		if (strlen(line + 8) == 2*MAC_LEN) fromhex(line + 8, genesis_mac, MAC_LEN);
	}
	memcpy(last_mac, genesis_mac, MAC_LEN);
	while (fgets(line, sizeof(line), r) && n_rec < MAX_REC) {
		line[strcspn(line, "\r\n")] = 0;
		if (!line[0]) continue;
		/* <seq>|<ts>|<event>|<mac_hex> */
		char *c1 = strchr(line, '|');       if (!c1) continue; *c1 = 0;
		char *c2 = strchr(c1 + 1, '|');     if (!c2) continue; *c2 = 0;
		char *c3 = strrchr(c2 + 1, '|');    if (!c3) continue; *c3 = 0;
		const char *macx = c3 + 1;
		if (strlen(macx) != 2*MAC_LEN) continue;
		struct rec *rc = &log[n_rec];
		rc->seq = strtoull(line, NULL, 10);
		rc->ts  = strtoull(c1 + 1, NULL, 10);
		snprintf(rc->event, sizeof(rc->event), "%s", c2 + 1);
		if (fromhex(macx, rc->mac, MAC_LEN) != 0) continue;
		memcpy(last_mac, rc->mac, MAC_LEN);
		next_seq = rc->seq + 1;
		n_rec++;
	}
	fclose(r);
	return 0;
}

int audit_init(void) {
	n_rec = 0; next_seq = 0;
	memset(last_mac, 0, MAC_LEN);
	memset(genesis_mac, 0, MAC_LEN);
	if (fp) { fclose(fp); fp = NULL; }
	mkdir(audit_dir, 0700);   /* best-effort */

	int rc = load_segment();
	if (rc == 0) {
		/* 기존 세그먼트 → append 모드로 이어쓰기 */
		char cur[512]; path_current(cur, sizeof(cur));
		fp = fopen(cur, "a");
		if (!fp) return -1;
	} else {
		/* 신규 세그먼트 */
		if (open_new_segment() != 0) return -1;
	}
	return 0;
}

int audit_append(const char *event) {
	if (!event || !fp || n_rec >= MAX_REC) return -1;
	struct rec *r = &log[n_rec];
	r->seq = next_seq;
	r->ts  = (uint64_t)time(NULL);
	snprintf(r->event, sizeof(r->event), "%s", event);   /* 길이 제한(8.1.2) */
	sanitize(r->event);
	if (compute_mac(r->seq, r->ts, r->event, last_mac, r->mac) != 0)
		return -1;                                       /* HMAC 실패 → 기록 거부(fail-closed) */
	/* 영속: 파일에 먼저 안전 기록(성공 확인 후 메모리 반영) */
	char macx[2*MAC_LEN + 1]; tohex(r->mac, MAC_LEN, macx);
	if (fprintf(fp, "%llu|%llu|%s|%s\n",
	            (unsigned long long)r->seq, (unsigned long long)r->ts, r->event, macx) < 0)
		return -1;
	if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) return -1;   /* 디스크 반영 확인 */
	memcpy(last_mac, r->mac, MAC_LEN);
	next_seq++; n_rec++;
	if (g_forward) {                          /* SFR:8.3.1 off-box 사본(best-effort) */
		char fl[EVENT_MAX + 40];
		snprintf(fl, sizeof(fl), "seq=%llu %s", (unsigned long long)r->seq, r->event);
		g_forward(fl);
	}
	return 0;
}

bool audit_verify(void) {
	uint8_t prev[MAC_LEN];
	memcpy(prev, genesis_mac, MAC_LEN);
	for (size_t i = 0; i < n_rec; i++) {
		uint8_t m[MAC_LEN];
		if (compute_mac(log[i].seq, log[i].ts, log[i].event, prev, m) != 0) return false;
		if (memcmp(m, log[i].mac, MAC_LEN) != 0) return false;   /* 변조 탐지 */
		memcpy(prev, log[i].mac, MAC_LEN);
	}
	return true;
}

size_t audit_count(void) { return n_rec; }

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

/* SFR:8.4.1 용량 임계 회전 · SFR:8.5.1 저장소 포화 대응 — 세그먼트 검증→아카이브→새 세그먼트(체인 연속) */
int audit_capacity_guard(size_t high_water) {
	if (n_rec < high_water) return 0;
	if (!audit_verify()) return -1;   /* 무결성 깨진 세그먼트는 회전 거부(fail-closed) */
	/* current.log → archive-<첫 seq>.log 로 보관 */
	if (fp) { fflush(fp); fsync(fileno(fp)); fclose(fp); fp = NULL; }
	char cur[512], arc[600];
	path_current(cur, sizeof(cur));
	snprintf(arc, sizeof(arc), "%s/archive-%llu.log", audit_dir,
	         (unsigned long long)(n_rec ? log[0].seq : next_seq));
	rename(cur, arc);                 /* 실패해도 진행(신규 세그먼트가 cur 덮어씀) */
	memcpy(genesis_mac, last_mac, MAC_LEN);   /* 새 세그먼트 prev = 이전 최종 MAC */
	n_rec = 0;
	if (open_new_segment() != 0) return -1;
	return 1;
}

#ifdef AUDIT_TEST
void audit_test_tamper(size_t idx, const char *new_event) {
	if (idx < n_rec) { snprintf(log[idx].event, sizeof(log[idx].event), "%s", new_event); }
}
#endif
