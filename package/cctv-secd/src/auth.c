/* auth.c — 사용자 인증 정책 실구현 (플랫폼 독립, 호스트 테스트 가능) */
#include "auth.h"
#include "crypto_hal.h"
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_USERS   8
#define HIST_LEN    4       /* 최근 4개 재사용 금지 */
#define PW_MIN_LEN  9       /* 표1 근사: 9자 이상 + 문자종류 3종 이상 */
#define LOCK_WINDOW 900     /* 잠금 지속(초). 경과 시 자동 해제 */

/* 사용자 상태는 password_set 으로 '등록'된 계정에만 존재.
 * 미등록 계정으로는 슬롯을 만들지 않아 테이블 소진(DoS)·정상사용자 잠금을 차단. */
struct user_state {
	char     name[32];
	uint8_t  hist[HIST_LEN][64];
	size_t   hist_len[HIST_LEN];
	int      stored;
	int      next;
	int      fail_count;
	uint64_t locked_until;   /* 0=미잠금 */
	bool     used;
};
static struct user_state users[MAX_USERS];

/* 패스워드 이력 다이제스트 키(양산: 프로비저닝 주입, [STUB]). crypto_hal 재사용. */
static ch_key *hist_key(void) {
	static ch_key *k = NULL;
	if (!k) {
		static const uint8_t kb[32] = "cctv-pw-history-key-placeholder!";
		crypto_hal_key_import(kb, 32, &k);
	}
	return k;
}
/* 반환 0=성공. HMAC 실패 시 비-0 → 상위에서 fail-closed */
static int pw_digest(const char *pw, uint8_t *out, size_t *outlen) {
	ch_key *k = hist_key();
	if (!k) return -1;
	if (crypto_hal_hmac(CH_HASH_SHA256, k, (const uint8_t *)pw, strlen(pw), out, outlen) != CH_OK)
		return -1;
	if (*outlen != 32) return -1;
	return 0;
}

static struct user_state *find(const char *user) {
	if (!user) return NULL;
	for (int i = 0; i < MAX_USERS; i++)
		if (users[i].used && strcmp(users[i].name, user) == 0) return &users[i];
	return NULL;
}
static struct user_state *find_or_create(const char *user) {
	struct user_state *u = find(user);
	if (u) return u;
	for (int i = 0; i < MAX_USERS; i++)
		if (!users[i].used) {
			memset(&users[i], 0, sizeof(users[i]));
			users[i].used = true;
			strncpy(users[i].name, user, sizeof(users[i].name) - 1);
			return &users[i];
		}
	return NULL;
}

/* SFR:2.3.1 길이 9+ 그리고 대문자/소문자/숫자/특수(출력가능 구두점) 중 3종 이상 */
pw_result password_policy_check(const char *pw) {
	if (!pw || strlen(pw) < PW_MIN_LEN) return PW_TOO_SHORT;
	int up = 0, lo = 0, di = 0, sp = 0;
	for (const char *p = pw; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (!isprint(c)) return PW_NO_COMPLEXITY;         /* 제어/비출력 문자 거부 */
		if (isupper(c)) up = 1;
		else if (islower(c)) lo = 1;
		else if (isdigit(c)) di = 1;
		else if (ispunct(c)) sp = 1;                      /* 특수문자 화이트리스트 */
	}
	return (up + lo + di + sp) >= 3 ? PW_OK : PW_NO_COMPLEXITY;
}

/* 대소문자 무시 부분문자열 포함 검사(패스워드에 사용자명 포함 금지) */
static bool contains_ci(const char *hay, const char *needle) {
	size_t nl = strlen(needle);
	if (nl == 0) return false;
	for (const char *h = hay; *h; h++) {
		size_t i = 0;
		while (i < nl && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) i++;
		if (i == nl) return true;
	}
	return false;
}

/* SFR:2.4.1 정책 통과 + 사용자명 미포함 + 최근 HIST_LEN개 재사용 금지 후 등록 */
pw_result password_set(const char *user, const char *pw) {
	pw_result r = password_policy_check(pw);
	if (r != PW_OK) return r;
	if (user && contains_ci(pw, user)) return PW_CONTAINS_USER;

	uint8_t d[64]; size_t dl = 0;
	if (pw_digest(pw, d, &dl) != 0) return PW_ERROR;      /* fail-closed */

	struct user_state *u = find_or_create(user);
	if (!u) return PW_ERROR;
	for (int i = 0; i < u->stored; i++)
		if (u->hist_len[i] == dl && memcmp(u->hist[i], d, dl) == 0) return PW_REUSED;

	memcpy(u->hist[u->next], d, dl);
	u->hist_len[u->next] = dl;
	u->next = (u->next + 1) % HIST_LEN;
	if (u->stored < HIST_LEN) u->stored++;
	return PW_OK;
}

void auth_reset(const char *user) {
	struct user_state *u = find(user);
	if (u) { u->fail_count = 0; u->locked_until = 0; }
}

/* 미등록 계정은 잠금·슬롯소비 없이 false(사용자 열거 방지 + DoS 차단) */
bool auth_record_fail(const char *user, int max_fails, uint64_t now) {
	struct user_state *u = find(user);
	if (!u) return false;
	if (u->locked_until && now >= u->locked_until) { u->locked_until = 0; u->fail_count = 0; }
	if (++u->fail_count >= max_fails) u->locked_until = now + LOCK_WINDOW;  /* SFR:2.2.1 */
	return u->locked_until != 0;
}
bool auth_is_locked(const char *user, uint64_t now) {
	struct user_state *u = find(user);
	if (!u || !u->locked_until) return false;
	if (now >= u->locked_until) { u->locked_until = 0; u->fail_count = 0; return false; }
	return true;
}
const char *auth_generic_fail_msg(void) { return "인증에 실패했습니다."; }  /* SFR:2.5.2 */
