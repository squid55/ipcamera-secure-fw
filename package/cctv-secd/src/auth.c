/* auth.c — 사용자 인증 정책 실구현 (플랫폼 독립, 호스트 테스트 가능) */
#include "auth.h"
#include "crypto_hal.h"
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_USERS   8
#define HIST_LEN    4     /* 최근 4개 재사용 금지 */
#define PW_MIN_LEN  9     /* 표1 근사: 9자 이상 + 문자종류 3종 이상 */

/* 패스워드 이력은 원문이 아니라 HMAC 다이제스트로 저장(SFR:2.4.1) */
struct user_state {
	char    name[32];
	uint8_t hist[HIST_LEN][64];
	size_t  hist_len[HIST_LEN];
	int     stored;   /* 유효 이력 수 (0..HIST_LEN) */
	int     next;     /* 다음 삽입 위치 (링버퍼) */
	int     fail_count;
	bool    locked;
	bool    used;
};
static struct user_state users[MAX_USERS];

/* 이력 다이제스트용 고정 키(양산: 프로비저닝 주입). crypto_hal 재사용. */
static ch_key *hist_key(void) {
	static ch_key *k = NULL;
	if (!k) {
		static const uint8_t kb[32] = "cctv-pw-history-key-placeholder!";
		crypto_hal_key_import(kb, 32, &k);
	}
	return k;
}
static void pw_digest(const char *pw, uint8_t *out, size_t *outlen) {
	crypto_hal_hmac(CH_HASH_SHA256, hist_key(), (const uint8_t *)pw, strlen(pw), out, outlen);
}

static struct user_state *find(const char *user, bool create) {
	for (int i = 0; i < MAX_USERS; i++)
		if (users[i].used && strcmp(users[i].name, user) == 0) return &users[i];
	if (!create) return NULL;
	for (int i = 0; i < MAX_USERS; i++)
		if (!users[i].used) {
			memset(&users[i], 0, sizeof(users[i]));
			users[i].used = true;
			strncpy(users[i].name, user, sizeof(users[i].name) - 1);
			return &users[i];
		}
	return NULL;
}

/* SFR:2.3.1 길이 9+ 그리고 대문자/소문자/숫자/특수 중 3종 이상 */
pw_result password_policy_check(const char *pw) {
	if (!pw || strlen(pw) < PW_MIN_LEN) return PW_TOO_SHORT;
	int up = 0, lo = 0, di = 0, sp = 0;
	for (const char *p = pw; *p; p++) {
		if (isupper((unsigned char)*p)) up = 1;
		else if (islower((unsigned char)*p)) lo = 1;
		else if (isdigit((unsigned char)*p)) di = 1;
		else sp = 1;
	}
	return (up + lo + di + sp) >= 3 ? PW_OK : PW_NO_COMPLEXITY;
}

/* SFR:2.4.1 정책 통과 + 최근 HIST_LEN개 이력 재사용 금지 후 등록 */
pw_result password_set(const char *user, const char *pw) {
	pw_result r = password_policy_check(pw);
	if (r != PW_OK) return r;
	struct user_state *u = find(user, true);
	if (!u) return PW_NO_COMPLEXITY;

	uint8_t d[64]; size_t dl = 0;
	pw_digest(pw, d, &dl);
	for (int i = 0; i < u->stored; i++)
		if (u->hist_len[i] == dl && memcmp(u->hist[i], d, dl) == 0) return PW_REUSED;

	memcpy(u->hist[u->next], d, dl);
	u->hist_len[u->next] = dl;
	u->next = (u->next + 1) % HIST_LEN;
	if (u->stored < HIST_LEN) u->stored++;
	return PW_OK;
}

void auth_reset(const char *user) {
	struct user_state *u = find(user, false);
	if (u) { u->fail_count = 0; u->locked = false; }
}
bool auth_record_fail(const char *user, int max_fails) {
	struct user_state *u = find(user, true);
	if (!u) return true;
	if (++u->fail_count >= max_fails) u->locked = true;   /* SFR:2.2.1 */
	return u->locked;
}
bool auth_is_locked(const char *user) {
	struct user_state *u = find(user, false);
	return u ? u->locked : false;
}
const char *auth_generic_fail_msg(void) { return "인증에 실패했습니다."; }  /* SFR:2.5.2 */
