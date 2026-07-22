/* session.c — 세션 관리 실구현 */
#include "session.h"
#include <string.h>

#define MAX_SESSIONS 16

struct sess { char user[32]; char sid[64]; uint64_t last; bool active; };
static struct sess tbl[MAX_SESSIONS];

void session_init(void) { memset(tbl, 0, sizeof(tbl)); }

static struct sess *by_sid(const char *sid) {
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (tbl[i].active && strcmp(tbl[i].sid, sid) == 0) return &tbl[i];
	return NULL;
}
static bool user_active(const char *user) {
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (tbl[i].active && strcmp(tbl[i].user, user) == 0) return true;
	return false;
}

session_rc session_open(const char *user, const char *sid, uint64_t now) {
	if (!user || !sid) return SESSION_NOTFOUND;
	if (by_sid(sid)) return SESSION_DUP;                /* sid 중복 차단(세션 혼동/탈취 방지) */
	if (user_active(user)) return SESSION_DUP;          /* SFR:7.2.1 */
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (!tbl[i].active) {
			strncpy(tbl[i].user, user, sizeof(tbl[i].user) - 1);
			tbl[i].user[sizeof(tbl[i].user)-1] = '\0';
			strncpy(tbl[i].sid, sid, sizeof(tbl[i].sid) - 1);
			tbl[i].sid[sizeof(tbl[i].sid)-1] = '\0';
			tbl[i].last = now;
			tbl[i].active = true;
			return SESSION_OK;
		}
	return SESSION_FULL;
}

session_rc session_touch(const char *sid, uint64_t now) {
	struct sess *s = by_sid(sid);
	if (!s) return SESSION_NOTFOUND;
	s->last = now;
	return SESSION_OK;
}

bool session_active(const char *sid) { return by_sid(sid) != NULL; }

void session_close(const char *sid) {
	struct sess *s = by_sid(sid);
	if (s) { memset(s, 0, sizeof(*s)); }
}

int session_reap(uint64_t now, uint64_t idle_timeout) {
	int closed = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		/* now >= last 가드: 벽시계 역행 시 부호없는 언더플로로 오종료되는 것 방지 */
		if (tbl[i].active && now >= tbl[i].last && now - tbl[i].last > idle_timeout) {  /* SFR:7.1.1 */
			memset(&tbl[i], 0, sizeof(tbl[i]));
			closed++;
		}
	return closed;
}

size_t session_count(void) {
	size_t n = 0;
	for (int i = 0; i < MAX_SESSIONS; i++) if (tbl[i].active) n++;
	return n;
}
