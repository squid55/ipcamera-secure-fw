/* session.h — 세션 관리 (플랫폼 독립, 시간 주입식으로 테스트 가능) */
#ifndef SESSION_H
#define SESSION_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef enum { SESSION_OK = 0, SESSION_DUP, SESSION_FULL, SESSION_NOTFOUND } session_rc;

void       session_init(void);
/* SFR:7.2.1 동일 계정 중복 접속 거부(이미 활성 세션이 있으면 SESSION_DUP) */
session_rc session_open(const char *user, const char *sid, uint64_t now);
session_rc session_touch(const char *sid, uint64_t now);   /* 활동 갱신 */
bool       session_active(const char *sid);
void       session_close(const char *sid);
/* SFR:7.1.1 idle_timeout 초과한 세션을 잠금·종료. 종료한 세션 수 반환 */
int        session_reap(uint64_t now, uint64_t idle_timeout);
size_t     session_count(void);

#endif
