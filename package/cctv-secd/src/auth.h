/* auth.h — 사용자 인증 정책 (플랫폼 독립) */
#ifndef AUTH_H
#define AUTH_H
#include <stdbool.h>

/* SFR:2.3.1 패스워드 보안성 기준(표1) 판정 결과 */
typedef enum { PW_OK = 0, PW_TOO_SHORT, PW_NO_COMPLEXITY, PW_REUSED } pw_result;

pw_result password_policy_check(const char *pw);                 /* SFR:2.3.1 */
pw_result password_set(const char *user, const char *pw);        /* SFR:2.4.1 재사용 방지 */
void      auth_reset(const char *user);                          /* 성공 시 실패 카운트 초기화 */
bool      auth_record_fail(const char *user, int max_fails);     /* SFR:2.2.1 true=잠금 */
bool      auth_is_locked(const char *user);
const char *auth_generic_fail_msg(void);                         /* SFR:2.5.2 사유 미노출 */

#endif
