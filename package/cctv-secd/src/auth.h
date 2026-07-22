/* auth.h — 사용자 인증 정책 (플랫폼 독립) */
#ifndef AUTH_H
#define AUTH_H
#include <stdbool.h>
#include <stdint.h>

/* SFR:2.3.1 패스워드 보안성 기준 판정 결과 */
typedef enum { PW_OK = 0, PW_TOO_SHORT, PW_NO_COMPLEXITY, PW_REUSED,
               PW_CONTAINS_USER, PW_ERROR } pw_result;

pw_result password_policy_check(const char *pw);                 /* SFR:2.3.1 */
pw_result password_set(const char *user, const char *pw);        /* SFR:2.4.1 재사용 방지 */
void      auth_reset(const char *user);                          /* 성공 시 실패 카운트 초기화 */
/* SFR:2.2.1 연속 실패 잠금. 등록된 사용자만 카운트(미등록 계정은 잠금·슬롯소비 없음).
 * now(초)로 잠금창을 계산해 시간 경과 시 자동 해제 → 영구 잠금/가용성 DoS 방지. */
bool      auth_record_fail(const char *user, int max_fails, uint64_t now); /* true=잠금 */
bool      auth_is_locked(const char *user, uint64_t now);
const char *auth_generic_fail_msg(void);                         /* SFR:2.5.2 사유 미노출 */

#endif
