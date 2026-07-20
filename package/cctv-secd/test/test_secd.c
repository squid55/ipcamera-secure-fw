/* cctv-secd 로직 호스트 테스트 (auth + audit) */
#include "auth.h"
#include "audit.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("  FAIL: %s\n", msg); fails++; } else printf("  ok: %s\n", msg); } while (0)

int main(void) {
	printf("[인증] 패스워드 정책 (SFR:2.3.1)\n");
	CHECK(password_policy_check("short1!") == PW_TOO_SHORT, "9자 미만 거부");
	CHECK(password_policy_check("alllowercase") == PW_NO_COMPLEXITY, "문자종류 부족 거부");
	CHECK(password_policy_check("Str0ng!Pass") == PW_OK, "강한 패스워드 통과");

	printf("[인증] 재사용 방지 (SFR:2.4.1)\n");
	CHECK(password_set("admin", "Str0ng!Pass") == PW_OK, "최초 설정");
	CHECK(password_set("admin", "Str0ng!Pass") == PW_REUSED, "동일 패스워드 재사용 거부");
	CHECK(password_set("admin", "An0ther!Pw") == PW_OK, "다른 패스워드 허용");

	printf("[인증] 연속 실패 잠금 (SFR:2.2.1)\n");
	auth_reset("bob");
	CHECK(!auth_record_fail("bob", 5), "1회 실패는 미잠금");
	auth_record_fail("bob", 5); auth_record_fail("bob", 5); auth_record_fail("bob", 5);
	CHECK(auth_record_fail("bob", 5), "5회째 잠금");
	CHECK(auth_is_locked("bob"), "잠금 상태 유지");
	auth_reset("bob");
	CHECK(!auth_is_locked("bob"), "성공 시 잠금 해제");

	printf("[인증] 실패 사유 미노출 (SFR:2.5.2)\n");
	CHECK(strcmp(auth_generic_fail_msg(), "인증에 실패했습니다.") == 0, "일반화 메시지");

	printf("[감사] append-only 해시체인 무결성 (SFR:8.1.1/8.3.1)\n");
	audit_init();
	audit_append("login success user=admin");
	audit_append("policy changed key=retention");
	audit_append("firmware update slot=B");
	CHECK(audit_count() == 3, "3건 기록");
	CHECK(audit_verify(), "정상 체인 검증 통과");

	printf("[감사] 위변조 탐지\n");
	audit_test_tamper(1, "policy changed key=DISABLED_AUDIT");  /* 중간 레코드 변조 */
	CHECK(!audit_verify(), "변조 시 체인 검증 실패(탐지)");

	printf("\n%s (실패 %d)\n", fails ? "❌ 테스트 실패" : "✅ 전체 통과", fails);
	return fails ? 1 : 0;
}
