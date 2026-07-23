/* cctv-secd 로직 호스트 테스트 (auth + audit + session + mgmt + config) */
#include "auth.h"
#include "audit.h"
#include "session.h"
#include "mgmt.h"
#include "config_store.h"
#include "provision.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("  FAIL: %s\n", msg); fails++; } else printf("  ok: %s\n", msg); } while (0)

int main(void) {
	printf("[인증] 패스워드 정책 (SFR:2.3.1)\n");
	CHECK(password_policy_check("short1!") == PW_TOO_SHORT, "9자 미만 거부");
	CHECK(password_policy_check("alllowercase") == PW_NO_COMPLEXITY, "문자종류 부족 거부");
	CHECK(password_policy_check("bad\tctrl99A") == PW_NO_COMPLEXITY, "제어문자 거부");
	CHECK(password_policy_check("Str0ng!Pass") == PW_OK, "강한 패스워드 통과");

	printf("[인증] 사용자명 포함 거부 + 재사용 방지 (SFR:2.4.1)\n");
	CHECK(password_set("admin", "adminP@ss12") == PW_CONTAINS_USER, "패스워드에 사용자명 포함 거부");
	CHECK(password_set("admin", "Str0ng!Pass") == PW_OK, "최초 설정");
	CHECK(password_set("admin", "Str0ng!Pass") == PW_REUSED, "동일 패스워드 재사용 거부");
	CHECK(password_set("admin", "An0ther!Pw9") == PW_OK, "다른 패스워드 허용");

	printf("[인증] 연속 실패 잠금 + DoS 차단 + 자동 해제 (SFR:2.2.1)\n");
	CHECK(!auth_record_fail("nosuch", 5, 100), "미등록 계정은 잠금·슬롯소비 없음(DoS 차단)");
	CHECK(password_set("bob", "B0b#Strong1") == PW_OK, "bob 등록");
	CHECK(!auth_record_fail("bob", 5, 100), "1회 실패는 미잠금");
	auth_record_fail("bob", 5, 100); auth_record_fail("bob", 5, 100); auth_record_fail("bob", 5, 100);
	CHECK(auth_record_fail("bob", 5, 100), "5회째 잠금");
	CHECK(auth_is_locked("bob", 200), "잠금 창 이내 유지");
	CHECK(!auth_is_locked("bob", 100 + 900 + 1), "시간 경과 후 자동 해제");

	printf("[인증] 실패 사유 미노출 (SFR:2.5.2)\n");
	CHECK(strcmp(auth_generic_fail_msg(), "인증에 실패했습니다.") == 0, "일반화 메시지");

	printf("[감사] 파일 영속 append-only 해시체인 (SFR:8.1.1/8.3.1)\n");
	system("rm -rf /tmp/cctv_audit_test");
	audit_set_dir("/tmp/cctv_audit_test");
	audit_init();
	audit_append("login success user=admin");
	audit_append("policy changed key=retention");
	audit_append("firmware update slot=B");
	CHECK(audit_count() == 3, "3건 기록");
	CHECK(audit_verify(), "정상 체인 검증 통과");
	audit_test_tamper(1, "policy changed key=DISABLED");
	CHECK(!audit_verify(), "변조 시 검증 실패(탐지)");

	printf("[감사] 재부팅(재-init) 영속·체인 연속성 (SFR:8.1.1/8.1.3)\n");
	audit_init();                                              /* 파일에서 재로드 */
	CHECK(audit_count() == 3, "재-init 후 3건 복원(디스크 영속)");
	CHECK(audit_verify(), "재로드된 체인 무결성 통과(연속성)");
	audit_append("after reboot event");
	CHECK(audit_count() == 4 && audit_verify(), "재부팅 후 이어쓰기 + 체인 연속");

	printf("[감사] 조회·정렬 + 용량 회전·아카이브 (SFR:8.2.1/8.2.2/8.4.1/8.5.1)\n");
	system("rm -rf /tmp/cctv_audit_test2");
	audit_set_dir("/tmp/cctv_audit_test2");
	audit_init();
	audit_append("login user=admin");
	audit_append("policy change");
	audit_append("login user=bob");
	size_t idx[8];
	CHECK(audit_query("login", 1, idx, 8) == 2, "substr 'login' 2건");
	CHECK(audit_query(NULL, 0, idx, 8) == 3 && idx[0] == 2, "내림차순(최신 먼저)");
	CHECK(audit_capacity_guard(3) == 1 && audit_count() == 0, "용량 도달 시 회전(아카이브)");
	audit_append("after rotate");
	CHECK(audit_verify(), "회전 후 세그먼트도 검증 통과(체인 연속)");

	printf("[세션] 미사용 종료 + 중복접속/중복sid 거부 (SFR:7.1.1/7.2.1)\n");
	session_init();
	CHECK(session_open("admin", "sidA", 1000) == SESSION_OK, "세션 개설");
	CHECK(session_open("admin", "sidB", 1001) == SESSION_DUP, "동일 계정 중복 거부");
	CHECK(session_open("carol", "sidA", 1002) == SESSION_DUP, "동일 sid 중복 거부");
	CHECK(session_touch("sidA", 1500) == SESSION_OK, "활동 갱신");
	CHECK(session_reap(1600, 300) == 0, "idle 미초과 유지");
	CHECK(session_reap(500, 300) == 0, "시계 역행 시 오종료 없음");
	CHECK(session_reap(2000, 300) == 1 && session_count() == 0, "idle 초과 종료");

	printf("[관리] RBAC 부트스트랩 + 인가 게이트 (SFR:3.1.1/3.2.1)\n");
	mgmt_init();
	CHECK(mgmt_bootstrap_admin("admin"), "최초 ADMIN 시딩");
	CHECK(!mgmt_bootstrap_admin("attacker"), "ADMIN 존재 시 부트스트랩 거부(권한상승 차단)");
	CHECK(!mgmt_set_role("attacker", "attacker", ROLE_ADMIN), "비인가자 역할부여 거부");
	CHECK(mgmt_set_role("admin", "viewer", ROLE_VIEWER), "ADMIN이 역할부여");
	CHECK(mgmt_can_manage("admin") && !mgmt_can_manage("viewer"), "ADMIN만 관리 가능");
	CHECK(!mgmt_service_set("viewer", SVC_WEB, true), "비인가자 토글 거부");
	CHECK(mgmt_service_set("admin", SVC_SSH, true) && mgmt_service_enabled(SVC_SSH), "ADMIN 토글 반영");

	printf("[설정] 암호화 저장 + 접근제어 + 무결성 (SFR:4.2.2/5.2.1)\n");
	config_store_init();
	const uint8_t cfg[] = "retention=30d; ip_allow=10.0.0.0/24";
	CHECK(config_set("viewer", cfg, sizeof(cfg)) == CFG_DENIED, "비인가자 저장 거부");
	CHECK(config_set("admin", cfg, sizeof(cfg)) == CFG_OK, "ADMIN 암호화 저장");
	uint8_t rd[512]; size_t rl = sizeof(rd);
	CHECK(config_get("admin", rd, &rl) == CFG_OK && memcmp(rd, cfg, sizeof(cfg)) == 0, "복호화 일치");
	config_test_tamper();
	rl = sizeof(rd);
	CHECK(config_get("admin", rd, &rl) == CFG_TAMPER, "변조된 설정 무결성 실패 탐지");

	printf("[프로비저닝] 관리 자격증명 강제설정·검증 (SFR:3.4.1/3.4.2)\n");
	const char *credp = "/tmp/.cctv_test_mgmt_cred";
	remove(credp);
	CHECK(provision_set_mgmt_cred("operator", "weak", credp) == PV_POLICY, "약한 PW 거부(기본값 존치 차단)");
	CHECK(provision_set_mgmt_cred("operator", "operatorX9!", credp) == PV_POLICY, "사용자명 포함 PW 거부");
	CHECK(provision_set_mgmt_cred("operator", "Str0ng!Cred9", credp) == PV_OK, "강한 관리 PW 설정");
	CHECK(provision_verify_mgmt_cred("operator", "Str0ng!Cred9", credp) == PV_OK, "정확한 PW 검증 통과");
	CHECK(provision_verify_mgmt_cred("operator", "WrongPass!9", credp) == PV_MISMATCH, "틀린 PW 거부");
	CHECK(provision_verify_mgmt_cred("intruder", "Str0ng!Cred9", credp) == PV_MISMATCH, "다른 사용자 거부");
	CHECK(provision_verify_mgmt_cred("operator", "Str0ng!Cred9", "/tmp/.no_such_cred") == PV_IO, "미프로비저닝 시 IO 실패(fail-closed)");
	char pw1[64], pw2[64];
	CHECK(provision_gen_password(pw1, sizeof(pw1)) == PV_OK && strlen(pw1) == 24, "임시 PW 생성(24hex)");
	CHECK(provision_gen_password(pw2, sizeof(pw2)) == PV_OK && strcmp(pw1, pw2) != 0, "매번 다른 난수 PW");
	CHECK(provision_gen_keyfile("/tmp/.cctv_test_auditkey", 32) == PV_OK, "per-device 감사 키파일 생성(32B)");
	remove("/tmp/.cctv_test_auditkey");
	remove(credp);

	printf("\n%s (실패 %d)\n", fails ? "❌ 테스트 실패" : "✅ 전체 통과", fails);
	return fails ? 1 : 0;
}
