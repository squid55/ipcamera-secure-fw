/*
 * cctv-secd — 국정원 보안기능확인서 대응 보안 데몬
 *
 * 플랫폼 독립 로직(암호·인증·감사·세션·관리·설정)은 실구현 + 호스트 테스트.
 * 플랫폼 종속 기능(프로비저닝 파일·dm-verity 연동·관리 UI)은 골격 + TODO.
 * 각 함수/모듈의 SFR:<항목ID> 태그를 sfr/sync.mjs 가 스캔해 구현명세서를 동기화.
 */
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <crypto_hal.h>
#include "auth.h"
#include "audit.h"
#include "session.h"
#include "mgmt.h"
#include "config_store.h"

#define IDLE_TIMEOUT 600u    /* 세션 미사용 종료: 10분 */
#define AUDIT_HW     3500u   /* 감사기록 용량 임계치 */

/* SFR:3.4.1 [STUB] 기본 계정 강제 변경·사용중지  SFR:3.4.2 [STUB] 기본 PW 강제 변경 */
static int provision_firstboot(void) {
	/* TODO: /etc/.factory-state 존재 시 password_set() 강제, 완료 후 플래그 제거.
	 *   현재 미구현 — 이 함수가 실제 접속경로(SSH/웹)와 연동돼야 강제 변경이 발효됨. */
	return 0;
}
/* SFR:5.1.1 [STUB] 자체시험  SFR:5.2.1 [STUB] 무결성 검증(dm-verity+설정HMAC)  SFR:5.2.3 [STUB] 결과 확인 */
static int self_test(void) { /* TODO: dm-verity 상태 + config_store 무결성 실검증. 현재 항상 0 */ return 0; }
/* SFR:5.1.2 [STUB] 자체시험 실패 대응  SFR:5.2.4 [STUB] 무결성 실패 대응 */
static void on_integrity_fail(void) { audit_append("integrity check FAILED"); }
/* SFR:2.2.2 [STUB] 관리자 연속 실패 즉시 통보(호출부·push 미구현) */
static void notify_admin(const char *msg) { audit_append(msg); /* TODO: 웹UI 팝업/외부 push */ }
/* SFR:1.4.1 [STUB] 관리도구 최초설정 default 한정  SFR:3.4.3 [STUB] 내부/외부 default PW 변경 */
static int provision_gate_default_only(void) { /* TODO: factory-state 확인 후 개방 */ return 0; }

int main(void) {
	if (crypto_hal_init() != CH_OK) return 1;   /* SFR:9.1.1 백엔드 초기화+자체시험 */
	audit_init();                                /* SFR:8.1.1 */
	session_init();
	mgmt_init();
	config_store_init();
	provision_firstboot();
	self_test();
	audit_append("cctv-secd started");
	for (;;) {                                    /* 메인 루프 */
		self_test();
		session_reap((uint64_t)time(NULL), IDLE_TIMEOUT);  /* SFR:7.1.1 */
		audit_capacity_guard(AUDIT_HW);                    /* SFR:8.4.1/8.5.1 */
		sleep(300);
	}
	(void)on_integrity_fail; (void)notify_admin; (void)provision_gate_default_only;
	return 0;
}
