/*
 * cctv-secd — 국정원 보안기능확인서 대응 보안 데몬
 *
 * 인증(auth.c)·감사(audit.c)·암호(crypto_hal)는 실구현. 플랫폼 종속 기능
 * (프로비저닝·dm-verity 연동·세션 서버·관리 UI)은 골격 + TODO로 이식 시 채운다.
 * 각 함수 위 SFR:<항목ID> 태그를 sfr/sync.mjs 가 스캔해 구현명세서를 동기화.
 */
#include <stdio.h>
#include <unistd.h>
#include <crypto_hal.h>
#include "auth.h"
#include "audit.h"

/* ── 프로비저닝 (firstboot) ─────────────────────────────── */
/* SFR:3.4.1 기본 제공 계정 강제 변경·사용중지 */
/* SFR:3.4.2 관리자 기본(default) 패스워드 강제 변경 (변경 전 기능 잠금) */
static int provision_firstboot(void) {
	/* TODO: /etc/.factory-state 존재 시 password_set() 강제, 완료 후 플래그 제거 */
	return 0;
}

/* ── 자체시험 · 무결성 ──────────────────────────────────── */
/* SFR:5.1.1 구동·운용중 주기적/요청 자체시험 */
/* SFR:5.2.1 제품·설정값 무결성 검증 (dm-verity + 설정 HMAC crypto_hal_hmac) */
/* SFR:5.2.3 무결성 검증 결과 관리자 확인 (웹UI/감사로그) */
static int self_test(void) { /* TODO: dm-verity 상태 + 설정파일 HMAC 검증 */ return 0; }
/* SFR:5.1.2 자체시험 실패 대응  SFR:5.2.4 무결성 실패 대응(안전모드/중단) */
static void on_integrity_fail(void) { audit_append("integrity check FAILED"); }

/* SFR:2.2.2 관리자 연속 실패 즉시 통보 */
static void notify_admin(const char *msg) { audit_append(msg); /* TODO: 웹UI 팝업/외부 push */ }

/* SFR:8.4.1 용량 도달 대응  SFR:8.5.1 저장 포화 대응 */
static void audit_capacity_guard(void) { /* TODO: 임계치 알림 + 로테이션/외부전송 */ }

/* ── 보안 관리 ──────────────────────────────────────────── */
/* SFR:3.1.1 인가된 관리자만 보안기능·정책·중요데이터 설정·관리 */
static int mgmt_authorize(const char *user) { (void)user; /* TODO: RBAC(admin) */ return 0; }
/* SFR:3.2.1 모든 관리접속(SSH·웹·ONVIF) 활성/비활성 토글 */
static int mgmt_service_toggle(const char *svc, int on) { (void)svc;(void)on; /* TODO */ return 0; }
/* SFR:8.2.1 인가 관리자 감사기록 조회  SFR:8.2.2 논리조건 검색·정렬 */
static int audit_query(const char *filter, const char *sort) { (void)filter;(void)sort; /* TODO */ return 0; }
/* SFR:4.2.2 저장된 제품 설정값에 인가 관리자만 접근(암호화+파일권한+앱 접근제어) */
static int config_access_control(void) { /* TODO: 0600 + crypto_hal 암호화 + mgmt_authorize */ return 0; }
/* SFR:1.4.1 관리도구 최초설정 default 상태 한정  SFR:3.4.3 내부/외부 default PW 변경 */
static int provision_gate_default_only(void) { /* TODO: factory-state 확인 후 개방 */ return 0; }
/* SFR:7.1.1 미사용 세션 잠금·종료  SFR:7.2.1 동일계정 중복접속 불가 */
static void session_reaper(void) { /* TODO: idle timeout + 단일 활성세션 강제 */ }

int main(void) {
	if (crypto_hal_init() != CH_OK) return 1;   /* SFR:9.1.1 백엔드 초기화+자체시험 */
	audit_init();                                /* SFR:8.1.1 감사 체인 초기화 */
	provision_firstboot();
	self_test();
	audit_append("cctv-secd started");
	for (;;) {                                    /* 메인 루프 */
		self_test();
		session_reaper();
		audit_capacity_guard();
		sleep(300);
	}
	/* 아래는 이식 시 연결될 골격 함수(현재 미사용 경고 억제) */
	(void)on_integrity_fail; (void)notify_admin; (void)mgmt_authorize;
	(void)mgmt_service_toggle; (void)audit_query; (void)config_access_control;
	(void)provision_gate_default_only;
	return 0;
}
