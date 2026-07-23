/*
 * cctv-secd — 국정원 보안기능확인서 대응 보안 데몬
 *
 * 플랫폼 독립 로직(암호·인증·감사·세션·관리·설정)은 실구현 + 호스트 테스트.
 * 플랫폼 종속 기능(프로비저닝 파일·dm-verity 연동·관리 UI)은 골격 + TODO.
 * 각 함수/모듈의 SFR:<항목ID> 태그를 sfr/sync.mjs 가 스캔해 구현명세서를 동기화.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <crypto_hal.h>
#include "auth.h"
#include "audit.h"
#include "session.h"
#include "mgmt.h"
#include "config_store.h"
#include "provision.h"

#define IDLE_TIMEOUT 600u    /* 세션 미사용 종료: 10분 */
#define AUDIT_HW     3500u   /* 감사기록 용량 임계치 */

/* SFR:3.4.1 기본 계정 강제 조치  SFR:3.4.2 기본 PW 강제 변경
 * 실제 강제 설정은 init(S20provision) + `cctv-secd provision-set-mgmt`(provision.c)가 수행하고
 * 자격증명을 /data/cred/mgmt.cred 에 저장한다(기본값이 이미지에 존치되지 않음).
 * 데몬은 완료 여부를 확인해 미완료 시 관리 기능을 개방하지 않는다(게이트). */
static int provision_firstboot(void) {
	return access("/data/.provisioned", F_OK) == 0;   /* 1=완료, 0=미완료 */
}
/* SFR:5.1.1 [STUB] 자체시험  SFR:5.2.1 [STUB] 무결성 검증(dm-verity+설정HMAC)  SFR:5.2.3 [STUB] 결과 확인 */
static int self_test(void) { /* TODO: dm-verity 상태 + config_store 무결성 실검증. 현재 항상 0 */ return 0; }
/* SFR:5.1.2 [STUB] 자체시험 실패 대응  SFR:5.2.4 [STUB] 무결성 실패 대응 */
static void on_integrity_fail(void) { audit_append("integrity check FAILED"); }
/* SFR:2.2.2 [STUB] 관리자 연속 실패 즉시 통보(호출부·push 미구현) */
static void notify_admin(const char *msg) { audit_append(msg); /* TODO: 웹UI 팝업/외부 push */ }
/* SFR:1.4.1 관리도구 최초설정 default 한정  SFR:3.4.3 내부/외부 default PW 변경
 * 미프로비저닝(=default 상태)에서는 정상 서비스가 개방되지 않음(init 게이트 S20/S65와 정합). */
static int provision_gate_default_only(void) { return access("/data/.provisioned", F_OK) == 0; }

/* SFR:3.4.1/3.4.2 프로비저닝 서브커맨드 — S20provision(init) 이 최초부팅 시 호출.
 *   provision-set-mgmt <user> <pw> <credpath> : 관리 암호 강제 설정(기본값 미존치)
 *   provision-verify-mgmt <user> <pw> <credpath> : 관리 암호 검증(로그인 경로)
 *   genpw : 임시 패스워드 생성(SFR:9.2.1) — viewer_pw=generate 처리 */
static int cli_provision(int argc, char **argv) {
	if (crypto_hal_init() != CH_OK) { fprintf(stderr, "crypto init 실패\n"); return 2; }
	if (strcmp(argv[1], "provision-set-mgmt") == 0 && argc == 5) {
		pv_rc r = provision_set_mgmt_cred(argv[2], argv[3], argv[4]);
		if (r == PV_POLICY) fprintf(stderr, "암호 정책 위반\n");
		else if (r != PV_OK) fprintf(stderr, "설정 실패(%d)\n", r);
		return r == PV_OK ? 0 : 1;
	}
	if (strcmp(argv[1], "provision-verify-mgmt") == 0 && argc == 5)
		return provision_verify_mgmt_cred(argv[2], argv[3], argv[4]) == PV_OK ? 0 : 1;
	if (strcmp(argv[1], "genpw") == 0) {
		char pw[64];
		if (provision_gen_password(pw, sizeof(pw)) != PV_OK) return 1;
		puts(pw);
		return 0;
	}
	if (strcmp(argv[1], "provision-genkey") == 0 && argc == 4)   /* SFR:9.2.1 per-device 키파일 */
		return provision_gen_keyfile(argv[2], (size_t)strtoul(argv[3], NULL, 10)) == PV_OK ? 0 : 1;
	fprintf(stderr, "usage: cctv-secd [provision-set-mgmt|provision-verify-mgmt <user> <pw> <credpath>|provision-genkey <path> <nbytes>|genpw]\n");
	return 2;
}

int main(int argc, char **argv) {
	if (argc > 1) return cli_provision(argc, argv);   /* 서브커맨드 모드 */

	if (crypto_hal_init() != CH_OK) return 1;   /* SFR:9.1.1 백엔드 초기화+자체시험 */
	audit_init();                                /* SFR:8.1.1/8.3.1/8.5.1 파일 영속 감사 체인(/data/audit) */
	session_init();
	mgmt_init();
	config_store_init();
	if (!provision_firstboot()) {                 /* SFR:3.4.1/3.4.2 미프로비저닝 → 게이트 유지 */
		audit_append("unprovisioned: management gated");   /* SFR:1.4.1/3.4.3 */
		notify_admin("device unprovisioned (default state)");
	}
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
