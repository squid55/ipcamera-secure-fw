/* provision.h — 최초 부팅 프로비저닝 핵심 (플랫폼 독립, 호스트 테스트 가능)
 *
 * 관리 자격증명(관리 인터페이스 암호)을 정책검사 후 salt+PBKDF2 로 해시하여
 * 쓰기가능 데이터 파티션에 저장/검증한다. OS 로그인 암호(/etc/shadow)가 아니라
 * 앱 계층 관리 암호 — SSH 셸 접근은 키 인증으로 분리(읽기전용 root 대응).
 *
 * SFR:3.4.1/3.4.2 기본 계정·PW 강제 변경(기본값이 이미지에 존치되지 않음)
 * SFR:2.3.1 암호 정책  SFR:9.2.1 안전 난수(salt·임시PW)
 */
#ifndef PROVISION_H
#define PROVISION_H
#include <stddef.h>

typedef enum { PV_OK = 0, PV_POLICY, PV_IO, PV_ERR, PV_MISMATCH } pv_rc;

/* 관리 자격증명 설정: 정책검사(password_set 재사용) → salt 난수 → PBKDF2 해시 →
 * "v1:<user>:<salt_hex>:<hash_hex>" 를 path 에 0600 원자적 기록. */
pv_rc provision_set_mgmt_cred(const char *user, const char *pw, const char *path);

/* 관리 자격증명 검증: path 에서 salt/해시 복원 → 재계산 → 상수시간 비교. */
pv_rc provision_verify_mgmt_cred(const char *user, const char *pw, const char *path);

/* 임시 패스워드 생성(viewer_pw=generate 등). out 에 16진 문자열(널종단).
 * outsz 는 (2*요청바이트 + 1) 이상. 기본 24hex(=12바이트 엔트로피). */
pv_rc provision_gen_password(char *out, size_t outsz);

/* 랜덤 바이트 키파일 생성(감사 체인 키 등). 0600 원자적 기록. nbytes<=64. SFR:9.2.1
 * per-device 키로 소스 상수 placeholder 를 탈피 → 감사 위변조 탐지(8.3.1) 실효 향상. */
pv_rc provision_gen_keyfile(const char *path, size_t nbytes);

#endif
