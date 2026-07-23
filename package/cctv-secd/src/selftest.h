/* selftest.h — 무결성 자체시험 (파일 매니페스트 HMAC, 플랫폼 독립·호스트 테스트 가능)
 *
 * SFR:5.1.1 자체시험  SFR:5.2.1 제품·설정 무결성 검증  SFR:5.2.3 결과 확인
 * 프로비저닝이 핵심 파일의 HMAC 매니페스트를 per-device 키로 생성하고,
 * 부팅 시 재계산·대조하여 무단 변경을 탐지한다.
 *
 * [한계] 키가 하드웨어 신뢰루트가 아니라 /data(root 600)라, root 공격자는 매니페스트를
 *   재생성 가능. 오프라인/비인가 변경 탐지에 유효하며, 완전한 무결성 강제(prevention)는
 *   dm-verity(읽기전용 root + 하드웨어 앵커, 후속)로 이관한다.
 */
#ifndef SELFTEST_H
#define SELFTEST_H

/* HMAC 키파일 경로 지정(기본 /data/cred/selftest.key). 테스트/구성용. */
void selftest_set_keyfile(const char *path);

/* 매니페스트(<path>|<hmac_hex> 줄들)의 각 파일 HMAC 을 재계산·대조.
 * 반환 0=전부 무결, >0=불일치/누락 파일 수, -1=오류(키/HMAC/매니페스트 없음 — fail-closed). */
int  selftest_verify(const char *manifest_path);

/* 매니페스트 생성: paths[] 각 파일의 HMAC 을 계산해 manifest_path 에 0600 원자적 기록.
 * 반환 0=성공, -1=실패. (프로비저닝 시 1회) */
int  selftest_gen(const char *manifest_path, const char *const *paths, int npaths);

#endif
