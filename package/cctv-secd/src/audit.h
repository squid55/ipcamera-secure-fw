/* audit.h — 감사기록 (append-only HMAC 해시체인, 위변조 탐지) */
#ifndef AUDIT_H
#define AUDIT_H
#include <stdbool.h>
#include <stddef.h>

/* 영속 저장 디렉터리 지정(기본 /data/audit). audit_init 전에 호출. 테스트/구성용. */
void   audit_set_dir(const char *dir);
/* SFR:8.3.1 off-box 전송 훅(예: syslog-TLS). audit_append 시 포맷된 라인을 best-effort 전달. */
void   audit_set_forward(int (*fn)(const char *line));
int    audit_init(void);                 /* SFR:8.1.1 파일 영속 로드(있으면 체인 이어감) */
int    audit_append(const char *event);  /* SFR:8.3.1 append-only + 체인. 실패 시 -1(fail-closed) */
bool   audit_verify(void);               /* 체인 무결성 검증 */
size_t audit_count(void);

/* SFR:8.2.1 조회 / SFR:8.2.2 substr 필터 + seq 정렬(ascending!=0 오름차순).
 * 매칭 레코드 인덱스를 idx_out(최대 max개)에 채우고, 반환=idx_out에 담긴 개수(<=max) */
size_t audit_query(const char *substr, int ascending, size_t *idx_out, size_t max);
/* SFR:8.4.1/8.5.1: count가 high_water 이상이면 (아카이브 후) 세그먼트 회전(반환 1).
 * 회전 시 직전 세그먼트 최종 MAC을 새 제네시스 prev로 이어 체인 연속성 유지. */
int    audit_capacity_guard(size_t high_water);

#ifdef AUDIT_TEST
/* 테스트 전용(양산 빌드 미포함): 저장된 레코드의 event 변조 */
void   audit_test_tamper(size_t idx, const char *new_event);
#endif

#endif
