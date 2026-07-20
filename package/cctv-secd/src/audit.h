/* audit.h — 감사기록 (append-only HMAC 해시체인, 위변조 탐지) */
#ifndef AUDIT_H
#define AUDIT_H
#include <stdbool.h>
#include <stddef.h>

int    audit_init(void);                 /* SFR:8.1.1 */
int    audit_append(const char *event);  /* SFR:8.3.1 append-only + 체인 */
bool   audit_verify(void);               /* 체인 무결성 검증 */
size_t audit_count(void);

/* SFR:8.2.1 조회 / SFR:8.2.2 substr 필터 + seq 정렬(ascending!=0 오름차순).
 * 매칭 레코드 인덱스를 idx_out(최대 max개)에 채우고 매칭 수 반환 */
size_t audit_query(const char *substr, int ascending, size_t *idx_out, size_t max);
/* SFR:8.4.1 용량 도달 대응 / SFR:8.5.1 포화 대응:
 * count가 high_water 이상이면 아카이브 후 체인 회전(반환 1), 아니면 0 */
int    audit_capacity_guard(size_t high_water);

/* 테스트 전용: 저장된 레코드의 event 를 임의 변조 */
void   audit_test_tamper(size_t idx, const char *new_event);

#endif
