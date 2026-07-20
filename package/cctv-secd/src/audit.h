/* audit.h — 감사기록 (append-only HMAC 해시체인, 위변조 탐지) */
#ifndef AUDIT_H
#define AUDIT_H
#include <stdbool.h>
#include <stddef.h>

int    audit_init(void);                 /* SFR:8.1.1 */
int    audit_append(const char *event);  /* SFR:8.3.1 append-only + 체인 */
bool   audit_verify(void);               /* 체인 무결성 검증 */
size_t audit_count(void);

/* 테스트 전용: 저장된 레코드의 event 를 임의 변조 */
void   audit_test_tamper(size_t idx, const char *new_event);

#endif
