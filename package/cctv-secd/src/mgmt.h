/* mgmt.h — 보안 관리 RBAC + 관리접속 토글 (플랫폼 독립) */
#ifndef MGMT_H
#define MGMT_H
#include <stdbool.h>

typedef enum { ROLE_NONE = 0, ROLE_VIEWER, ROLE_OPERATOR, ROLE_ADMIN } role_t;
typedef enum { SVC_SSH = 0, SVC_WEB, SVC_ONVIF, SVC_COUNT } svc_t;

void   mgmt_init(void);
void   mgmt_set_role(const char *user, role_t r);
role_t mgmt_role(const char *user);
/* SFR:3.1.1 인가된 관리자(ADMIN)만 보안기능·정책·중요데이터 관리 */
bool   mgmt_can_manage(const char *user);
bool   mgmt_service_enabled(svc_t s);
/* SFR:3.2.1 관리접속(SSH·웹·ONVIF) 개별 활성/비활성 — ADMIN만 변경 가능 */
bool   mgmt_service_set(const char *user, svc_t s, bool on);

#endif
