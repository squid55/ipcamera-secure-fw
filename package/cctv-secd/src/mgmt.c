/* mgmt.c — 보안 관리 RBAC 실구현 (인가 게이트 포함) */
#include "mgmt.h"
#include <string.h>

#define MAX_USERS 8

struct role_ent { char name[32]; role_t role; bool used; };
static struct role_ent roles[MAX_USERS];
/* 하드닝 기본값: 원격 관리접속(SSH·웹)은 default-off, 프로비저닝 후 명시적 개방(SFR:3.2.1) */
static bool svc_enabled[SVC_COUNT];

void mgmt_init(void) {
	memset(roles, 0, sizeof(roles));
	svc_enabled[SVC_SSH] = false; svc_enabled[SVC_WEB] = false; svc_enabled[SVC_ONVIF] = false;
}

static struct role_ent *find_role(const char *user) {
	for (int i = 0; i < MAX_USERS; i++)
		if (roles[i].used && strcmp(roles[i].name, user) == 0) return &roles[i];
	return NULL;
}
static bool any_admin(void) {
	for (int i = 0; i < MAX_USERS; i++)
		if (roles[i].used && roles[i].role == ROLE_ADMIN) return true;
	return false;
}
static bool set_role_internal(const char *user, role_t r) {
	struct role_ent *e = find_role(user);
	if (e) { e->role = r; return true; }
	for (int i = 0; i < MAX_USERS; i++)
		if (!roles[i].used) {
			roles[i].used = true; roles[i].role = r;
			strncpy(roles[i].name, user, sizeof(roles[i].name) - 1);
			roles[i].name[sizeof(roles[i].name) - 1] = '\0';
			return true;
		}
	return false;
}

/* SFR:3.1.1 최초 ADMIN은 ADMIN 부재 시에만 시딩(부트스트랩 승격 벡터 차단) */
bool mgmt_bootstrap_admin(const char *user) {
	if (!user || any_admin()) return false;
	return set_role_internal(user, ROLE_ADMIN);
}

/* SFR:3.1.1 인가된 ADMIN(actor)만 역할 변경 */
bool mgmt_set_role(const char *actor, const char *target, role_t r) {
	if (!actor || !target || !mgmt_can_manage(actor)) return false;
	return set_role_internal(target, r);
}

role_t mgmt_role(const char *user) {
	struct role_ent *e = user ? find_role(user) : NULL;
	return e ? e->role : ROLE_NONE;
}
bool mgmt_can_manage(const char *user) { return mgmt_role(user) == ROLE_ADMIN; }

bool mgmt_service_enabled(svc_t s) {
	return ((unsigned)s < SVC_COUNT) ? svc_enabled[s] : false;
}
bool mgmt_service_set(const char *actor, svc_t s, bool on) {
	if (!mgmt_can_manage(actor)) return false;   /* SFR:3.2.1 ADMIN 게이트 */
	if ((unsigned)s >= SVC_COUNT) return false;
	svc_enabled[s] = on;
	return true;
}
