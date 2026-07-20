/* mgmt.c — 보안 관리 RBAC 실구현 */
#include "mgmt.h"
#include <string.h>

#define MAX_USERS 8

struct role_ent { char name[32]; role_t role; bool used; };
static struct role_ent roles[MAX_USERS];
static bool svc_enabled[SVC_COUNT] = { true, true, false };  /* 기본: SSH·웹 on, ONVIF off */

void mgmt_init(void) {
	memset(roles, 0, sizeof(roles));
	svc_enabled[SVC_SSH] = true; svc_enabled[SVC_WEB] = true; svc_enabled[SVC_ONVIF] = false;
}

void mgmt_set_role(const char *user, role_t r) {
	for (int i = 0; i < MAX_USERS; i++)
		if (roles[i].used && strcmp(roles[i].name, user) == 0) { roles[i].role = r; return; }
	for (int i = 0; i < MAX_USERS; i++)
		if (!roles[i].used) {
			roles[i].used = true; roles[i].role = r;
			strncpy(roles[i].name, user, sizeof(roles[i].name) - 1);
			roles[i].name[sizeof(roles[i].name)-1] = '\0';
			return;
		}
}

role_t mgmt_role(const char *user) {
	for (int i = 0; i < MAX_USERS; i++)
		if (roles[i].used && strcmp(roles[i].name, user) == 0) return roles[i].role;
	return ROLE_NONE;
}

bool mgmt_can_manage(const char *user) { return mgmt_role(user) == ROLE_ADMIN; }  /* SFR:3.1.1 */

bool mgmt_service_enabled(svc_t s) {
	return (s >= 0 && s < SVC_COUNT) ? svc_enabled[s] : false;
}

bool mgmt_service_set(const char *user, svc_t s, bool on) {
	if (!mgmt_can_manage(user)) return false;          /* SFR:3.2.1 ADMIN 게이트 */
	if (s < 0 || s >= SVC_COUNT) return false;
	svc_enabled[s] = on;
	return true;
}
