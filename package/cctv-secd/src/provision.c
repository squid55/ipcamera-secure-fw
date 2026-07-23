/* provision.c — 최초 부팅 프로비저닝 핵심 구현 (플랫폼 독립) */
#include "provision.h"
#include "auth.h"
#include "crypto_hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>   /* chmod */

#define PV_SALT_LEN   16
#define PV_HASH_LEN   32
#define PV_ITERS      100000u   /* PBKDF2-HMAC-SHA256 반복(장비 응답성/강도 절충) */
#define PV_PW_MAXLEN  64        /* HMAC 키 길이 상한과 정합 */

/* ---- 16진 인코딩/디코딩 ---- */
static void tohex(const uint8_t *in, size_t n, char *out) {
	static const char h[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[2*i] = h[in[i] >> 4]; out[2*i+1] = h[in[i] & 15]; }
	out[2*n] = 0;
}
static int hexv(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}
static int fromhex(const char *s, uint8_t *out, size_t n) {
	for (size_t i = 0; i < n; i++) {
		int hi = hexv(s[2*i]), lo = hexv(s[2*i+1]);
		if (hi < 0 || lo < 0) return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

/* 상수시간 비교(타이밍 사이드채널 차단) */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
	uint8_t r = 0;
	for (size_t i = 0; i < n; i++) r |= (uint8_t)(a[i] ^ b[i]);
	return r == 0;
}

/* PBKDF2-HMAC-SHA256 (dkLen=32, 1블록). 암호를 HMAC 키로 삼아 salt||INT(1) 반복. */
static int pv_pbkdf2(const char *pw, const uint8_t *salt, size_t saltlen,
                     uint32_t iters, uint8_t out[PV_HASH_LEN]) {
	if (strlen(pw) > PV_PW_MAXLEN) return -1;
	ch_key *k = NULL;
	if (crypto_hal_key_import((const uint8_t *)pw, strlen(pw), &k) != CH_OK) return -1;

	uint8_t block[PV_SALT_LEN + 4];
	if (saltlen > PV_SALT_LEN) { crypto_hal_key_destroy(k); return -1; }
	memcpy(block, salt, saltlen);
	block[saltlen+0] = 0; block[saltlen+1] = 0; block[saltlen+2] = 0; block[saltlen+3] = 1;

	uint8_t u[64]; size_t ul = 0;
	uint8_t t[PV_HASH_LEN];
	int rc = -1;
	if (crypto_hal_hmac(CH_HASH_SHA256, k, block, saltlen+4, u, &ul) != CH_OK || ul != PV_HASH_LEN)
		goto out;
	memcpy(t, u, PV_HASH_LEN);
	for (uint32_t i = 1; i < iters; i++) {
		if (crypto_hal_hmac(CH_HASH_SHA256, k, u, PV_HASH_LEN, u, &ul) != CH_OK || ul != PV_HASH_LEN)
			goto out;
		for (int j = 0; j < PV_HASH_LEN; j++) t[j] ^= u[j];
	}
	memcpy(out, t, PV_HASH_LEN);
	rc = 0;
out:
	memset(u, 0, sizeof(u));
	memset(t, 0, sizeof(t));
	crypto_hal_key_destroy(k);
	return rc;
}

pv_rc provision_set_mgmt_cred(const char *user, const char *pw, const char *path) {
	if (!user || !pw || !path) return PV_ERR;
	if (strlen(pw) > PV_PW_MAXLEN) return PV_POLICY;
	/* SFR:2.3.1/2.4.1 정책·사용자명포함·복잡도 검사(auth 로직 재사용) */
	if (password_set(user, pw) != PW_OK) return PV_POLICY;

	uint8_t salt[PV_SALT_LEN], hash[PV_HASH_LEN];
	if (crypto_hal_random(salt, sizeof(salt)) != CH_OK) return PV_ERR;   /* SFR:9.2.1 */
	if (pv_pbkdf2(pw, salt, sizeof(salt), PV_ITERS, hash) != 0) return PV_ERR;

	char salthex[2*PV_SALT_LEN + 1], hashhex[2*PV_HASH_LEN + 1];
	tohex(salt, sizeof(salt), salthex);
	tohex(hash, sizeof(hash), hashhex);

	/* 원자적 기록: tmp 에 쓰고 rename */
	char tmp[512];
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return PV_IO;
	FILE *f = fopen(tmp, "w");
	if (!f) return PV_IO;
	int w = fprintf(f, "v1:%s:%s:%s\n", user, salthex, hashhex);
	if (fclose(f) != 0 || w < 0) { remove(tmp); return PV_IO; }
	if (chmod(tmp, 0600) != 0) { remove(tmp); return PV_IO; }
	if (rename(tmp, path) != 0) { remove(tmp); return PV_IO; }

	memset(hash, 0, sizeof(hash));
	return PV_OK;
}

pv_rc provision_verify_mgmt_cred(const char *user, const char *pw, const char *path) {
	if (!user || !pw || !path) return PV_ERR;
	FILE *f = fopen(path, "r");
	if (!f) return PV_IO;
	char line[512];
	char *ok = fgets(line, sizeof(line), f);
	fclose(f);
	if (!ok) return PV_IO;

	/* "v1:<user>:<salt_hex>:<hash_hex>" 파싱 */
	if (strncmp(line, "v1:", 3) != 0) return PV_ERR;
	char *p = line + 3;
	char *c1 = strchr(p, ':');       if (!c1) return PV_ERR;
	char *c2 = strchr(c1 + 1, ':');  if (!c2) return PV_ERR;
	*c1 = 0;
	size_t saltlen_hex = (size_t)(c2 - (c1 + 1));
	char *hashhex = c2 + 1;
	hashhex[strcspn(hashhex, "\r\n")] = 0;

	if (strcmp(p, user) != 0) return PV_MISMATCH;                 /* 사용자 불일치 */
	if (saltlen_hex != 2*PV_SALT_LEN) return PV_ERR;
	if (strlen(hashhex) != 2*PV_HASH_LEN) return PV_ERR;

	uint8_t salt[PV_SALT_LEN], stored[PV_HASH_LEN], calc[PV_HASH_LEN];
	if (fromhex(c1 + 1, salt, PV_SALT_LEN) != 0) return PV_ERR;
	if (fromhex(hashhex, stored, PV_HASH_LEN) != 0) return PV_ERR;
	if (pv_pbkdf2(pw, salt, sizeof(salt), PV_ITERS, calc) != 0) return PV_ERR;

	int eq = ct_eq(calc, stored, PV_HASH_LEN);
	memset(calc, 0, sizeof(calc));
	memset(stored, 0, sizeof(stored));
	return eq ? PV_OK : PV_MISMATCH;
}

pv_rc provision_gen_password(char *out, size_t outsz) {
	if (!out || outsz < 25) return PV_ERR;   /* 24hex + NUL */
	uint8_t raw[12];
	if (crypto_hal_random(raw, sizeof(raw)) != CH_OK) return PV_ERR;   /* SFR:9.2.1 */
	tohex(raw, sizeof(raw), out);
	memset(raw, 0, sizeof(raw));
	return PV_OK;
}

pv_rc provision_gen_keyfile(const char *path, size_t nbytes) {
	if (!path || nbytes == 0 || nbytes > 64) return PV_ERR;
	uint8_t buf[64];
	if (crypto_hal_random(buf, nbytes) != CH_OK) return PV_ERR;   /* SFR:9.2.1 */

	char tmp[512];
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) { memset(buf,0,sizeof(buf)); return PV_IO; }
	FILE *f = fopen(tmp, "wb");
	if (!f) { memset(buf, 0, sizeof(buf)); return PV_IO; }
	size_t w = fwrite(buf, 1, nbytes, f);
	memset(buf, 0, sizeof(buf));
	if (fclose(f) != 0 || w != nbytes) { remove(tmp); return PV_IO; }
	if (chmod(tmp, 0600) != 0) { remove(tmp); return PV_IO; }
	if (rename(tmp, path) != 0) { remove(tmp); return PV_IO; }
	return PV_OK;
}
