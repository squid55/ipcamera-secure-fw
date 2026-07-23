/* selftest.c — 무결성 자체시험 구현 (파일 매니페스트 HMAC) */
#include "selftest.h"
#include "crypto_hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define MAC_LEN     32
#define LINE_MAX    600
#define FILE_CAP    (64u * 1024 * 1024)   /* 파일 1개 최대 64MB(메모리 로드 상한) */

static char keyfile[256] = "/data/cred/selftest.key";

void selftest_set_keyfile(const char *path) {
	if (path) snprintf(keyfile, sizeof(keyfile), "%s", path);
}

static void tohex(const uint8_t *in, size_t n, char *out) {
	static const char h[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[2*i] = h[in[i] >> 4]; out[2*i+1] = h[in[i] & 15]; }
	out[2*n] = 0;
}
static int ct_eq(const char *a, const char *b, size_t n) {
	uint8_t r = 0; for (size_t i = 0; i < n; i++) r |= (uint8_t)(a[i] ^ b[i]); return r == 0;
}

static ch_key *st_key(void) {
	static ch_key *k = NULL;
	if (k) return k;
	uint8_t kb[32];
	FILE *kf = fopen(keyfile, "rb");
	if (kf) {
		size_t rd = fread(kb, 1, sizeof(kb), kf);
		fclose(kf);
		if (rd == sizeof(kb)) { crypto_hal_key_import(kb, 32, &k); return k; }
	}
	static const uint8_t ph[32] = "cctv-selftest-key-placeholder!!!";
	crypto_hal_key_import(ph, 32, &k);
	return k;
}

/* 파일 내용 HMAC → out_hex(2*MAC_LEN+1). 0=성공, -1=실패(없음/과대/HMAC오류) */
static int file_hmac_hex(const char *path, char *out_hex) {
	FILE *f = fopen(path, "rb");
	if (!f) return -1;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
	long sz = ftell(f);
	if (sz < 0 || (unsigned long)sz > FILE_CAP) { fclose(f); return -1; }
	rewind(f);
	uint8_t *buf = malloc((size_t)sz ? (size_t)sz : 1);
	if (!buf) { fclose(f); return -1; }
	size_t rd = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	if (rd != (size_t)sz) { free(buf); return -1; }

	ch_key *k = st_key();
	uint8_t mac[MAC_LEN]; size_t ml = 0;
	int rc = (k && crypto_hal_hmac(CH_HASH_SHA256, k, buf, (size_t)sz, mac, &ml) == CH_OK && ml == MAC_LEN) ? 0 : -1;
	free(buf);
	if (rc != 0) return -1;
	tohex(mac, MAC_LEN, out_hex);
	return 0;
}

int selftest_verify(const char *manifest_path) {
	FILE *m = fopen(manifest_path, "r");
	if (!m) return -1;                         /* 매니페스트 없음 → fail-closed */
	char line[LINE_MAX];
	int fails = 0, seen = 0;
	while (fgets(line, sizeof(line), m)) {
		line[strcspn(line, "\r\n")] = 0;
		if (!line[0]) continue;
		char *bar = strrchr(line, '|');
		if (!bar) { fails++; continue; }
		*bar = 0;
		const char *want = bar + 1;
		if (strlen(want) != 2*MAC_LEN) { fails++; continue; }
		seen++;
		char got[2*MAC_LEN + 1];
		if (file_hmac_hex(line, got) != 0) { fails++; continue; }   /* 파일 없음/오류 */
		if (!ct_eq(got, want, 2*MAC_LEN)) fails++;                  /* 변경 탐지 */
	}
	fclose(m);
	if (seen == 0) return -1;                  /* 빈 매니페스트 → 오류 */
	return fails;
}

int selftest_gen(const char *manifest_path, const char *const *paths, int npaths) {
	if (!manifest_path || npaths <= 0) return -1;
	char tmp[512];
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", manifest_path) >= (int)sizeof(tmp)) return -1;
	FILE *f = fopen(tmp, "w");
	if (!f) return -1;
	int written = 0;
	for (int i = 0; i < npaths; i++) {
		char hex[2*MAC_LEN + 1];
		if (file_hmac_hex(paths[i], hex) != 0) continue;   /* 없는 파일은 건너뜀(견고) */
		if (fprintf(f, "%s|%s\n", paths[i], hex) < 0) { fclose(f); remove(tmp); return -1; }
		written++;
	}
	if (fclose(f) != 0) { remove(tmp); return -1; }
	if (written == 0) { remove(tmp); return -1; }          /* 하나도 없으면 실패 */
	if (chmod(tmp, 0600) != 0) { remove(tmp); return -1; }
	if (rename(tmp, manifest_path) != 0) { remove(tmp); return -1; }
	return 0;
}
