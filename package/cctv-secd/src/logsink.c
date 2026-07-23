/* logsink.c — syslog-over-TLS(RFC5425) off-box 전송 구현 (OpenSSL libssl) */
#include "logsink.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAC_AUDIT   13          /* log audit facility */
#define SEV_NOTICE  5
#define SEV_ALERT   1

static int   enabled = 0;
static char  g_host[128], g_port[16], g_ca[256];
static SSL_CTX *ctx;
static SSL   *ssl;
static int    sock = -1;

static void parse_conf(const char *path) {
	FILE *f = fopen(path, "r");
	if (!f) return;
	char line[300];
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = 0;
		char *eq = strchr(line, '=');
		if (!eq) continue;
		*eq = 0;
		const char *k = line, *v = eq + 1;
		if (!strcmp(k, "host")) snprintf(g_host, sizeof(g_host), "%s", v);
		else if (!strcmp(k, "port")) snprintf(g_port, sizeof(g_port), "%s", v);
		else if (!strcmp(k, "ca")) snprintf(g_ca, sizeof(g_ca), "%s", v);
	}
	fclose(f);
}

void logsink_init(const char *conf_path) {
	enabled = 0;
	g_host[0] = g_port[0] = g_ca[0] = 0;
	parse_conf(conf_path);
	if (!g_host[0]) return;                       /* 미설정 → 비활성 */
	if (!g_port[0]) snprintf(g_port, sizeof(g_port), "6514");   /* RFC5425 기본 포트 */

	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) return;
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);         /* 1순위: TLS1.2+ */
	if (g_ca[0]) {
		if (SSL_CTX_load_verify_locations(ctx, g_ca, NULL) == 1)
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);    /* 서버 인증서 검증 */
	}
	enabled = 1;
}

int logsink_enabled(void) { return enabled; }

static void disconnect(void) {
	if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
	if (sock >= 0) { close(sock); sock = -1; }
}

static int connect_tls(void) {
	if (ssl) return 0;                            /* 이미 연결 */
	struct addrinfo hints, *res = NULL, *rp;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(g_host, g_port, &hints, &res) != 0) return -1;
	for (rp = res; rp; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0) continue;
		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
		close(sock); sock = -1;
	}
	freeaddrinfo(res);
	if (sock < 0) return -1;

	ssl = SSL_new(ctx);
	if (!ssl) { close(sock); sock = -1; return -1; }
	SSL_set_fd(ssl, sock);
	SSL_set_tlsext_host_name(ssl, g_host);
	if (SSL_connect(ssl) != 1) { disconnect(); return -1; }
	if (g_ca[0] && SSL_get_verify_result(ssl) != X509_V_OK) { disconnect(); return -1; }
	return 0;
}

/* RFC5424 메시지 + RFC5425 octet-counting 프레이밍으로 전송 */
static int send_sev(const char *msg, int sev) {
	if (!enabled || !msg) return -1;
	int pri = FAC_AUDIT * 8 + sev;

	char host[64];
	if (gethostname(host, sizeof(host)) != 0) snprintf(host, sizeof(host), "ipcam");
	host[sizeof(host)-1] = 0;

	char ts[32];
	time_t now = time(NULL);
	struct tm tmv;
	gmtime_r(&now, &tmv);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);

	/* <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG */
	char syslog_msg[600];
	int n = snprintf(syslog_msg, sizeof(syslog_msg),
	                 "<%d>1 %s %s cctv-secd - %s - %s",
	                 pri, ts, host, sev == SEV_ALERT ? "alert" : "audit", msg);
	if (n < 0) return -1;
	if (n >= (int)sizeof(syslog_msg)) n = sizeof(syslog_msg) - 1;

	char frame[700];
	int fn = snprintf(frame, sizeof(frame), "%d %s", n, syslog_msg);   /* octet-counting */
	if (fn < 0 || fn >= (int)sizeof(frame)) return -1;

	for (int attempt = 0; attempt < 2; attempt++) {     /* 끊겼으면 1회 재연결 */
		if (connect_tls() != 0) return -1;
		if (SSL_write(ssl, frame, fn) == fn) return 0;
		disconnect();                                    /* 실패 → 끊고 재시도 */
	}
	return -1;
}

int logsink_send(const char *msg)  { return send_sev(msg, SEV_NOTICE); }
int logsink_alert(const char *msg) { return send_sev(msg, SEV_ALERT); }

void logsink_close(void) {
	disconnect();
	if (ctx) { SSL_CTX_free(ctx); ctx = NULL; }
	enabled = 0;
}
