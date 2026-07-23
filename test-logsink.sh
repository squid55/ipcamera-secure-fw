#!/bin/sh
# logsink(syslog-over-TLS) end-to-end 검증:
#   로컬 TLS 수신기(python ssl)를 띄우고, logsink 로 메시지를 보내 수신 확인.
# 사용: ./test-logsink.sh   (openssl, gcc, libssl-dev, python3 필요)
set -e
cd "$(dirname "$0")"
SD=package/cctv-secd
PORT=16514
OUT=$(mktemp -d)
trap 'kill "$SRV_PID" 2>/dev/null; rm -rf "$OUT"' EXIT

echo "== 1) 수신기 인증서 생성 =="
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	-keyout "$OUT/srv.key" -out "$OUT/srv.crt" -subj "/CN=localhost" >/dev/null 2>&1

echo "== 2) TLS syslog 수신기 기동(python ssl :$PORT) =="
cat > "$OUT/recv.py" <<'PYEOF'
import socket, ssl, sys
cert, key, port, outf = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', port)); srv.listen(5)
out = open(outf, 'ab', buffering=0)
while True:
    try:
        c, _ = srv.accept()
        s = ctx.wrap_socket(c, server_side=True)
        while True:
            d = s.recv(65536)
            if not d: break
            out.write(d)
        s.close()
    except Exception:
        pass
PYEOF
python3 "$OUT/recv.py" "$OUT/srv.crt" "$OUT/srv.key" "$PORT" "$OUT/received.log" &
SRV_PID=$!
sleep 0.5   # 바인드 대기

echo "== 3) logsink 설정 + 테스트 송신기 빌드 =="
printf 'host=127.0.0.1\nport=%s\nca=%s\n' "$PORT" "$OUT/srv.crt" > "$OUT/logsink.conf"
cat > "$OUT/tsend.c" <<'EOF'
#include "logsink.h"
#include <stdio.h>
int main(int argc, char **argv) {
	(void)argc;
	logsink_init(argv[1]);
	if (!logsink_enabled()) { fprintf(stderr, "logsink 비활성\n"); return 2; }
	if (logsink_send("audit-test-event seq=1") != 0) { fprintf(stderr, "send 실패\n"); return 1; }
	if (logsink_alert("LOCKOUT admin notify") != 0) { fprintf(stderr, "alert 실패\n"); return 1; }
	logsink_close();
	printf("sent ok\n");
	return 0;
}
EOF
gcc -Wall -I "$SD/src" "$OUT/tsend.c" "$SD/src/logsink.c" -lssl -lcrypto -o "$OUT/tsend"

echo "== 4) 송신(최대 5회 재시도) =="
ok=0
for i in 1 2 3 4 5; do
	if "$OUT/tsend" "$OUT/logsink.conf"; then ok=1; break; fi
	sleep 0.3
done
[ $ok -eq 1 ] || { echo "송신 실패"; exit 1; }
sleep 0.3   # 수신 flush 대기

echo "== 5) 수신 확인(TLS 복호화된 RFC5424 메시지) =="
FAILS=0
check() { if grep -q "$1" "$OUT/received.log" 2>/dev/null; then echo "  ok: $2"; else echo "  FAIL: $2"; FAILS=$((FAILS+1)); fi; }
check "audit-test-event seq=1" "감사 이벤트 수신(8.3.1 off-box)"
check "LOCKOUT admin notify"    "관리자 통보 수신(2.2.2)"
check "cctv-secd"               "RFC5424 APP-NAME 포함"
check "alert"                   "통보 severity(alert) MSGID"

echo
[ $FAILS -eq 0 ] && echo "== logsink TLS 전송 검증 통과 ==" || { echo "== 실패 $FAILS =="; echo "--- received.log ---"; cat "$OUT/received.log"; exit 1; }
