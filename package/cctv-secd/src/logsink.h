/* logsink.h — syslog-over-TLS(RFC5425) off-box 전송
 *
 * 원격 로그서버(SIEM)로 TLS 연결해 RFC5424 메시지를 보낸다.
 * SFR:8.3.1 감사기록 off-box 사본(로컬 삭제·변경에도 원격 보존)
 * SFR:2.2.2 관리자 즉시 통보(연속 인증실패·무결성 실패)
 * 1순위: 암호통신은 표준 프로토콜(TLS)만 — 서버 인증서를 CA 로 검증.
 *
 * 미설정 시 no-op(graceful). 전송은 best-effort(로컬 영속 감사가 주 저장).
 */
#ifndef LOGSINK_H
#define LOGSINK_H

/* 설정파일(host=..\nport=..\nca=..) 로드. 없거나 host 미지정이면 비활성. */
void logsink_init(const char *conf_path);
int  logsink_enabled(void);
/* 감사 이벤트 전송(severity=notice). 0=성공, -1=실패/비활성(best-effort). */
int  logsink_send(const char *msg);
/* 관리자 통보 전송(severity=alert). */
int  logsink_alert(const char *msg);
void logsink_close(void);

#endif
