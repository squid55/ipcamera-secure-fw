# RAUC keyring

`system.conf`의 `keyring.pem`은 **서명 번들 검증용 공개 인증서**다(SFR:6.1.1).

- **개인키·실제 인증서는 저장소에 커밋하지 않는다.** 빌드/프로비저닝 단계에서 주입한다.
- 개발용 생성 예:
  ```bash
  openssl req -x509 -newkey rsa:4096 -keyout dev-key.pem -out keyring.pem -days 3650 -nodes
  # keyring.pem(공개 인증서)만 이미지에 포함, dev-key.pem(서명 개인키)은 빌드 서버 보관
  ```
- 업데이트 번들은 이 개인키로 서명(`rauc bundle`), 기기는 `keyring.pem`으로 검증 후에만 설치한다.
