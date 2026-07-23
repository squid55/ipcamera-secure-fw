# Changelog

이 프로젝트의 주요 변경 사항을 기록합니다.
형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/), 버전은 [SemVer](https://semver.org/lang/ko/)를 따릅니다.

## [Unreleased]
> 아래는 **호스트 검증 완료·main 반영**. 실기(RPi5) 검증은 다음 리플래시에 번들 예정(플랫폼 독립 로직이라 통합 리스크 낮음).
### Added
- **감사기록 파일 영속**(8.1.1): `/data/audit` append-only + fsync, 재부팅 체인 연속, 타임스탬프(8.1.3)
- **per-device 감사/자체시험 키**(8.3.1): 프로비저닝 생성 → 소스 상수 placeholder 탈피
- **감사 회전·아카이브**(8.4.1/8.5.1): 용량/포화 시 검증→아카이브
- **무결성 자체시험**(5.1.1/5.2.1): 핵심파일 매니페스트 HMAC 검증 + 실패 시 서비스 게이트(5.1.2/5.2.4)
- **syslog-over-TLS off-box 전송**(8.3.1): 감사기록 원격 사본 + **관리자 즉시 통보**(2.2.2). RFC5424/5425, 서버 인증서 CA 검증
- `cctv-secd` 서브커맨드: `provision-genkey`, `manifest-gen`
- **커버리지: 구현 49 / 스텁 0 / 미착수 1(8.3.2 선택)** — 필수·조건부 전 항목 실구현
### 후속
- 실기 검증(다음 리플래시 번들) → 검증 후 정식 릴리스(v0.1.4)
- dm-verity(무결성 prevention), 하드웨어 키(SoC), A/B 롤백, RPi5 카메라 브링업(#3)

## [0.1.3] - 2026-07-23
> 실기(RPi5) 검증 완료: 부팅·프로비저닝·RTSPS·TLS·인증. 영상 발행 SW 파이프라인 완비.
> (실제 IMX219 캡처는 카메라 HW 브링업 후속 과제 — 보안 기능과 별개)
### Added
- **최초부팅 프로비저닝(SD 사이드카)**: `provision.conf` 소비 → 관리 암호 강제 설정
  (기본값 미존치, SFR:3.4.1/3.4.2), 영상 계정·TLS 자체서명 발급, 완료 후 파기(shred)
- `crypto_hal_random`(HAL 뒤 CSPRNG, SFR:9.2.1), `provision.c`(salt+PBKDF2 자격 저장/검증)
- `cctv-secd` 서브커맨드: `provision-set-mgmt` / `provision-verify-mgmt` / `genpw`
- 서비스 게이트: 프로비저닝 완료 전 RTSPS 등 정상 서비스 차단(fail-closed)
- 영상 발행 파이프라인: x264(소프트 H.264) + gst h264parse/rtspclientsink/rtp
- `openssl` CLI(`BR2_PACKAGE_LIBOPENSSL_BIN`) — 인증서 생성에 필요
- CI(GitHub Actions)·SECURITY.md·CHANGELOG·이슈/PR 템플릿·Dependabot(저장소 위생)
### Changed
- **D0 스테핑 대응 `config.txt`를 부트 파티션에 내장**(`device_tree=bcm2712d0-rpi-5-b.dtb`)
  → SD 수동 편집 없이 부팅
- `mediamtx.yml` 설정 키를 v1.9.3 스키마로(`encryption`/`serverCert`/`protocols`)
- 프로비저닝 인증서 유효기간 확대(-days 36500) — epoch 시계 만료 회피(SFR:8.1.3 후속)
### Fixed
- `S30nftables` 실행권한(644→755) — 부팅 시 방화벽 로드(3.3.1 fail-open 수정)
- 실기 통합버그 3건(openssl CLI 미설치, mediamtx 설정 키, gst 파이프라인 요소 부재)

## [0.1.2-headless] - 2026-07-22
### Fixed
- `eth0`/`end0` 둘 다 DHCP 설정(RP1 NIC 이름 대응)

## [0.1.1-headless] - 2026-07-22
### Added
- `admin` 사용자 + SSH 키 인증 헤드리스 접속, 호스트명 `ipcam`

## [0.1.0-prototype] - 2026-07-21
### Added
- RPi5 + IMX219 최초 부팅 이미지, 보안 데몬·crypto HAL·하드닝 골격

[Unreleased]: https://github.com/squid55/ipcamera-secure-fw/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/squid55/ipcamera-secure-fw/releases/tag/v0.1.3
[0.1.2-headless]: https://github.com/squid55/ipcamera-secure-fw/releases/tag/v0.1.2-headless
[0.1.1-headless]: https://github.com/squid55/ipcamera-secure-fw/releases/tag/v0.1.1-headless
[0.1.0-prototype]: https://github.com/squid55/ipcamera-secure-fw/releases/tag/v0.1.0-prototype
