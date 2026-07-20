# ipcamera-secure-fw

> 라즈베리파이 5 + IMX219 기반 **보안 IP카메라 펌웨어** 이미지 빌드 트리입니다.
> 국정원 **보안기능확인서**(영상정보처리기기 IP카메라 보안요구사항 53항목) 대응을 목표로 합니다.

![platform](https://img.shields.io/badge/platform-RaspberryPi%205-c51a4a)
![base](https://img.shields.io/badge/base-Buildroot-blue)
![sensor](https://img.shields.io/badge/sensor-IMX219-informational)
![status](https://img.shields.io/badge/status-WIP-yellow)

2027년 4월부터 공공기관 CCTV는 민간 TTA 인증 대신 국정원 보안기능확인서가 필수가 됩니다.
이 저장소는 그 요구사항을 만족하는 IP카메라 펌웨어를 **RPi5에서 먼저 프로토타이핑**하고,
이후 실제 카메라 SoC로 이식하기 위한 Buildroot `BR2_EXTERNAL` 트리입니다.

> ⚠️ 이 저장소만으로는 빌드되지 않습니다. Buildroot 체크아웃 위에 얹어서 사용하는 **외부 트리**입니다.

<br/>

## 목차

- [소개](#소개)
- [왜 이렇게 만들었나](#왜-이렇게-만들었나)
- [주요 기능](#주요-기능)
- [하드웨어 · 개발 환경](#하드웨어--개발-환경)
- [프로젝트 구조](#프로젝트-구조)
- [빌드 방법](#빌드-방법)
- [구현명세서 동기화 (핵심 워크플로)](#구현명세서-동기화-핵심-워크플로)
- [파티션 레이아웃](#파티션-레이아웃)
- [보안 설계 요약](#보안-설계-요약)
- [로드맵](#로드맵)
- [라이선스 · 참고](#라이선스--참고)

<br/>

## 소개

공공기관에 IP카메라를 납품하려면 국정원 보안기능 시험(53항목: 필수 42 / 조건부 9 / 선택 2)을 통과해야 합니다.
이 프로젝트는 **최소화·하드닝된 펌웨어 이미지**를 Buildroot로 빌드해서, 상용 배포판을 그대로 쓰는 방식으로는 맞추기 어려운
`무결성 검증 · 서명 업데이트 · 검증필 암호모듈 · 불필요 서비스 제거` 같은 요구사항을 처음부터 반영합니다.

인증 대상(TOE)은 하드웨어가 아니라 **이 이미지(펌웨어/구동 SW)** 입니다.
따라서 "OS를 깔고 앱을 얹는다"가 아니라 **"필요한 것만 넣어 이미지를 굽는다"** 는 관점으로 설계했습니다.

## 왜 이렇게 만들었나

처음엔 데비안을 올리고 프로그램만 설치하면 되지 않을까 생각했지만, 인증 관점에서는 그럴 수 없었습니다.

- 상용 배포판을 그대로 쓰면 **OS 전체가 시험 대상**이 되어, 수백 개 패키지의 취약점(CVE)을 전부 책임져야 합니다.
- 기본 서비스·열린 포트·기본 계정이 그대로면 `미기재 접속경로 = 백도어`로 간주되어 반려됩니다.
- 제품 스스로 무결성을 검증하고, 서명된 펌웨어만 설치하는 기능은 배포판에 없어 **직접 넣어야** 합니다.

그래서 Hailo 같은 가속기 없이 **RPi5 + IMX219** 최소 구성으로 잡고, 가속기 블롭이 빠진 만큼
시험 대상을 줄이는 방향을 택했습니다.

> 📌 참고: RPi5(BCM2712)에는 하드웨어 H.264 인코더가 없습니다(RPi4엔 있었음).
> 그래서 영상 인코딩은 소프트웨어로 처리하며, 2GB 램을 고려해 **1080p 다운스케일 + soft H.264/MJPEG** 로 설계합니다.

## 주요 기능

- **최소 이미지**: read-only squashfs 루트 + dm-verity 무결성 검증
- **A/B 이중화 + 서명 OTA**: RAUC 기반, 업데이트 실패 시 자동 롤백
- **네트워크 하드닝**: HTTPS/TLS·SSH만 허용, nftables default-deny + 관리 IP allowlist, 평문 HTTP·telnet 제거
- **강제 초기 설정**: 최초 부팅 시 기본 계정·패스워드 강제 변경 전까지 기능 잠금
- **암호 HAL**: 프로토타입 OpenSSL(ARIA256-GCM 우선) ↔ 양산 KCMVP 검증필 모듈로 백엔드만 교체
- **자체시험·감사기록**: 부팅/주기 무결성 검사, append-only 감사로그, 신뢰 시간(인증 NTP)
- **외부 저장매체 차단**: 부팅 SD 외 USB/추가 SD 자동 인식 차단
- **요구항목 추적성**: 코드의 `SFR:<항목ID>` 태그로 53항목과 구현을 1:1 연결

## 하드웨어 · 개발 환경

| 구분 | 내용 |
|------|------|
| 보드 | Raspberry Pi 5 (2GB) |
| 카메라 | IMX219 (Camera Module v2 센서) |
| 베이스 | Buildroot (`BR2_EXTERNAL`) |
| 타깃 | aarch64 / Cortex-A76 (BCM2712) |
| 영상 | libcamera + soft H.264/MJPEG (HW 인코더 없음) |
| 부트/업데이트 | U-Boot(FIT 서명) + RAUC A/B |
| 암호 | crypto HAL — OpenSSL(프로토) / KCMVP(양산) |

## 프로젝트 구조

```
ipcamera-secure-fw/
├── external.desc / Config.in / external.mk   # BR2_EXTERNAL 정의
├── configs/
│   └── rpi5_secure_defconfig                 # RPi5 보안 defconfig
├── board/rpi5-secure/
│   ├── genimage.cfg                          # A/B 파티션 레이아웃
│   ├── post-build.sh / post-image.sh         # 하드닝 · dm-verity · 이미지 조립
│   └── rootfs-overlay/                       # nftables · sshd · udev · config.txt
├── package/
│   ├── cctv-secd/                            # 보안 데몬(프로비저닝·자체시험·감사·세션)
│   └── crypto-hal/                           # 암호 HAL(OpenSSL ↔ KCMVP)
├── sfr/
│   ├── sfr-ipcam.json                        # 53항목 목록(ID·영역·강도, 원문 제외)
│   └── sync.mjs                              # 코드 ↔ 53항목 ↔ 구현명세서 동기화
└── impl-spec/
    └── 구현명세서-3장.md                      # 보안기능 구현명세서 3장 (living)
```

## 빌드 방법

Buildroot는 이 저장소에 포함돼 있지 않습니다. `raspberrypi5_defconfig` 위에 우리 보안 설정을 병합해서 빌드합니다. **셋업 스크립트가 자동화**합니다:

```bash
./scripts/gen-dev-keys.sh          # (서명 업데이트용) 개발 키 생성
./scripts/setup.sh                 # buildroot 고정 + raspberrypi5_defconfig + 보안 fragment 병합
make -C buildroot BR2_EXTERNAL=$PWD # → buildroot/output/images/
```

SD카드(16GB)에 굽기:

```bash
lsblk                              # SD 장치 확인 (예: /dev/sdX) — 반드시 재확인!
sudo dd if=buildroot/output/images/sdcard.img of=/dev/sdX bs=4M conv=fsync status=progress
```

> 상세 절차·A/B+dm-verity 옵트인·하드웨어 조정은 **[BUILD.md](BUILD.md)** 참고.
> 우리 보안 SW·하드닝은 병합만으로 이미지에 포함됩니다. A/B·서명부팅 등 부트 통합은 온보드 조정이 필요합니다.

## 호스트 테스트 (보안 로직 검증)

플랫폼 독립 보안 로직(암호 HAL·인증·감사)은 Buildroot·하드웨어 없이 **호스트에서 gcc로 빌드·검증**할 수 있습니다.

```bash
sudo apt install -y libssl-dev   # 최초 1회
./run-host-tests.sh
```

검증 항목:
- **crypto_hal**: ARIA-256-GCM 라운드트립, 변조 탐지, nonce 유일성(고정 IV 재사용 없음), HMAC, 키 파기
- **auth**: 패스워드 정책(2.3.1)·재사용 방지(2.4.1)·연속 실패 잠금(2.2.1)
- **audit**: append-only HMAC 해시체인 무결성 + 위변조 탐지(8.3.1) + 조회·정렬(8.2.x)·용량 회전(8.4.1)
- **session**: 미사용 세션 종료(7.1.1) + 동일 계정 중복 접속 거부(7.2.1)
- **mgmt**: RBAC 관리 권한(3.1.1) + 관리접속 토글(3.2.1)
- **config_store**: 설정값 암호화 저장 + 접근제어(4.2.2) + 무결성 검증(5.2.1)

## 구현명세서 동기화 (핵심 워크플로)

이 프로젝트의 특징은 **코드와 인증 문서(보안기능 구현명세서)가 항상 붙어 다닌다는 점**입니다.
보안기능을 구현할 때 소스에 요구항목 태그만 달면, 구현명세서의 커버리지 표가 자동으로 갱신됩니다.

```c
/* SFR:5.2.1 제품·설정값 무결성 검증 */
static int self_test(void) { ... }
```

```bash
node sfr/sync.mjs            # 커버리지 확인 (매핑 / 미착수 / 해당없음)
node sfr/sync.mjs --write    # 구현명세서 3장의 자동 상태표 갱신
```

- 서술(4단 골격: 요구사항 / 설명 / 순서도 / 동작)은 `impl-spec/구현명세서-3장.md`에서 **직접 편집**합니다.
- 상태표(`AUTO-STATUS` 블록)만 스크립트가 갱신하므로, 손으로 쓴 내용은 보존됩니다.
- 완성되면 마크다운을 `.hwpx`로 변환해 제출용 구현명세서에 그대로 넣습니다.

## 파티션 레이아웃

| 파티션 | 포맷 · 보호 | 용도 |
|--------|-------------|------|
| boot | FAT, 서명 FIT | RPi5 펌웨어 + U-Boot + 서명 커널/DTB |
| rootfs A | squashfs + dm-verity (RO) | 시스템 이미지 A |
| rootfs B | squashfs + dm-verity (RO) | 시스템 이미지 B (롤백용) |
| config | 암호화(LUKS) | 설정값 · 정책 · 자격증명 |
| data | 암호화 | 감사로그 · 런타임 상태 |

> 온보드 영상 저장은 하지 않습니다(순수 스트리밍, 저장은 별도 DVR/VMS 담당).

## 보안 설계 요약

- **암호는 애플리케이션이 직접 호출하지 않습니다.** 모든 암호 연산은 `crypto_hal` 인터페이스만 통과합니다.
  AEAD·해시·키관리만 노출해 ECB·고정 IV·금지 알고리즘을 API 수준에서 차단합니다.
- **양산 이식**: 플랫폼 종속 부분(암호 백엔드, secure boot)만 HAL 뒤로 격리해,
  인증·세션·감사·업데이트 로직은 프로토타입 코드를 그대로 재사용합니다.

## 로드맵

- [x] BR2_EXTERNAL 뼈대 (defconfig · 파티션 · 하드닝 오버레이)
- [x] 보안 데몬 / 암호 HAL 골격 + `SFR:` 태그 추적성
- [x] 구현명세서 동기화 도구
- [ ] 영상 보안: RTSP 인증 + RTSPS (mediamtx 패키지 추가) — `1.1.1`, `1.2.1`
- [ ] 서명 A/B 업데이트: RAUC 실동작 — `6.1.1`~`6.1.3`
- [ ] 취약점 대응: SBOM + CVE 스캔, 불필요 서비스 제거 태깅 — `10.2.1`, `10.3.1`
- [ ] 웹 관리 UI (경량 서버) + 감사기록 뷰어 — `8.2.1`, `8.2.2`
- [ ] 실제 카메라 SoC 이식 (KCMVP · SoC secure boot · Yocto 검토)

## 라이선스 · 참고

- 이 저장소의 스캐폴드 코드는 [MIT License](LICENSE)를 따릅니다. Buildroot·상용 배포판·오픈소스 컴포넌트는 각자의 라이선스를 따릅니다.
- 요구사항 근거: 국가용 보안요구사항 「영상정보처리기기」 IP카메라 (53항목). **요구항목 원문은 공개 저장소에서 제외했으며**(국정원/국가사이버안보센터 공식 배포본 참조), 여기엔 항목 식별번호·영역·강도만 둡니다.
- 참고한 외부 프로젝트 구조: [cdsteinkuehler/br2rauc](https://github.com/cdsteinkuehler/br2rauc) (Buildroot + RAUC).
