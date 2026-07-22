# 보안 정책 (Security Policy)

이 프로젝트는 **보안 IP카메라 펌웨어**로, 취약점 처리에 특히 주의를 기울입니다.
(관련 요구: 국정원 보안요구사항 10.x 취약성 대응)

## 지원 버전

| 버전 | 지원 |
|------|------|
| 최신 릴리스(main) | ✅ |
| pre-release / experiment 브랜치 | ⚠️ 실험적(검증 전) |
| 그 외 이전 버전 | ❌ |

## 취약점 신고 (Responsible Disclosure)

**공개 이슈에 취약점을 올리지 마세요.** 공개되면 패치 전 악용될 수 있습니다.

- **권장 경로**: 저장소 **Security 탭 → "Report a vulnerability"**
  (GitHub Private Vulnerability Reporting — 비공개로 메인테이너에게 전달)
- 신고 시 포함: 영향 버전, 재현 절차, 예상 영향(기밀/무결성/가용성), 가능하면 PoC

## 처리 절차 및 목표 시간

| 단계 | 목표 |
|------|------|
| 접수 확인 | 3영업일 이내 |
| 초기 평가(심각도 산정) | 7영업일 이내 |
| 수정·릴리스 | 심각도에 따라 협의 |
| 공개(disclosure) | 패치 배포 후 조율 공개(coordinated disclosure) |

## 범위

- 대상: 이 저장소의 커스텀 코드(`package/`), 하드닝 설정(`board/`), 빌드 스크립트(`scripts/`)
- 제3자 구성요소(Buildroot, OpenSSL, OpenSSH, Linux 커널 등)의 취약점은
  **상위 프로젝트에 신고**하고, 본 저장소는 해당 CVE의 **버전 반영·완화**로 대응합니다.
  (의존성 CVE 점검: `scripts/` 및 CI 참고)

## 서명·무결성

- 릴리스 이미지에는 SHA256 해시를 함께 배포합니다(다운로드 검증용).
- 업데이트 서명 검증(RAUC)·저장 무결성(dm-verity)은 로드맵 항목입니다.
