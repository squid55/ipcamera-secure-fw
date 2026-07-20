# BUILD — SD카드 이미지 빌드 가이드 (RPi5 + 16GB SD)

빌드는 **리눅스 호스트 PC**에서 하고, 나온 이미지를 SD카드에 굽는다. (RPi 위에서 빌드하는 게 아님)

## 0. 사전 준비 (호스트)

```bash
sudo apt install -y build-essential git bc rsync cpio unzip file wget \
  libssl-dev bison flex libncurses-dev python3 mtools dosfstools
# 디스크 ~30GB 여유, 최초 빌드 1~2시간
```

## 1. 셋업 (Buildroot 고정 + 우리 보안 설정 병합)

```bash
git clone https://github.com/squid55/ipcamera-secure-fw.git
cd ipcamera-secure-fw
./scripts/gen-dev-keys.sh     # 서명 업데이트(RAUC) 쓸 때. 개발용 키 생성
./scripts/setup.sh            # buildroot 체크아웃(2025.02) + raspberrypi5_defconfig + fragment 병합
```

`setup.sh`가 하는 일:
- Buildroot를 `buildroot/`에 clone·태그 고정(재현성)
- `raspberrypi5_defconfig` 로드 → `configs/ipcamera_secure.fragment` 병합(`olddefconfig`)
- 우리 패키지(cctv-secd·crypto-hal·rtsp-server)·하드닝 오버레이·커널 fragment(모듈서명/dm-verity) 활성화

## 2. 빌드

```bash
make -C buildroot BR2_EXTERNAL=$PWD
# 산출물: buildroot/output/images/
```

기본 산출물에는 **우리 보안 SW·하드닝이 모두 포함된 rootfs**가 만들어진다.
(RPi5 표준 부트 + 우리 패키지/설정)

## 3. SD카드에 굽기 (16GB)

```bash
lsblk                         # SD 장치 확인 (예: /dev/sda) — 반드시 재확인!
sudo dd if=buildroot/output/images/sdcard.img of=/dev/sdX bs=4M conv=fsync status=progress
sync
```

> SD가 16GB여도 이미지 크기만 기록되고 나머지는 미사용으로 남는다(어플라이언스는 정상).
> 로그·녹화 공간이 필요하면 `board/rpi5-secure/genimage.cfg`의 `data` 파티션 크기를 키운다.

## 4. (옵트인·고급) A/B + dm-verity 이미지

읽기전용 A/B 이중화 + 무결성 검증 이미지를 만들려면:

1. `configs/ipcamera_secure.fragment`에서 `BR2_ROOTFS_POST_IMAGE_SCRIPT` 줄의 주석을 해제
2. `./scripts/setup.sh` 재실행 후 `make`
3. `post-image.sh`가 `veritysetup`으로 root hash를 만들고 `genimage.cfg`(A/B)로 `sdcard.img` 조립

### 이 단계에서 조정이 필요한 부분 (정직한 안내)
- **부트 레이아웃**: RPi5 부트로더/DTB/`kernel8.img` 파일명이 `genimage.cfg`의 boot 파티션 목록과 맞아야 함(`buildroot/output/images/` 확인 후 조정).
- **roothash 연결**: `verity.roothash`를 커널 cmdline(`dm-mod.create=...`) 또는 U-Boot 부트스크립트에 주입해야 커널이 실제로 verify 함 → **온보드 검증 필요**.
- **서명 부팅**: FIT 서명·U-Boot는 별도 구성(양산은 SoC secure boot로 이관).

## 5. 부팅 후 확인

- 최초 부팅: 기본 관리자 패스워드 강제 변경(SFR:3.4.2) 전까지 기능 잠금
- `fwinfo` : 펌웨어 버전·빌드 해시·활성 슬롯(SFR:6.1.2)
- 관리 접속: HTTPS/SSH만(평문 없음), 영상: RTSPS 인증 필요

## 참고
- 먼저 표준 `make raspberrypi5_defconfig`로 vanilla 이미지가 부팅되는지 확인하면 하드웨어·flash 문제를 분리할 수 있다.
- 플랫폼 독립 보안 로직은 빌드 없이 `./run-host-tests.sh`로 검증 가능.
