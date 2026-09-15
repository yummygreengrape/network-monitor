# 데이터원과 함정

실측 환경: macOS 26.6.2 (빌드 25G83), Apple 실리콘, Wi-Fi. 다른 버전에서는 다를 수
있으므로 `netmon.sh doctor`가 실행 시점에 다시 탐침합니다.

## 쓰는 명령

전부 **sudo 없이** 동작하고, **외부로 나가지 않습니다.**

| 명령 | 얻는 것 | 비고 |
|---|---|---|
| `networksetup -listallhardwareports` | 인터페이스 목록과 종류 | Wi-Fi/유선 구분 |
| `networksetup -listnetworkserviceorder` | 서비스 우선순위 | 물리 주 인터페이스 선택 |
| `ifconfig <dev>` | 링크 상태, 주소, 넷마스크 | |
| `route -n get [-ifscope <dev>] default` | 기본 경로 | |
| `netstat -rn -f inet[6]` | 기본 경로 전체 | VPN이 만든 경로 포함 |
| `ndp -rn` | IPv6 라우터 목록 | rogue RA 탐지 |
| `arp -an -x` | 이웃 표, 게이트웨이 MAC | |
| `netstat -s -p arp` | ARP 통계, `Duplicate IP seen` | |
| `ipconfig getpacket <dev>` | DHCP 옵션 (server_identifier, router, DNS) | rogue DHCP 탐지 |
| `ipconfig getsummary <dev>` | 임대 시각, SSID, BSSID, Security | 아래 함정 참조 |
| `scutil --dns` | 시스템 리졸버 | |
| `scutil --proxy` | 프록시·WPAD 설정 | |
| `ping` | 왕복 시간 | 아래 함정 참조 |

VPN 상태는 공급자별로 `warp-cli status`, `tailscale status --json`,
`wg show interfaces`, `scutil --nc list`를 씁니다. 기본은 꺼짐입니다.

## 실측으로 확인한 함정

### 게이트웨이가 ICMP에 응답하지 않는 네트워크가 있다

측정한 네트워크에서 게이트웨이가 ICMP에도 TCP(80/443/53)에도 전혀 응답하지 않았고,
같은 시각 ARP는 정상이었으며 인터넷도 정상이었습니다(HTTPS 200, 50ms). 클라이언트
격리나 ICMP 필터링을 켠 네트워크에서는 흔한 구성입니다.

**게이트웨이 ping을 무선 구간 장애의 기준으로 쓰면 그런 네트워크에서는 매 주기가
장애로 기록됩니다.** 그래서 네트워크마다 "이 게이트웨이가 ICMP에 응답하는가"를 먼저
보정하고(기본 5주기), 응답하지 않으면 ARP 해석 여부로 판정 기준을 바꿉니다.
전환 사실은 `GATEWAY_ICMP_SILENT`로 한 번 기록합니다. → `netmon/liveness.py`

### SSID·BSSID는 위치 권한이 없으면 `<redacted>`

`ipconfig getsummary <dev>`에 `SSID`·`BSSID`·`NetworkID` 키가 있지만, 위치 서비스
권한이 없으면 값이 `<redacted>`로 나옵니다. 오류가 아니라 가려진 것이므로 그렇게
보고합니다.

**`Security`(암호화 방식)는 가려지지 않습니다.** `system_profiler SPAirPortDataType`과
대조해 값이 일치함을 확인했습니다(양쪽 모두 `None`). 그래서 암호화 다운그레이드
탐지는 권한 없이 동작하고, evil twin(BSSID) 탐지만 권한을 요구합니다.

`getsummary`는 15ms입니다. `system_profiler SPAirPortDataType`은 20초 이상 걸리므로
주기 측정에 쓰지 않습니다.

### `wdutil info`는 sudo가 필요한데 rc=0으로 끝난다

권한 없이 실행하면 usage를 출력하고 **종료 코드 0**을 돌려줍니다. 성공처럼 보이는
함정이라 반환 코드만으로 판정하면 안 됩니다. 이 도구는 `wdutil`을 쓰지 않습니다.

### `security dump-trust-settings`의 rc=1은 오류가 아니다

사용자·관리자 도메인에 추가된 신뢰 설정이 없으면 rc=1과 함께
`No Trust Settings were found`를 출력합니다. **이것이 깨끗한 기준 상태입니다.**
rc=1을 실패로 처리하면 신뢰 저장소 변조를 영구히 놓칩니다. 시스템 도메인(`-s`)은
rc=0으로 동작합니다.

### `networksetup -getairportnetwork`은 macOS 26에서 고장나 있다

인터페이스가 `status: active`이고 기본 경로를 쥐고 있는데도
`You are not associated with an AirPort network`를 반환합니다. 쓰지 않습니다.

### `log show`로 Wi-Fi 이벤트를 찾을 수 있다

`subsystem == "com.apple.wifi"`는 아무것도 주지 않습니다. 동작하는 조건자는
`senderImagePath CONTAINS "IO80211"`이고, 로밍·인증 키워드로 좁히면 30분 구간에
19줄을 5초 만에 가져옵니다. 로밍·연결 해제 이벤트가 실제로 들어 있습니다.
(2단계에서 씁니다.)

### VPN이 있으면 기본 경로가 물리 인터페이스가 아니다

터널이 기본 경로를 쥐고 있으면 게이트웨이도 MAC도 DHCP도 전부 엉뚱한 것을 보게
됩니다. `route -n get default`의 인터페이스가 `utun`/`ipsec`/`ppp`면 서비스 순서에서
물리 인터페이스를 따로 찾습니다. 측정한 기계에는 `utun0`~`utun7`이 동시에 있었고
기본 경로가 둘이었습니다.

### 시스템 리졸버가 루프백인 것은 정상일 수 있다

VPN이나 DNS 필터를 쓰면 `scutil --dns`의 리졸버가 `127.x`가 됩니다. 그 자체를
이상으로 보면 VPN 사용자 전원에게 오탐이 납니다. 상태가 **바뀌는 것**만 봅니다.

### `bash`와 `zsh`

이 도구의 본체는 Python이지만 실행기와 검사 스크립트는 셸입니다. 셸 코드는
`bash`로 실행합니다. bash 3.2에서 `${s: -n}`은 `s`가 `n`보다 짧으면 빈 값이 되고,
인자 없는 `wait`는 모든 백그라운드 작업을 기다립니다.

## 외부로 나가는 요청

기본값에서는 **없습니다.** 품질 측정 대상은 게이트웨이와 이미 설정된 시스템
리졸버뿐입니다. 둘 다 이미 내 트래픽을 보고 있으므로 새로 알려지는 정보가 없습니다.

`external_probes` 동의를 받으면 DNS 가로채기·TLS 발급자·공인 IP 확인이 켜집니다.
그때 나가는 것은 고정된 조회 이름과 이 기계의 출발지 IP이고, SSID·BSSID·MAC 같은
네트워크 식별자는 보내지 않습니다.
