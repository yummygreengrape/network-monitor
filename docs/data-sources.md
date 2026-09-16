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

### 게이트웨이 ping을 도달성 기준으로 쓸 수 없다

두 가지가 겹칩니다.

**첫째, ICMP에 응답하지 않는 네트워크가 있습니다.** 클라이언트 격리나 ICMP
필터링을 켠 공용 Wi-Fi에서는 흔한 구성입니다. 이때 게이트웨이 ping을 무선 구간
장애의 기준으로 쓰면 매 주기가 장애로 기록됩니다.

**둘째, 측정 환경 자체가 ICMP를 막을 수 있습니다.** 개발 중 한 네트워크에서
"게이트웨이가 ICMP에 전혀 응답하지 않는다"고 결론지었는데, 나중에 같은 셸에서
`ping 127.0.0.1`조차 100% 손실이 나는 것을 확인했습니다. 그 셸이 ICMP를 막고
있었던 것이고, 네트워크의 성질이 아니었습니다. 같은 시각 LaunchAgent로 돌던
같은 코드는 297주기 중 289주기에서 정상 응답(RTT 18ms)을 받고 있었습니다.
**`ping` 실패는 "상대가 응답하지 않는다"가 아니라 "이 프로세스에서 응답을 받지
못했다"입니다.**

그래서 도달성은 ARP 해석을 1순위로 봅니다. 권한도 응답도 필요 없고, 게이트웨이
MAC이 잡힌다는 것은 L2가 살아 있다는 뜻입니다. ICMP는 **이 네트워크에서 한 번
이라도 응답한 적이 있을 때만** 씁니다(기본 5주기 보정). 한번 ICMP로 정한 뒤에도
ARP는 정상인데 ICMP만 20주기 연속 실패하면 ARP 기준으로 되돌립니다 — 게이트웨이가
속도 제한을 켜는 경우가 있고, 되돌리지 않으면 거짓 경보가 끝나지 않습니다.
ARP까지 함께 죽는 진짜 장애에서는 이 조건이 성립하지 않아 경보가 유지됩니다.
→ `netmon/liveness.py`

### macOS `ping`의 `-W`는 총 대기 시간이 아니다

실측한 소요 시간(무응답 대상, `-c 1`): `-W 300` → 1.33초, `-W 500` → 1.53초,
`-W 800` → 1.84초. 고정 오버헤드 약 1초에 `-W`가 더해집니다.

`-t`(전체 제한)는 더 나쁩니다. **응답이 와도 그 시간만큼 붙잡고 있습니다** —
`ping -c 1 -t 1`은 응답 여부와 무관하게 1.03초가 걸립니다.

패킷 간격은 1초 고정이고 1초 미만은 root 권한이 필요합니다. 그래서 `-c 2`로
재면 한 주기가 최소 2초 늘어납니다. 주기마다 **한 번만** 쏘고, 손실은 주기
사이의 연속 실패로 봅니다. 이 변경으로 한 주기가 3.6초에서 2.3초가 됐습니다.

### launchd는 PATH로 `/usr/bin:/bin:/usr/sbin:/sbin`만 준다

사용자가 설치한 도구는 대개 `/usr/local/bin`이나 `/opt/homebrew/bin`에 있습니다.
테스트한 기계에서는 VPN 도구가 `/usr/local/bin`에 설치돼 있었고,
상시 실행으로 등록하자 **VPN 감시가 조용히 아무것도 보지 못했습니다.** 이것이
이 도구가 가장 피하려는 실패 방식입니다.

PATH에 기대지 않습니다. 명령을 찾을 때 `shutil.which` 다음으로 흔한 설치 위치를
직접 뒤지고, 찾은 절대 경로로 실행합니다(`netmon/util.py`의 `find_tool`).
LaunchAgent와 실행기에서도 PATH를 넓히지만, 그것은 보조 수단입니다.

### SSID·BSSID는 위치 권한이 없으면 `<redacted>`

`ipconfig getsummary <dev>`에 `SSID`·`BSSID`·`NetworkID` 키가 있지만, 위치 서비스
권한이 없으면 값이 `<redacted>`로 나옵니다. 오류가 아니라 가려진 것이므로 그렇게
보고합니다.

**`Security`(암호화 방식)는 가려지지 않습니다.** `system_profiler SPAirPortDataType`과
대조해 값이 일치함을 확인했습니다(양쪽 모두 `None`). 그래서 암호화 다운그레이드
탐지는 권한 없이 동작하고, evil twin(BSSID) 탐지만 권한을 요구합니다.

표기가 한 가지가 아닙니다. 두 네트워크에서 각각 `NONE`과 `WPA2_PSK`를 봤고,
`WPA2 Personal`·`WPA2/WPA3 Personal` 같은 형태도 쓰입니다. 고정 문자열 표를 쓰면
처음 보는 표기에서 **조용히 판정 불가**가 되므로(실제로 그렇게 깨졌습니다) 세대
토큰으로 읽습니다. 혼합 모드는 약한 쪽 접속을 허용하므로 약한 쪽으로 칩니다.

`getsummary`는 15ms입니다. `system_profiler SPAirPortDataType`은 20초 이상 걸리므로
주기 측정에 쓰지 않습니다.

### 위치 권한은 앱 단위라 CLI가 직접 받을 수 없다

실측한 순서와 결과입니다.

1. `-sectcreate __TEXT __info_plist`로 Info.plist를 박은 **단일 실행 파일**에서
   `requestWhenInUseAuthorization` 호출 → **75초 동안 요청 창이 뜨지 않음**,
   상태는 계속 `not-determined`.
2. 같은 코드를 **`.app` 번들**로 만들어 `open -n`으로 실행 → 요청 창이 뜨고
   `authorized-always` 획득.
3. 그 상태에서도 터미널의 `ipconfig getsummary`는 **여전히 `<redacted>`**.
   권한은 요청한 앱에만 붙고 다른 프로세스로 넘어가지 않습니다.

그래서 권한을 가진 헬퍼가 값을 읽어서 넘기는 구조로 만들었습니다. 한 번 호출에
약 0.5초 걸리므로 기본 15초 간격으로 캐시하고, 게이트웨이 MAC·DHCP 서버·임대
시작 시각이 바뀐 직후에는 즉시 다시 읽습니다.

곁들여 확인한 것 두 가지:

- **`open -a`는 이미 실행 중인 인스턴스를 재활성화할 뿐** 새 인자를 전달하지
  않습니다. `open -n`으로 새 인스턴스를 띄워야 합니다.
- **재서명하면 TCC 승인이 무효가 됩니다.** 그냥 ad-hoc 서명하면 재빌드마다
  cdhash가 바뀌어 사용자가 매번 다시 허용해야 합니다. 지정 요구사항을
  `identifier "io.github.network-monitor.location-helper"`로 고정하면 재빌드
  후에도 승인이 유지되는 것을 확인했습니다.
- **`CLLocationManager.authorizationStatus`는 만든 직후 읽으면 안 됩니다.**
  델리게이트로 비동기 전달되므로 이미 승인된 앱도 `not-determined`로 보입니다.
  첫 콜백을 최대 2초 기다린 뒤 읽습니다.

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
물리 인터페이스를 따로 찾습니다. 테스트한 기계에는 `utun` 인터페이스가 여럿 있었고
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
