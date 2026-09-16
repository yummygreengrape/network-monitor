# network-monitor

지금 붙어 있는 네트워크에서 **내 연결과 보안에 영향을 주는 일**이 생겼는지 알려주는
macOS용 감시 도구입니다.

- **연결 품질과 보안을 따로 봅니다.** 하나의 관측이 두 축 모두에서 판정될 수 있습니다.
  품질 사건이 보안 사건을 가리지 않습니다.
- **판정마다 근거와 확신도가 붙습니다.** `확정`·`의심`·`가능`을 섞지 않습니다.
- **내 행동으로 생긴 변화는 억제하되 지우지 않습니다.** 억제된 판정도 기록에 남습니다.
- **기본값은 최소 권한입니다.** sudo를 쓰지 않고, 외부로 요청을 보내지 않으며,
  VPN 감시와 위치 권한은 꺼진 상태로 시작합니다.

## 요구 사항

macOS와 Python 3.9 이상. 추가 설치는 없습니다. `python3`가 없으면 Xcode Command Line
Tools를 설치하면 `/usr/bin/python3`가 생깁니다.

## 처음 켤 때

```
./netmon.sh setup
```

무엇을 켜고 끌지 하나씩 물어봅니다. 측정 간격, 기록 위치와 보존 기간, 위치 권한,
VPN 감시, 외부 점검 요청, 상시 실행 여부입니다. **엔터만 눌러도 안전한 값**입니다 —
sudo를 쓰지 않고, 외부로 요청을 보내지 않고, 상시 실행으로 등록하지도 않습니다.

아무 인자 없이 `./netmon.sh`를 실행해도 설정이 없으면 마법사를 권합니다.
묻지 않고 기본값만 쓰려면 `./netmon.sh setup --defaults`입니다.

## 쓰는 법

```
./netmon.sh doctor           이 기계에서 무엇이 되고 무엇이 안 되는지
./netmon.sh once             한 주기만 측정
./netmon.sh run              계속 측정 (Ctrl+C로 종료)
./netmon.sh report           오늘 요약
./netmon.sh report --redact  식별자를 가려서 출력 (남에게 보낼 때)
./netmon.sh location setup   위치 권한 헬퍼를 만들고 권한 요청 (evil twin 탐지)
./netmon.sh service install  항상 켜 두기 (로그인할 때 자동 시작)
./netmon.sh investigate list 이어지는 조사 보기
./netmon.sh watch            실시간 화면 (감시는 에이전트가 계속합니다)
```

## 실시간으로 보기

```
./netmon.sh watch                    지금 상태·열린 조사·최근 판정
./netmon.sh watch --redact           식별자를 가려서 (화면 공유할 때)
./netmon.sh watch -v                 억제된 판정도 함께
```

`watch`는 **스스로 측정하지 않습니다.** 상시 실행 에이전트가 남긴 기록을 읽어
보여 줄 뿐이라, 창을 띄운다고 측정이 두 번 일어나지 않습니다. 창을 닫아도
감시는 계속됩니다. 에이전트가 멈추면 화면이 "멈춘 듯"이라고 알려 줍니다.

## 유의미한 신호는 계속 조사합니다

"게이트웨이 MAC이 바뀌었다"는 확정이지만, 그것이 공격인지 접속점 교체인지는
**그 다음에 일어나는 일**로만 갈립니다. 유의미한 신호가 잡히면 조사를 열고,
더 자주 측정하면서 결론이 날 때까지 봅니다.

무엇을 유의미하다고 볼지는 바꿀 수 있고, **조사가 스스로도 바꿉니다.** MAC
변경에 DHCP 변조가 겹치면 감시 범위를 넓히고, VPN 끊김이 되풀이되면 무선 구간
품질까지 함께 봅니다. 기준이 바뀔 때마다 이유와 이전·이후 값이 기록에 남습니다.

```
netmon.sh investigate rules                        지금 기준 보기
netmon.sh investigate rules --set severities=high  좁히기
netmon.sh investigate show <id>                    기준이 어떻게 움직였는지
```

자세한 것은 [docs/detections.md](docs/detections.md)의 "이어지는 조사"에 있습니다.

## 항상 켜 두기

```
./netmon.sh service install     등록
./netmon.sh service status      상태 확인
./netmon.sh service uninstall   해제 (기록은 남습니다)
```

`~/Library/LaunchAgents/io.github.network-monitor.plist` 파일 하나를 만듭니다.
**sudo를 쓰지 않고**, 시스템 설정을 바꾸지 않으며, `uninstall`로 되돌립니다.
`setup` 마법사에서도 고를 수 있고, 기본값은 등록하지 않는 것입니다.

등록하면 로그인할 때 시작하고 멈추면 다시 뜹니다. 우선순위를 낮춰(`nice 5`,
`Background`, `LowPriorityIO`) 다른 작업을 방해하지 않습니다. 실측에서 CPU 0.0%,
메모리 약 17MB였습니다. `launchd`의 출력 파일은 회전되지 않으므로 5MB를 넘으면
앞부분을 잘라 냅니다.

저장소를 다른 곳으로 옮기면 등록된 실행 경로가 깨집니다. `service status`와
`doctor`가 그 상태를 알려 주고, `service install`로 다시 등록하면 됩니다.

먼저 `doctor`를 실행하세요. 기종과 macOS 버전, 권한에 따라 쓸 수 있는 탐지가 다르고,
`doctor`는 **무엇이 왜 안 되는지**를 함께 알려줍니다. 남의 기계에서 탐지가 조용히
빠지는 것이 이 도구의 가장 위험한 실패 방식이라, 안 되는 것을 숨기지 않습니다.

기록 위치는 `--log-dir` 또는 `NETMON_LOG_DIR`로 바꿉니다. 기본은
`~/.config/network-monitor/data`입니다.

## 권한과 동의

두 가지는 **동의해야만** 켜집니다. 동의하지 않으면 관련 기능은 꺼진 채로 남고,
나머지 탐지는 그대로 동작합니다.

```
./netmon.sh consent list                       무엇을 왜 요구하는지 읽기
./netmon.sh location setup                     위치 권한 헬퍼 생성 + 권한 요청
./netmon.sh location status                    현재 권한 상태
./netmon.sh consent revoke location            철회 (관련 기능도 함께 꺼집니다)
```

### 위치 권한이 왜 별도 앱을 거치나

macOS의 위치 권한은 **앱 단위**입니다. 터미널에서 돌리는 스크립트는 권한을 요청할
주체가 없어 요청 창이 뜨지 않고, 권한을 받은 다른 앱의 승인을 물려받지도 못합니다.
그래서 `location setup`이 작은 헬퍼 앱(`NetworkMonitorLocation.app`)을 만들어
설정 디렉터리에 두고, 그 앱이 권한을 받아 **SSID와 BSSID만** 돌려줍니다.

헬퍼는 위치 좌표를 읽지 않고(`startUpdatingLocation`을 호출하지 않습니다),
주변 AP 목록도 훑지 않습니다. 필요한 두 값이 전부입니다. 소스는
[tools/location-helper/request_location.m](tools/location-helper/request_location.m)에
있습니다.

| 항목 | 무엇에 쓰나 | 밖으로 나가는 것 |
|---|---|---|
| `location` | SSID·BSSID를 읽어 evil twin과 정상 로밍을 구분 | 없음 |
| VPN 감시 | 연결 상태와 끊김 원인 (동의 항목은 아니지만 기본 꺼짐) | 없음 |
| `external_probes` | DNS 가로채기·TLS 발급자·공인 IP 확인 | 고정된 조회 이름과 내 출발지 IP |

동의하기 전에는 SSID·BSSID를 **기록조차 하지 않습니다.** 위치 권한이 우연히 열려
있어도 마찬가지입니다.

## 개인정보

로그에는 식별자 원문이 남습니다. 기록 시점에 해시하면 "MAC이 a에서 b로 바뀜"은 남지만
그 `b`가 어제 본 AP인지 내 폰인지 사람이 판단할 수 없게 되어 조사 가치가 사라집니다.
로그는 본인 기계에만 남으므로 원문을 두고, **남에게 보낼 때 `--redact`로 가립니다.**

가리기는 로컬 솔트 HMAC이라 같은 값이 같은 토큰이 됩니다. "바뀌었다가 원래대로
돌아왔다" 같은 관계는 가린 뒤에도 보입니다. 솔트는
`~/.config/network-monitor/salt`에 소유자 전용(600)으로 둡니다.

## 하지 않는 것

- 다른 호스트를 스캔하지 않습니다. ARP 위조·deauth 같은 공격을 재현하지 않습니다.
- sudo를 쓰지 않습니다. 시스템 설정을 바꾸지 않습니다. 상시 실행으로 등록하지 않습니다.
- 네트워크 식별자를 외부로 보내지 않습니다.

## 구조

```
netmon/collect/   각 데이터원. parse_*(문자열)은 순수 함수, collect()가 명령을 실행
netmon/detect/    판정. (이전 관측, 현재 관측, 문맥) → 판정 목록. 순수 함수
netmon/liveness.py  첫 홉 도달성을 ICMP에 기대지 않고 판정
netmon/baseline.py  기준선. 판정 전/후로 나눠 갱신
netmon/redact.py    식별자 가리기
```

수집과 판정을 나눈 이유는 테스트입니다. 현장에서 관측을 떠 오면
(`netmon.sh capture N --redact`) 이후 판정 수정은 네트워크 없이 재현합니다.

```
./netmon.sh capture 60 -o /tmp/cafe.jsonl --redact
./netmon.sh replay /tmp/cafe.jsonl
```

## 개발

```
PYTHONPATH=. python3 -m unittest discover -s tests -t .
tools/leak-check.sh          커밋될 내용에 환경 식별자가 섞였는지 검사
```

테스트는 전부 합성 입력입니다. 실제 환경에서 뜬 값을 저장소에 넣지 않습니다.

## 문서

- [docs/threat-model.md](docs/threat-model.md) — 누가 무엇을 할 수 있나
- [docs/data-sources.md](docs/data-sources.md) — 쓰는 명령과 실측한 함정
- [docs/detections.md](docs/detections.md) — 탐지 항목과 확신도 상한
