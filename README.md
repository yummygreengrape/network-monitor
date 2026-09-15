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

## 쓰는 법

```
./netmon.sh doctor           이 기계에서 무엇이 되고 무엇이 안 되는지
./netmon.sh once             한 주기만 측정
./netmon.sh run              계속 측정 (Ctrl+C로 종료)
./netmon.sh report           오늘 요약
./netmon.sh report --redact  식별자를 가려서 출력 (남에게 보낼 때)
```

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
./netmon.sh consent grant location --enable    위치 권한 (evil twin 탐지)
./netmon.sh consent revoke location            철회 (관련 기능도 함께 꺼집니다)
```

| 항목 | 무엇에 쓰나 | 밖으로 나가는 것 |
|---|---|---|
| `location` | SSID·BSSID를 읽어 evil twin과 정상 로밍을 구분 | 없음 |
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
