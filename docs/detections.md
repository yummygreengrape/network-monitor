# 탐지 항목

각 항목의 **확신도 상한**은 그 탐지가 원리적으로 도달할 수 있는 최대치입니다.
상한이 `의심`인 것을 `확정`으로 올리지 않습니다.

| 확신도 | 뜻 |
|---|---|
| `확정` | 관측만으로 사실이라고 말할 수 있다. **원인은 별개다** |
| `의심` | 기준선과 어긋난다. 양성 오류의 여지가 있다 |
| `가능` | 구조적으로 가능하다. 증거는 없다 |

"게이트웨이 MAC이 바뀌었다"는 확정입니다. "ARP 스푸핑을 당했다"는 아닙니다.
판정 이름과 요약은 이 구분을 지킵니다.

## 1단계 — 기본으로 켜짐 (sudo 불필요, 외부 요청 없음)

| 판정 | 축 | 확신도 상한 | 데이터원 |
|---|---|---|---|
| `GW_MAC_CHANGED` | 보안 | 확정 | `arp -an -x` |
| `DUPLICATE_IP` | 보안 | 확정 | `netstat -s -p arp` |
| `ARP_REPLY_SPIKE` | 보안 | 의심 | `netstat -s -p arp` (초당 건수) |
| `SHARED_MAC` | 보안 | 가능 | `arp -an -x` |
| `DHCP_SERVER_CHANGED` | 보안 | 확정 | `ipconfig getpacket` |
| `DHCP_ROUTER_CHANGED` | 보안 | 확정 | `ipconfig getpacket` |
| `DHCP_DNS_CHANGED` | 보안 | 확정 | `ipconfig getpacket` |
| `RESOLVER_CHANGED` | 보안 | 확정 | `scutil --dns` |
| `DNS_LOCAL_PROXY_CHANGED` | 보안 | 의심 | `scutil --dns` |
| `PROXY_ENABLED` / `PROXY_SETTINGS_CHANGED` | 보안 | 확정 | `scutil --proxy` |
| `DEFAULT_ROUTE_CHANGED` | 보안 | 확정 | `netstat -rn` |
| `IPV6_DEFAULT_ROUTE_APPEARED` | 보안 | 확정 | `netstat -rn -f inet6` |
| `IPV6_ROUTER_APPEARED` | 보안 | 의심 | `ndp -rn` |
| `WIFI_SECURITY_DOWNGRADE` | 보안 | 확정 | `ipconfig getsummary` |
| `WIFI_SECURITY_CHANGED` | 보안 | 확정 | `ipconfig getsummary` |
| `FIRST_HOP_UNREACHABLE` / `FIRST_HOP_RECOVERED` | 품질 | 확정 | ARP 또는 ping |
| `LATENCY_SPIKE` | 품질 | 의심 | ping (연속 3주기) |
| `DHCP_LEASE_RENEWED` | 품질 | 확정 | `ipconfig getsummary` |
| `WIFI_LINK_CHANGED` | 품질 | 확정 | `ipconfig getsummary` |
| `GATEWAY_ICMP_SILENT` / `GATEWAY_ICMP_OK` | 참고 | 확정 | 보정 결과 |
| `MEASUREMENT_GAP` | 참고 | 확정 | 측정 간격 |
| `MULTIPLE_DEFAULT_ROUTES` | 참고 | 확정 | `netstat -rn` |

## 동의가 필요한 탐지

| 판정 | 동의 항목 | 확신도 상한 | 왜 상한이 낮은가 |
|---|---|---|---|
| `WIFI_ROAM` | `location` | 확정 | 같은 SSID 안의 AP 전환은 사실 |
| `EVIL_TWIN_CANDIDATE` | `location` | **의심** | 정상 로밍과 완전히 구분할 수 없다. 게이트웨이 MAC이나 DHCP 서버가 함께 바뀌었을 때만 올린다 |
| `WIFI_NETWORK_SWITCHED` | `location` | 확정 | 다른 SSID로 옮긴 것은 사실 |

`location` 동의는 `netmon.sh location setup`으로 받습니다. macOS의 위치 권한이
앱 단위라 헬퍼 앱을 거치며, 그 이유와 실측 근거는
[data-sources.md](data-sources.md)에 적었습니다.

## VPN 감시 (기본 꺼짐)

`setup`에서 켜거나 `vpn.enabled`로 켭니다. 설치된 공급자를 찾아 상태만 봅니다 —
WARP(`warp-cli`), Tailscale(`tailscale`), WireGuard(`wg`), macOS 내장(`scutil --nc`).
외부로 나가는 요청은 없고, 기록하는 것은 연결 상태와 사유 문자열뿐입니다.
Tailscale의 `status --json`에는 기기 이름·주소·계정이 들어 있지만 `BackendState`
외에는 읽지 않고, `scutil --nc list`의 서비스 이름(사용자가 지은 것)도 읽지 않습니다.

| 판정 | 축 | 확신도 상한 | 비고 |
|---|---|---|---|
| `VPN_DISCONNECTED` | 품질 | 확정 | 끊김 자체는 사실. **원인은 단정하지 않는다** |
| `VPN_PROTECTION_LOST` | 보안 | 확정 | 같은 끊김의 다른 면. 직접 끊었어도 기록된다 |
| `VPN_RECONNECTED` | 품질 | 확정 | 끊겼던 시각을 함께 남긴다 |
| `VPN_STATE_UNKNOWN` | 참고 | 확정 | 조회 실패. **끊김으로 세지 않는다** |

원본 스크립트는 끊김 원인을 하나만 골랐습니다(`WIFI` / `WARP_PATH` /
`NETWORK_CHANGE` / `SLEEP` / `ARP_ANOMALY`). 여기서는 고르지 않습니다. 대신 같은
주기의 첫 홉 상태와 억제 사유를 **근거로 함께** 남기고, 요약문에 "가장 그럴듯한
설명"만 덧붙입니다. 원인을 하나 골라 적으면 그 순간 나머지 근거가 사라집니다.

`VPN_PROTECTION_LOST`의 심각도는 지금 붙은 네트워크가 개인별 자격증명
(Enterprise/EAP)을 쓰는지로 갈립니다. 접미사 없는 `WPA2`도 사실상 공유 비밀번호
이므로, **개인별 자격증명이라는 근거가 있을 때만** 위험이 낮다고 봅니다.

## 이어지는 조사

한 번의 판정으로 끝나지 않는 신호가 있습니다. "게이트웨이 MAC이 바뀌었다"는
**확정**이지만, 그것이 공격인지 접속점 교체인지는 그 다음에 일어나는 일로만
갈립니다. 유의미한 신호가 잡히면 조사를 열고, 결론이 날 때까지 계속 봅니다.

### 무엇이 "유의미한 신호"인가

기준은 세 층에서 정해지고, 아래로 갈수록 좁습니다.

1. **기본값** — 보안 축의 `high`·`medium`, 그리고 `EVIL_TWIN_CANDIDATE`,
   `DUPLICATE_IP`, `ARP_REPLY_SPIKE`, `VPN_DISCONNECTED`,
   `FIRST_HOP_UNREACHABLE`. 억제된 판정은 열지 않습니다 — 장소를 옮길 때마다
   조사가 쏟아지면 쓸모가 없습니다.
2. **사용자 설정** — `investigate rules --set`으로 바꿉니다.
   ```
   netmon.sh investigate rules                              지금 기준 보기
   netmon.sh investigate rules --set severities=high        좁히기
   netmon.sh investigate rules --set kinds=GW_MAC_CHANGED   특정 판정 추가
   netmon.sh investigate rules --set include_attributed=yes 억제된 것도 조사
   ```
3. **조사 자신의 기준** — 조사가 열린 뒤에는 그 조사의 기준이 쓰이고,
   **조사 중에 바뀝니다.**

### 기준이 조사 중에 바뀝니다

처음부터 넓게 보면 평소 소음까지 다 걸리고, 좁게만 보면 따라오는 신호를
놓칩니다. 그래서 알게 된 것에 따라 옮깁니다.

| 조사 | 언제 기준을 바꾸나 | 어떻게 |
|---|---|---|
| `l2_identity` | MAC 변경에 경로·이름 해석 변화가 겹칠 때 | 감시 범위에 DNS 프록시·IPv6 라우터·암호화 다운그레이드 추가 |
| `path_config` | 설정이 두 번 이상 흔들릴 때 | 한 번의 변조가 아니라 "경합"으로 보고, 자리 잡았다고 보는 기준을 2배로 |
| `vpn_drop` | 끊김이 두 번째일 때 | 무선 구간 품질(`FIRST_HOP_UNREACHABLE`·`LATENCY_SPIKE`·임대 갱신)까지 함께 |

**기준을 바꿀 때마다 이유·이전 값·이후 값을 기록에 남깁니다**
(`INVESTIGATION_RETUNED`). 조용히 바꾸면 나중에 "왜 이건 잡고 저건 놓쳤나"를
설명할 수 없습니다.

### 조사가 하는 일

- **더 자주 봅니다.** 조사 중에는 측정 간격을 줄이고(`l2_identity` 2초,
  `path_config`·`vpn_drop` 3초) Wi-Fi 식별자를 매 주기 다시 읽습니다.
- **결론을 내고 닫습니다.** 확신도는 증거에 맞춰 정해집니다 — 따라오는 신호가
  있으면 `의심`으로 올리고, 새 값이 안정되면 `가능`으로 내립니다.
- **예산이 있습니다.** 주기 한도를 넘기면 "가르지 못했다"고 적고 닫습니다.
  동시에 열리는 조사는 기본 3개까지입니다.
- **끝낸 뒤 냉각합니다.** 같은 종류를 기본 30주기 동안 다시 열지 않습니다.
  없으면 되풀이되는 문제에서 조사가 끝없이 새로 열립니다 — 결론을 낸 바로
  그 주기에 같은 신호로 또 열리기까지 합니다.
- **네트워크가 바뀌면 중단합니다.** 조용히 버리지 않고 `INVESTIGATION_ABANDONED`로
  남깁니다. 무엇을 못 보고 넘어갔는지가 기록에 있어야 합니다.
- **에이전트를 재시작해도 이어집니다.** 조사 상태는 `state.json`에 남습니다.

```
netmon.sh investigate list          조사 목록
netmon.sh investigate show <id>     기준이 어떻게 움직였는지 포함한 전체 경과
```

## 상시 실행일 때

`service install`로 등록하면 로그인할 때 시작합니다. 측정 간격은 설정을 따르고,
날짜가 바뀔 때마다 보존 기간이 지난 기록을 지웁니다.

잠자기와 깨어남은 `MEASUREMENT_GAP`으로 남고, 그 구간의 **품질** 판정만 억제됩니다.
보안 판정은 억제되지 않습니다 — 자는 동안 붙은 접속점이 바뀌는 것이야말로
확인해야 할 일이기 때문입니다.

## 2단계 (예정)

Wi-Fi 로밍·해제·인증 이벤트(`log show`), 신뢰 저장소 변화
(`security dump-trust-settings`), 설정 프로파일(`profiles list`),
노출면(열린 수신 포트, 방화벽 상태).

## 3단계 — `external_probes` 동의 필요 (예정)

DNS 응답과 DoH 기준값 비교, 고정 호스트의 TLS 발급자 변화, 공인 IP·ASN 변화.

## 판정할 수 없는 주기는 판정하지 않는다

주 인터페이스가 없으면 링크가 끊긴 것이고, 그 순간의 경로·리졸버·ARP는
"없음"일 뿐 **무엇이 바뀌었다는 뜻이 아닙니다.** 그것을 정상 상태로 보고
비교하면 링크가 한 번 깜빡일 때마다 `high`가 쏟아집니다.

실측에서 한 주기(5초) 동안 인터페이스가 사라졌다 돌아왔고, 그 한 주기 때문에
네 가지가 한꺼번에 잘못됐습니다.

- 기본 경로 변경이 `high`로, 억제 없이
- 끊김 원인이 "판단 근거 부족" (신호가 전부 비어 있었으므로)
- 보호 상실이 "신뢰 여부 판단 불가" (암호화 방식을 못 읽었으므로)
- 엉뚱한 조사가 열렸다 3초 뒤 "네트워크가 바뀌어 중단"

그런 주기는 기록만 남기고 판정하지 않습니다(`LINK_ABSENT`). 기준선도 건드리지
않습니다. 다음 완전한 관측은 **빈 관측이 아니라 마지막 정상 관측과** 비교되고,
그 사이에 공백이 있었다는 사실이 링크 재시작의 근거가 됩니다.

## 기록에 남기는 것은 판정에 쓰는 것만

`SHARED_MAC` 판정은 한 MAC 이 IP를 **3개 이상** 쥐고 있을 때만 씁니다. 그런데
수집기가 2개짜리까지 전부 기록하고 있었고, 큰 네트워크에서 그 항목 224개가
샘플 하나의 22KB — **하루 기록의 59%** — 를 차지했습니다. 판정에 한 번도
쓰이지 않는 데이터였습니다.

덤으로 탐지 누락도 있었습니다. IP 2개짜리 MAC은 이미 기록에 있으므로, 그것이
3개가 되어도 "새로 나타남"으로 잡히지 않았습니다.

이제 판정 기준(3개)을 수집 단계에서 적용하고, 주소 목록은 판정 근거로 쓰는
만큼(8개)만, 항목 수는 20개까지 남깁니다. **자른 사실은 총계로 남깁니다** —
주소를 자르면서 개수까지 잃으면 판정이 실제보다 작은 수를 말하게 됩니다.

## 누적 카운터와 주기 간격

`netstat -s -p arp` 같은 누적 카운터는 **반드시 시간으로 나눠서** 씁니다.
주기 사이의 간격은 일정하지 않습니다 — 잠자기로 939초가 벌어진 구간의
증가분을 5초 주기의 증가분과 같은 잣대로 비교해 실제로 거짓 경보가 났습니다
(초당으로 환산하면 오히려 평소의 1/12이었습니다). 측정이 크게 벌어진 주기는
아예 건너뜁니다. 그 구간의 증가분이 무엇을 뜻하는지 알 수 없기 때문입니다.

같은 이유로 왕복 시간 급변은 **연속 3주기** 높을 때 한 번만 알립니다. 한 주기만
보고 알리면 무선 구간의 정상적인 흔들림이 전부 사건이 됩니다 — 실측에서 한
시간에 아홉 번까지 떴습니다.

## 지금은 할 수 없는 것

| 하고 싶은 것 | 막는 것 |
|---|---|
| deauth 프레임 관측 | BPF 접근에 sudo 필요 |
| ARP 폭주의 실체 확인 | 같음. 지금은 카운터 증가분만 본다 |
| VPN 재연결 중 터널 밖 유출 확인 | 패킷 관측 없이는 간접 증거뿐이라 상한이 `의심` |
| 수동 도청 탐지 | 원리적으로 흔적이 없다 |
