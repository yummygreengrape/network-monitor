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
| `ARP_REPLY_SPIKE` | 보안 | 의심 | `netstat -s -p arp` |
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
| `LATENCY_SPIKE` | 품질 | 의심 | ping |
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

## 2단계 (예정)

Wi-Fi 로밍·해제·인증 이벤트(`log show`), 신뢰 저장소 변화
(`security dump-trust-settings`), 설정 프로파일(`profiles list`),
노출면(열린 수신 포트, 방화벽 상태).

## 3단계 — `external_probes` 동의 필요 (예정)

DNS 응답과 DoH 기준값 비교, 고정 호스트의 TLS 발급자 변화, 공인 IP·ASN 변화.

## 지금은 할 수 없는 것

| 하고 싶은 것 | 막는 것 |
|---|---|
| deauth 프레임 관측 | BPF 접근에 sudo 필요 |
| ARP 폭주의 실체 확인 | 같음. 지금은 카운터 증가분만 본다 |
| VPN 재연결 중 터널 밖 유출 확인 | 패킷 관측 없이는 간접 증거뿐이라 상한이 `의심` |
| 수동 도청 탐지 | 원리적으로 흔적이 없다 |
