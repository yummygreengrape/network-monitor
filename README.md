# network-monitor

A monitor for macOS that tells you whether something happened on the network you are connected to
that **affects your connection or your security**.

- **Connection quality and security are judged separately.** One observation can produce findings
  on both axes; a quality event never hides a security event.
- **Every finding carries its evidence and a confidence level.** `confirmed`, `suspect` and
  `possible` are never mixed.
- **Changes you caused yourself are suppressed, not deleted.** Suppressed findings stay in the record.
- **Least privilege by default.** No sudo, no outbound requests, and VPN monitoring and location
  access start switched off.

> Most of the text in new findings, reports, the live view and the setup wizard follows the language
> setting: Korean by default, English after the wizard's first question or `netmon lang en`. Some
> labels and some command-line output are still Korean only — see
> [Language and wording](#language-and-wording). The documents in `docs/` are written in
> Korean. A Korean summary of this README is at the end (한국어 요약).

## Requirements

macOS and Python 3.9 or later. Nothing else to install. If `python3` is missing, installing the Xcode
Command Line Tools provides `/usr/bin/python3`.

## Where to run it

Right after cloning, it only runs **from inside the repository**:

```
$ cd ~
$ ./netmon.sh setup
zsh: no such file or directory: ./netmon.sh     ← because you are outside the repository
```

There are three ways:

```
cd <repository>/network-monitor && ./netmon.sh setup    move into the repository
/full/path/to/netmon.sh setup                           use the full path
./netmon.sh link                                        link it, then run netmon from anywhere
```

`link` creates a symbolic link in a writable directory on your `PATH`. It does not use sudo, and
`netmon link remove` undoes it. If no directory on `PATH` is writable, it tells you how to add one.
The setup wizard asks about this too, and the default is to create the link.

```
netmon link           make netmon runnable from anywhere
netmon link status    where the link is and what it points to
netmon link remove    undo
```

The examples below write `netmon`, assuming the link exists. Without it, read them as `./netmon.sh`
run inside the repository.

## First run

```
netmon setup
```

The wizard asks, one at a time: the language first, then what to turn on — measurement interval,
where to keep records and for how long, location access, VPN monitoring, outbound checks, and whether to run always-on.
**Pressing Enter at every prompt gives safe values** — no sudo, no outbound requests, and no
always-on registration.

Running `netmon` with no arguments also suggests the wizard when there is no configuration yet.
To take the defaults without questions, use `netmon setup --defaults`.

## Usage

```
netmon doctor           what works and what does not on this machine
netmon once             measure a single cycle
netmon run              measure continuously (Ctrl+C to stop)
netmon report           today's summary
netmon report --redact  print with identifiers masked (for sending to someone)
netmon location setup   build the location helper and request access (evil twin detection)
netmon service install  keep it running (starts automatically at login)
netmon investigate list ongoing investigations
netmon watch            live view (the agent keeps monitoring)
```

## Live view

```
netmon watch                    current state, open investigations, recent findings
netmon watch --redact           with identifiers masked (for screen sharing)
netmon watch -v                 include suppressed findings
```

`watch` **does not measure anything itself.** It only reads what the always-on agent recorded, so
opening a window does not double the measurements, and closing it does not stop monitoring. If the
agent stops, the screen says it looks stalled.

## Meaningful signals are followed up

"The gateway MAC changed" is a confirmed fact, but whether it is an attack or a replaced access point
can only be told **from what happens next**. When a meaningful signal appears, an investigation opens
and keeps measuring more often until it reaches a conclusion.

What counts as meaningful is configurable, and **investigations adjust it themselves.** If a MAC change
coincides with DHCP tampering, the watch widens; if VPN drops keep recurring, wireless link quality is
watched as well. Every change of criteria records its reason and the before and after values.

```
netmon.sh investigate rules                        show the current criteria
netmon.sh investigate rules --set severities=high  narrow them
netmon.sh investigate show <id>                    how the criteria moved
```

Details are in the "이어지는 조사" (ongoing investigations) section of
[docs/detections.md](docs/detections.md).

## Always-on

```
netmon service install     register
netmon service status      check the state
netmon service uninstall   unregister (records are kept)
```

This creates a single file, `~/Library/LaunchAgents/io.github.network-monitor.plist`. It **does not use
sudo**, does not change system settings, and `uninstall` undoes it. The `setup` wizard offers it as
well; the default is not to register.

Once registered, it starts at login and restarts if it stops. It runs at low priority (`Nice 5`,
`Background`, `LowPriorityIO`) so it does not get in the way of other work — measured at 0.0% CPU and
about 17 MB of memory. `launchd` does not rotate its output files, so once they pass 5 MB the oldest
part is trimmed.

Moving the repository elsewhere breaks the registered path. `service status` and `doctor` report
that state, and running `service install` again fixes it.

Run `doctor` first. Which detections are available depends on the model, the macOS version and the
permissions granted, and `doctor` tells you **what does not work and why**. A detection silently
missing on someone else's machine is this tool's most dangerous failure mode, so nothing unavailable is
hidden.

Configuration lives in `~/.config/network-monitor/config.json`, and records go to `data/` next to it
by default. Choose another location in the wizard, or with `--log-dir` or `NETMON_LOG_DIR`. When you
register the always-on agent, the chosen location is also written to the configuration file, so
`netmon report` reads the same place the agent writes to.

## Permissions and consent

Two things turn on **only with your consent**. Without it, the related features stay off and every
other detection keeps working.

```
netmon consent list                       read what is requested and why
netmon location setup                     build the location helper and request access
netmon location status                    current permission state
netmon consent revoke location            revoke (the related features are turned off as well)
```

### Why location access goes through a separate app

macOS grants location access **per app**. A script run from a terminal has no app to ask on its
behalf, so no prompt appears, and it cannot inherit another app's approval. So `location setup` builds
a small helper app (`NetworkMonitorLocation.app`) in the configuration directory; that app holds the
permission and returns **only the SSID and BSSID**.

The helper does not read coordinates (it never calls `startUpdatingLocation`) and does not scan
nearby access points. Those two values are all it needs. The source is in
[tools/location-helper/request_location.m](tools/location-helper/request_location.m).

| Item | What it is for | What leaves the machine |
|---|---|---|
| `location` | Reads the SSID and BSSID to tell an evil twin from normal roaming | Nothing |
| VPN monitoring | Connection state and the cause of drops. For WARP, state broadcasts and drop-cause lines from the daemon log (`/Library/Application Support/Cloudflare/cfwarp_service_log.txt`) are stored in local samples with addresses and structures cut out (not a consent item, but off by default) | Nothing. Turning on tunnel endpoint probing (`vpn.tunnel_probe`) follows `external_probes` below |
| `external_probes` | Reachability of the tunnel's far end in cycles where the VPN is not connected. DNS hijack, TLS issuer and public IP checks are planned under the same consent but not implemented yet ([docs/detections.md](docs/detections.md)) | Today only ICMP to the tunnel endpoint, and only when tunnel endpoint probing (`vpn.tunnel_probe`) is also turned on. While a VPN is not connected (down or renegotiating) it sends ICMP to the tunnel endpoint address the provider reported — ping_count packets, 1 by default. The decision uses the previous cycle's state, so a probe may also go out on the first cycle after reconnecting, and at most 12 packets go out per provider per outage. The address is **the one the provider wrote into its reason string**, and nothing is sent unless it is a public unicast address. The planned checks would send a fixed set of lookup names and your source IP |

Before you consent, the SSID and BSSID are **not even recorded** — even if location access happens to
be open.

## Language and wording

Korean and English are supported.

```
netmon lang           show the current language and the available ones
netmon lang en        switch to English
netmon lang ko        switch to Korean
NETMON_LANG=en netmon report    another language for one run only
```

**Most of the text that follows the language setting lives in one place.**

```
netmon/messages/ko.py   Korean
netmon/messages/en.py   English
```

Finding summaries (investigation findings included), report headings, the live view, the setup
wizard's questions and part of the CLI output are all there. To change that wording, open only these
files. To add a language, create another file with the same names and register it in `CATALOGUES` in
`netmon/messages/__init__.py`.

Not everything goes through the catalogues yet. These are hard-coded in Korean and do not follow
`netmon lang`:

- the command-line `--help` text;
- most of the output of `doctor`, `consent` (including the consent descriptions),
  `investigate list`/`show`/`rules`, `service status`/`install` and `location`;
- the reasons and errors `link` prints (the wizard's link step shows them too), the suppression note
  and network line printed by `once`/`run`/`replay`, and the setup wizard's link failure message;
- the first-run prompt shown when `netmon` runs with no configuration, and the "가림 대상:" line at the
  end of `report --redact`;
- some labels inside reports, the live view and finding summaries — axis names, counts, relative
  times ("…초 전"), the investigation criteria summary and the first-hop method name;
- outside the Python package: the location helper's app name and the macOS permission prompt text
  (`tools/location-helper/Info.plist`), and the messages of `netmon.sh` and the helper's build script.

The style rules are written at the top of each catalogue file and enforced by a test
(`tests/test_messages.py`).

- Korean: results and states **end in a noun form** — "게이트웨이 왕복 시간이 112ms 로 크게 증가함
  (평균 20ms)." Questions and instructions stay as they are.
- English: terse and declarative, no first or second person.
- Both catalogues must have **exactly the same names and placeholders**. A test checks this.

Changing the language **does not change findings already recorded.** Records are never rewritten
afterwards. Parts built when you view them, such as report headings and the live view, switch at once
(apart from the Korean-only labels above).

## Privacy

Logs keep identifiers verbatim. Hashing them at record time would keep "the MAC changed from a to b"
but make it impossible to tell whether that `b` is the access point you saw yesterday or your phone,
which destroys the value of an investigation. Logs stay on your own machine, so the originals are
kept, and **you mask them with `--redact` when sending them to someone.**

**Reports and the live view never show identifiers.** Summaries carry no identifiers, and evidence
(`evidence`) is not printed on screen. This was checked on real data and is kept by tests — an
unmasked report can be shown as is.

`--redact` matters **when exporting observations to a file** (`capture`). Fields wrapped as identifiers
become a token as a whole. Free-form strings whose shape cannot be fixed, such as the reason string a
VPN provider supplies (including lines cut from the WARP daemon log), are searched for IPv4 and IPv6
addresses only, and those are replaced with the same tokens:

- Ports are kept. When a port follows a compressed IPv6 address without brackets, the address and the
  port become one token. In the IPv4-embedded IPv6 form `2001:db8::192.0.2.1:2408` only the address
  becomes a token and the port stays — that form is an IPv6 token, so it differs from the token of a
  value wrapping the same IPv4 address.
- Forms that are not valid IPv6 once the IPv4 part is included (`:::192.0.2.1`, `2001:db8:192.0.2.1`
  with too few groups, `2001:db8:1:2:3:4::192.0.2.1` with `::` after all groups are used, and so on)
  have only the IPv4 part masked and the leading part left — and that leading part may itself be an
  IPv6 form. An IPv4-embedded IPv6 address followed by a dot and letters
  (`2001:db8::192.0.2.1.example`) also has only its IPv4 part masked.
- Conversely, a hex word in front (`cafe::192.0.2.1`) and an IPv4 address joined to a MAC by a colon
  are masked together with that word or MAC as one token.
- Only ASCII digits count as part of an address — full-width and Arabic-Indic digits are not treated as
  part of it and are left (an ASCII address next to them is masked).

Some things in free-form strings are not masked: **identifiers that are not addresses** (names and
the like), addresses joined to letters, digits or dots on either side (and colons, for IPv6) such as
`ip192.0.2.1`, `host.192.0.2.1` and `addr:2001:db8::7`, truncated address fragments, octets with a
leading zero (`192.0.2.001`), eight-group IPv6 with a port attached directly by a colon, and the IPv6
nibble form of reverse-lookup names.

Masking is an HMAC with a local salt, so the same value becomes the same token, and relationships such
as "changed and then changed back" remain visible after masking. The salt is kept in
`~/.config/network-monitor/salt`, readable by the owner only (600).

## What it does not do

- It does not scan other hosts. It does not reproduce attacks such as ARP spoofing or deauth.
- It does not use sudo, change system settings, or register itself to run always-on.
- It does not send network identifiers anywhere.

## Layout

```
netmon/collect/     one module per data source. parse_*(string) are pure functions; collect() runs the commands
netmon/detect/      judgement. (previous observation, current observation, context) → findings. Pure functions
netmon/liveness.py  first-hop reachability without relying on ICMP
netmon/baseline.py  baselines, updated before and after judgement
netmon/redact.py    identifier masking
```

Collection and judgement are split for testing. Once observations are captured in the field
(`netmon.sh capture N --redact`), later changes to judgement are reproduced without a network.

```
netmon capture 60 -o /tmp/cafe.jsonl --redact
netmon replay /tmp/cafe.jsonl
```

## Development

```
PYTHONPATH=. python3 -m unittest discover -s tests -t .
tools/leak-check.sh          check whether what is about to be committed contains environment identifiers
```

All tests use synthetic input. Values captured from real environments are never put in the repository.

## What has been verified

It runs always-on on two Macs (a wireless laptop and a wired desktop) and is being refined there.
**Almost every defect found so far has been a false positive or an overstatement.**

Verified

- Every stage-1 detection works on real machines. On the wired machine the Wi-Fi detections drop out
  as "not applicable", and without a VPN tool the VPN ones drop out as "none" — **stating the reason**.
- It has caught real VPN drops. It **cannot tell which segment was at fault**, though — it records only
  that the first hop answered (a single batch of ICMP cannot separate the local segment from the far
  end of the tunnel).
- Sleep, reconnects, link flaps and moving between networks do not throw off the findings. The
  exception: moving to a different network on the same subnet with the same IP, across cycles where the
  SSID could not be read, can raise an alert (the remaining limits under "SSID 를 읽다가 못 읽게 된
  주기" in [docs/threat-model.md](docs/threat-model.md)).
- Masking (`--redact`) left no wrapped identifiers on real data (measured 2026-09-16). Masking of
  free-form strings was measured again on 2026-09-27: among 300,000 free-form strings in real samples
  and events (09-16 to 09-26), 146 contained an address, and after masking 0 address candidates
  remained (the detector also counts IPv4 and IPv6 joined to letters, digits or dots on either side and
  eight-group IPv6 with a port; it does not count octets with a leading zero, truncated fragments or
  identifiers that are not addresses). State broadcasts from the WARP daemon log are stored by name only,
  so the stored state lines have no addresses even before masking (about 5 hours of retained log: of 3,451 state
  broadcast lines, 3,282 carried an address in the message; repeated broadcasts are not stored, so 192
  state lines were stored, 56 of them from broadcasts that carried an address, and 0 addresses remained
  in the stored text). Classification and error lines have their addresses cut out with the same
  address matching that masking uses, but the 26 such lines in the retained log had no address to cut, so this is not confirmed
  on real data (only by synthetic tests — the forms that cannot be masked, listed under
  [Privacy](#privacy), remain in stored text as well). Reports print only summaries, so identifiers do
  not appear even without masking.

Not yet verified

- **The evil twin finding (`EVIL_TWIN_CANDIDATE`) has never been verified against a real situation.**
  Normal roaming within one SSID has been confirmed on real data.
- Retention cleanup and log rotation are confirmed by unit tests only. Those paths run only at UTC
  midnight and past 5 MB.
- Stage-2 and stage-3 detections are not implemented. What is missing is written down in
  [docs/detections.md](docs/detections.md).

Many thresholds **still rest on thin evidence.** Values such as "10 per second" for an ARP reply
spike, "3 consecutive cycles" for a round-trip time jump and "30 cycles" for investigation cooldown
were not set after living through enough real attacks or outages.

If you run into a false positive or a missed event, capturing that stretch with
`netmon capture N --redact` and sending it helps. It can be reproduced from the masked observations
alone.

## Documents

Written in Korean.

- [docs/threat-model.md](docs/threat-model.md) — what networks are assumed, and who can do what
- [docs/data-sources.md](docs/data-sources.md) — the commands used and the pitfalls measured
- [docs/detections.md](docs/detections.md) — the detections and their confidence ceilings

## 한국어 요약

현재 연결된 네트워크에서 **내 연결과 보안에 영향을 주는 일**이 생겼는지 알려 주는 macOS용 감시
도구입니다. 판정·보고서·실시간 화면·설정 마법사 문구의 기본 언어는 한국어이고 `netmon lang en` 으로
영어로 바꿀 수 있습니다. 다만 `--help`, `doctor`·`consent`·`investigate` 등 일부 CLI 출력, 보고서·실시간
화면·판정 요약의 일부 이름표, 위치 헬퍼의 권한 요청 창 문구는 아직 한국어만 나옵니다. `docs/` 문서도 한국어로 씁니다.

- **연결 품질과 보안을 따로 판정합니다.** 한 관측이 두 축 모두에서 판정될 수 있고, 품질 사건이 보안
  사건을 가리지 않습니다.
- **판정마다 근거와 확신도가 붙습니다.** `확정`·`의심`·`가능`을 섞지 않습니다. 내 행동으로 생긴
  변화는 억제하되 지우지 않습니다.
- **기본값은 최소 권한입니다.** sudo를 쓰지 않고, 외부로 요청을 보내지 않으며, VPN 감시와 위치
  권한은 꺼진 상태로 시작합니다. `netmon setup` 마법사에서 엔터만 눌러도 안전한 값입니다.
- **유의미한 신호는 조사로 이어 봅니다.** 게이트웨이 MAC 변경처럼 그다음 일로만 갈리는 신호가
  잡히면 더 자주 측정하며 결론이 날 때까지 보고, 조사가 기준을 바꾸면 이유와 이전·이후 값을
  남깁니다.
- **동의해야만 켜지는 것이 둘입니다.** `location`(SSID·BSSID 로 evil twin 과 정상 로밍 구분, 밖으로
  나가는 것 없음)과 `external_probes`(VPN 이 연결돼 있지 않은 주기의 터널 상대편 도달성 — DNS 가로채기·
  TLS 발급자·공인 IP 확인은 같은 동의에 묶일 예정이며 아직 구현 전)입니다. 터널 엔드포인트 측정을 켜면 VPN 이 연결돼 있지 않은 동안(끊김·재협상)
  공급자가 사유에 적어 준 터널 상대편(엔드포인트) 주소로 ICMP 를 보냅니다(ping_count 만큼, 기본 1발).
  보낼지는 직전 주기의 상태로 정하므로 다시 연결된 직후 첫 주기에도 나갈 수 있고, 공급자마다 한
  끊김에 최대 12발까지만 보냅니다. 동의하기 전에는 SSID·BSSID를 기록조차 하지 않습니다.
- **로그에는 식별자 원문이 남고, 남에게 보낼 때 `--redact` 로 가립니다.** 보고서와 실시간 화면에는
  식별자가 나오지 않습니다. 가리기는 로컬 솔트 HMAC 이라 같은 값이 같은 토큰이 되며, 자유 문자열에서
  가리지 못하는 모양은 위 [Privacy](#privacy) 절에 적었습니다.
- **하지 않는 것**: 다른 호스트 스캔, 공격 재현, sudo, 시스템 설정 변경, 네트워크 식별자 외부 전송.
- **어디까지 확인됐나**: 두 대(무선 노트북, 유선 데스크톱)에서 상시 실행 중이며, 지금까지 찾은 결함은
  거의 전부 오탐과 과잉 단정이었습니다. evil twin 판정은 실제 상황으로 검증된 적이 없고, 임계값의
  상당수는 아직 근거가 얇습니다. 오탐이나 놓친 것을 만나면 `netmon capture N --redact` 로 그 구간을
  떠서 알려 주세요.

## License / 라이선스

MIT. See [LICENSE](LICENSE).

MIT 라이선스입니다. [LICENSE](LICENSE)를 참조하세요.
