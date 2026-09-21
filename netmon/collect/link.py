"""연결 품질 측정.

기본 대상은 게이트웨이와 이미 설정된 시스템 리졸버뿐이다. 둘 다 이미
내 트래픽을 보고 있는 상대라 새로 알려지는 정보가 없다. 공개 인터넷
도달성(1.1.1.1 등)은 새 제3자에게 내 IP 를 알리므로 동의 항목으로 뺀다.
"""
from __future__ import annotations

import concurrent.futures
import re
from typing import Any, Dict, List, Optional

from .. import liveness
from ..model import ident, unwrap
from ..util import OK, Capability, run

NAME = "link"

_TIME_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")
_LOSS_RE = re.compile(r"([0-9.]+)% packet loss")


def parse_ping(text: str) -> Dict[str, Optional[float]]:
    """`ping -c N` 출력에서 왕복 시간과 손실률."""
    times = [float(m) for m in _TIME_RE.findall(text)]
    loss = _LOSS_RE.search(text)
    return {
        "rtt_ms": round(sum(times) / len(times), 2) if times else None,
        "rtt_max_ms": round(max(times), 2) if times else None,
        "loss_pct": float(loss.group(1)) if loss else (None if times else 100.0),
        "replies": len(times),
    }


# macOS ping 은 패킷 간격이 1초 고정이다(1초 미만은 root 권한이 필요하다).
# -c 2 로 재면 한 주기가 최소 2초가 되어 3초 간격 측정이 밀린다. 주기마다
# 한 번만 쏘고, 손실은 주기 사이의 연속 실패로 본다 (netmon/liveness.py).
DEFAULT_COUNT = 1
DEFAULT_WAIT_MS = 800

# 무응답 대상 기준 ping 한 번의 고정 오버헤드(초). -W 는 총 대기가 아니라
# 이 오버헤드 위에 더해진다 — 실측 -W 800 → 약 1.84초
# (docs/data-sources.md "macOS `ping`의 `-W`는 총 대기 시간이 아니다").
PING_OVERHEAD_SECONDS = 1.0

# subprocess 제한과 결과 대기. **둘 다 위 소요보다 넉넉히 크게 잡는다** —
# 여기서 먼저 끊으면 응답할 수 있었던 대상이 손실로 둔갑해서, 손실률이
# 네트워크가 아니라 우리 제한 시간의 산물이 된다.
PING_TIMEOUT_SECONDS = 4.0
RESULT_WAIT_SECONDS = 10.0


def ping_seconds(wait_ms: int = DEFAULT_WAIT_MS, count: int = DEFAULT_COUNT) -> float:
    """무응답 대상에게 ping 한 번이 걸리는 시간(초) 추정."""
    return PING_OVERHEAD_SECONDS + count * (wait_ms / 1000.0)


def ping(target: str, count: int = DEFAULT_COUNT, wait_ms: int = DEFAULT_WAIT_MS,
         timeout: float = PING_TIMEOUT_SECONDS) -> Dict[str, Any]:
    family = ["ping6"] if ":" in target else ["ping"]
    argv = family + ["-n", "-c", str(count), "-W", str(wait_ms), target]
    r = run(argv, timeout=timeout)
    out = parse_ping(r.out)
    out["reachable"] = bool(out["replies"])
    return out


def probe() -> Capability:
    return Capability(NAME, OK, "ping 사용 가능", provides=["gateway_rtt", "loss"])


# --- 이상 징후 주기의 첫 홉 다발 측정 ---
#
# 평소에는 주기마다 1발이다. 그래서 끊김을 되짚을 때 "첫 홉은 응답했다" 의
# 근거가 그 1발의 참/거짓뿐이었고 손실률도 흔들림도 알 수 없었다
# (2026-09-21 WARP 끊김 12건). 이상 징후가 있는 주기에만 1발짜리 ping 을
# 여러 개 **동시에** 띄운다. 순차 `-c 3` 은 macOS 의 1초 고정 간격 때문에
# 주기를 넘긴다. 동시에 띄우므로 총 소요는 ping 하나와 같다.
BURST_PROBES = 3

# 유효 주기가 이보다 짧으면 다발을 하지 않는다. 조사 중에는 주기가 2~3초로
# 좁혀지는데, 무응답 대상 한 번이 실측 약 1.84초라 여유가 없다.
BURST_MIN_INTERVAL = 3.0

# 다발 측정임을 관측에 남기는 문구. 이 값들은 **같은 순간에 나란히 잰 것**이라
# 시간에 걸친 지터가 아니다. 읽는 쪽이 이것을 시계열로 오해하면 안 된다.
BURST_NOTE = "같은 순간 동시 측정 — 시간에 걸친 지터가 아님"


def vpn_states(vpn_block: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """VPN 수집 결과에서 공급자 → 상태."""
    out: Dict[str, Any] = {}
    for name, st in (vpn_block or {}).items():
        if isinstance(st, dict):
            out[name] = st.get("state")
    return out


def first_hop_silent(prev_link: Optional[Dict[str, Any]] = None,
                     prev_arp: Optional[Dict[str, Any]] = None,
                     method: Optional[str] = None) -> bool:
    """직전 주기의 첫 홉이 **이 망의 판정 방법 기준으로** 무응답이었는가.

    `gateway_reachable`(ICMP)만 보면 안 된다. 게이트웨이가 ICMP 를 막아 둔
    망에서는 그 값이 **정상 상태에도 매 주기 False** 다 — liveness 가 바로
    그래서 보정 뒤에 ARP 로 판정을 바꾼다(netmon/liveness.py). ICMP 를 그대로
    이상 징후로 세면 아무 일도 없는데 주기마다 3발이 나가고, "정상 상태가
    이어지는 동안에는 켜지지 않는다"(AC-2)가 깨진다.

    그래서 liveness 가 고른 방법과 같은 신호를 본다.
      - ICMP 로 판정하는 망: `link.gateway_reachable` 이 False
      - ARP 로 판정하는 망: `arp.gateway_mac` 이 비었다 — 그 망에서 liveness 가
        도달성을 판정하는 신호가 이것이기 때문이다.
      - 보정 중(`unknown`): ARP 나 ICMP 가 살아 있다고 말하면 아니고, ICMP 가
        명시적으로 False 일 때 참이다.

    **이 신호가 실제 끊김을 드러낸다는 근거는 없다.** 여기서 말할 수 있는 것은
    "그 망에서 liveness 가 도달성을 보는 신호를 같이 본다" 까지다.
      - macOS 의 ARP 캐시는 해석된 항목을 바로 버리지 않는다. 수집기는 파싱해
        둔 만료 열(`collect/arp.py` 의 `expire_o`·`expire_i`)을 판단에 쓰지 않아,
        첫 홉이 끊긴 뒤 이 값이 언제 비는지는 모른다 — 늦거나 끝내 뜨지 않을 수 있다.
      - 반대로 **첫 홉이 살아 있는데 비는 주기도 있었다.** 보관 샘플 6일치
        (2026-09-16~21)에서 `gateway_mac` 이 빈 주기 297건 중 게이트웨이 주소가
        함께 있던 것은 4건뿐이고(나머지는 게이트웨이 자체를 모르는 주기), 그 4건
        중 3건은 같은 주기의 ICMP 가 응답했다.
    그래서 이 갈래는 드물게 헛켜질 수 있다. 다발은 판정이 아니라 측정을 늘리는
    것뿐이라 그 대가는 그 주기의 ping 2발이다.

    **모르는 것을 근거로 켜지 않는다.** 측정하지 않은 주기(`gateway_reachable`
    None)와 수집기가 통째로 실패해 블록이 빈 주기는 거짓으로 둔다. 후자는
    liveness 와 갈라지는 지점이다 — `liveness.evaluate` 는 빈 arp 블록을 ARP
    판정 망에서 "죽음" 으로 읽어 `gw_fail_streak` 를 올리지만, 여기서는 없던
    패킷을 만들지 않으려고 보수적으로 켜지 않는다.

    보정 중에 ARP 도 ICMP 도 살아 있다고 말하지 않으면 참이다. 이것도
    `liveness.evaluate` 와 갈라진다 — 그쪽은 같은 입력에서 `link_active` 까지
    보고 판정을 보류한다(None). 여기서는 보류하지 않고 다발로 재 본다:
    측정을 늘리는 쪽이라 판정을 만들지 않고, 그 상태가 이어지면 어차피 보정이
    끝나 방법이 정해진다.
    """
    icmp = (prev_link or {}).get("gateway_reachable")
    arp_ok = bool(unwrap((prev_arp or {}).get("gateway_mac")))
    if method == liveness.ICMP:
        return icmp is False
    if method == liveness.ARP:
        # 빈 블록은 ARP 수집 실패다. MAC 이 없는 것과 구분한다.
        return bool(prev_arp) and not arp_ok
    if arp_ok or icmp is True:
        return False
    return icmp is False


def first_hop_anomaly(prev_link: Optional[Dict[str, Any]] = None,
                      prev_vpn: Optional[Dict[str, Any]] = None,
                      before_vpn: Optional[Dict[str, Any]] = None,
                      prev_arp: Optional[Dict[str, Any]] = None,
                      method: Optional[str] = None) -> bool:
    """이번 주기에 다발로 잴 만한 이상 징후가 **직전 주기**에 있었는가.

    둘 중 하나면 참이다 (AC-2).
      - 직전 주기의 첫 홉이 무응답 — 이 망의 판정 방법 기준으로 본다
        (`first_hop_silent`). `method` 는 liveness 가 고른 방법이다.
      - 직전 주기에 VPN 상태가 바뀌었다 (직전 주기와 그 앞 주기의 비교).
        "connected 가 아니면서 그 앞과 다름" 은 이 조건에 포함된다.

    **상태가 그대로면 켜지 않는다.** connected 가 아닌 것만으로 켜면,
    설치만 해 두고 꺼 둔 공급자가 있는 사람에게 매 주기 3발이 나간다.

    같은 주기의 VPN 상태로는 켤 수 없다 — 수집 순서상 link 가 vpn 보다
    먼저 돈다 (netmon/engine.py). 그래서 한 주기(5초)만에 끝나는 끊김은
    다발 측정이 켜지지 않고, 첫 홉 증거가 평소 주기와 같이 ping 명령 한
    번뿐이다(보낸 발 수는 `ping_count` 설정에 달렸고 관측에 남지 않는다).
    """
    if first_hop_silent(prev_link, prev_arp, method):
        return True
    if before_vpn is None:
        return False  # 비교할 앞 주기가 없다. 바뀌었다고 말할 수 없다.
    now = vpn_states(prev_vpn)
    before = vpn_states(before_vpn)
    return any(now.get(k) != before.get(k) for k in set(now) | set(before))


def burst_probes(ctx: Dict[str, Any]) -> int:
    """이번 주기에 첫 홉으로 띄울 ping 개수. 1 이면 평소 동작이다."""
    if not ctx.get("first_hop_burst"):
        return 1
    interval = ctx.get("interval")
    try:
        if interval is not None and float(interval) < BURST_MIN_INTERVAL:
            return 1
    except (TypeError, ValueError):
        pass
    try:
        want = int(ctx.get("burst_probes") or BURST_PROBES)
    except (TypeError, ValueError):
        want = BURST_PROBES
    return max(1, want)


def merge_probes(probes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """동시에 띄운 1발 ping 들을 관측 하나로 합친다.

    **판정이 보는 값(`reachable`·`rtt_ms`)은 첫 발 그대로다** (AC-1b).
    3발 중 하나만 응답한 것을 "도달함" 으로 삼으면 첫 홉 연속 실패 셈
    (`baseline.gw_fail_streak`)과 지연 기준선(`rtt_ewma`)이 1발 때와 달라져,
    같은 네트워크에서 `FIRST_HOP_BRIEF_GAP`·`FIRST_HOP_UNREACHABLE` 이
    전과 다르게 뜬다. 나머지 발은 **증거로만** 싣는다.

    보낸 수는 **실제로 띄운 개수**다. 명령이 실패했거나 제한 시간을 넘긴
    것도 보낸 것으로 세고 응답 없음으로 친다 — 그래야 손실률이 관측의
    범위(0~100) 안에 머문다.
    """
    first = probes[0] if probes else {}
    sent = len(probes)
    received = 0
    rtts: List[float] = []
    errors: List[str] = []
    for p in probes:
        replies = p.get("replies")
        got = int(replies) if isinstance(replies, int) else int(bool(p.get("reachable")))
        received += max(0, min(got, 1))
        rtt = p.get("rtt_ms")
        if isinstance(rtt, (int, float)):
            rtts.append(float(rtt))
        err = p.get("error")
        if err and err not in errors:
            errors.append(str(err)[:80])
    first_rtt = first.get("rtt_ms")
    out: Dict[str, Any] = {
        # --- 종전 의미 그대로: 판정이 읽는 값 ---
        "reachable": bool(first.get("reachable")),
        "rtt_ms": float(first_rtt) if isinstance(first_rtt, (int, float)) else None,
        "reachable_basis": "first_probe",
        # --- 여기부터는 증거 ---
        "rtt_min_ms": round(min(rtts), 2) if rtts else None,
        "rtt_max_ms": round(max(rtts), 2) if rtts else None,
        "loss_pct": round(100.0 * (sent - received) / sent, 1) if sent else None,
        "sent": sent,
        "received": received,
        "replies": received,
        "any_reachable": received > 0,
        "mode": "burst",
        "concurrent": True,
        "note": BURST_NOTE,
    }
    if errors:
        out["errors"] = errors
    return out


def collect(ctx: Dict[str, Any] = None) -> Dict[str, Any]:
    ctx = ctx or {}
    targets: Dict[str, str] = {}
    if ctx.get("gateway"):
        targets["gateway"] = ctx["gateway"]
    resolver = ctx.get("resolver_external")
    if resolver:
        targets["resolver"] = resolver
    if ctx.get("allow_external") and ctx.get("external_target"):
        targets["public"] = ctx["external_target"]

    if not targets:
        return {"targets": {}, "note": "측정 대상 없음 (게이트웨이 미확인)"}

    count = int(ctx.get("ping_count", DEFAULT_COUNT))
    probes = burst_probes(ctx) if "gateway" in targets else 1
    if probes > 1:
        # ping_count 를 올려 둔 사람이 이상 징후 주기에 오히려 적게 보내면
        # 놀란다. 평소보다 적게 보내지 않는다.
        probes = max(probes, count)

    # 대상 하나에 여러 번 띄울 수 있으므로 작업 단위로 펼친다. 다발은 1발씩
    # 쪼개서 보낸다 — 한 명령으로 여러 발을 쏘면 패킷 간격 1초가 붙는다.
    jobs: List[tuple] = []
    for name, addr in targets.items():
        n = probes if name == "gateway" else 1
        per = 1 if n > 1 else count
        for _ in range(n):
            jobs.append((name, addr, per))

    got: Dict[str, List[Dict[str, Any]]] = {}
    # **worker 수를 작업 수에 맞춘다.** 대상 수에 맞추면 리졸버·공개 IP 가
    # 함께 있을 때 다발이 직렬로 밀려 주기를 넘긴다.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [(name, pool.submit(ping, addr, per)) for name, addr, per in jobs]
        for name, fut in futures:
            try:
                got.setdefault(name, []).append(fut.result(timeout=RESULT_WAIT_SECONDS))
            except Exception as exc:  # 측정 실패는 관측값이지 예외가 아니다
                got.setdefault(name, []).append({"reachable": False, "error": str(exc)[:80]})

    results: Dict[str, Any] = {}
    for name, rs in got.items():
        results[name] = merge_probes(rs) if len(rs) > 1 else rs[0]

    out = {
        "targets": {n: ident("ipv4" if "." in a else "ipv6", a) for n, a in targets.items()},
        "results": results,
        "gateway_reachable": results.get("gateway", {}).get("reachable"),
        "gateway_rtt_ms": results.get("gateway", {}).get("rtt_ms"),
    }
    if "gateway" in targets:
        # 첫 홉 증거가 1발인지 다발인지 판정이 알아야 한다 (요약문에 드러낸다).
        out["first_hop_probes"] = probes
    return out
