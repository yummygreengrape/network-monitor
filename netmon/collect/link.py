"""연결 품질 측정.

기본 대상은 게이트웨이와 이미 설정된 시스템 리졸버뿐이다. 둘 다 이미
내 트래픽을 보고 있는 상대라 새로 알려지는 정보가 없다. 공개 인터넷
도달성(1.1.1.1 등)은 새 제3자에게 내 IP 를 알리므로 동의 항목으로 뺀다.
"""
from __future__ import annotations

import concurrent.futures
import re
from typing import Any, Dict, List, Optional

from ..model import ident
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


def ping(target: str, count: int = DEFAULT_COUNT, wait_ms: int = DEFAULT_WAIT_MS,
         timeout: float = 4.0) -> Dict[str, Any]:
    family = ["ping6"] if ":" in target else ["ping"]
    argv = family + ["-n", "-c", str(count), "-W", str(wait_ms), target]
    r = run(argv, timeout=timeout)
    out = parse_ping(r.out)
    out["reachable"] = bool(out["replies"])
    return out


def probe() -> Capability:
    return Capability(NAME, OK, "ping 사용 가능", provides=["gateway_rtt", "loss"])


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

    results: Dict[str, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as pool:
        count = int(ctx.get("ping_count", DEFAULT_COUNT))
        futures = {name: pool.submit(ping, addr, count) for name, addr in targets.items()}
        for name, fut in futures.items():
            try:
                results[name] = fut.result(timeout=10)
            except Exception as exc:  # 측정 실패는 관측값이지 예외가 아니다
                results[name] = {"reachable": False, "error": str(exc)[:80]}

    return {
        "targets": {n: ident("ipv4" if "." in a else "ipv6", a) for n, a in targets.items()},
        "results": results,
        "gateway_reachable": results.get("gateway", {}).get("reachable"),
        "gateway_rtt_ms": results.get("gateway", {}).get("rtt_ms"),
    }
