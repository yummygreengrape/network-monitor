"""조사 지침.

지침 하나가 하나의 가설을 다룬다. 지침은 세 가지를 정한다.

  initial_criteria  조사를 열 때의 기준 — 무엇을 계속 볼 것인가
  step              주기마다 무엇을 보고, 기준을 어떻게 고칠 것인가
  needs             조사 중에 엔진에 무엇을 더 요청할 것인가

지침은 **순수 함수처럼 쓴다.** 명령을 실행하지 않고 관측과 판정만 본다.
더 필요한 것이 있으면 needs() 로 엔진에 요청한다. 그래야 조사 전체를 합성
입력으로 재현할 수 있다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..liveness import evaluate
from ..model import (CONFIRMED, HIGH, INFO, INFO_SEV, LOW, MEDIUM, POSSIBLE,
                     QUALITY, SECURITY, SUSPECT, Finding, Observation, unwrap)
from .model import ABANDONED, CONCLUDED, Investigation


class Playbook:
    name = "?"
    triggers: Tuple[str, ...] = ()
    max_cycles = 60          # 이 주기 수를 넘기면 결론을 내고 닫는다
    fast_interval: Optional[int] = None   # 조사 중 측정 간격(초)

    def initial_criteria(self, finding: Finding, cur: Observation) -> Dict[str, Any]:
        return {}

    def step(self, inv: Investigation, prev: Optional[Observation],
             cur: Observation, ctx, findings: List[Finding]) -> List[Finding]:
        raise NotImplementedError

    def needs(self, inv: Investigation) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.fast_interval:
            out["interval"] = self.fast_interval
        return out

    # --- 도우미 ---
    @staticmethod
    def _kinds(findings: List[Finding]) -> List[str]:
        return [f.kind for f in findings]

    @staticmethod
    def _retuned(inv: Investigation, change: Dict[str, Any]) -> Finding:
        return Finding(
            axis=INFO, kind="INVESTIGATION_RETUNED",
            confidence=CONFIRMED, severity=INFO_SEV,
            summary="조사 %s 의 기준을 바꿨습니다: %s" % (inv.id, change["reason"]),
            evidence={"investigation": inv.id, "kind": inv.kind, **change},
        )


class L2Identity(Playbook):
    """첫 홉의 정체가 바뀌었다 — 스푸핑인가 접속점 교체인가.

    한 번의 관측으로는 갈리지 않는다. 갈라 주는 것은 그 다음이다.

      되돌아온다          스푸핑이나 전파 간섭 쪽. 정상 교체는 되돌아오지 않는다
      새 값으로 안정된다   교체 쪽. 시간이 지나도 그대로다
      다른 신호가 따라온다 DHCP·DNS·경로가 함께 바뀌면 경로 전체를 쥔 것이다
    """

    name = "l2_identity"
    triggers = ("GW_MAC_CHANGED", "EVIL_TWIN_CANDIDATE", "DUPLICATE_IP",
                "ARP_REPLY_SPIKE", "SHARED_MAC")
    max_cycles = 60
    fast_interval = 2

    # 새 값이 이만큼 이어지면 "안정됐다"고 본다
    STABLE_CYCLES = 20
    # 되돌아오거나 다시 바뀌는 것을 이만큼 보면 요동으로 본다
    FLAP_THRESHOLD = 3

    CORROBORATING = ("DHCP_SERVER_CHANGED", "DHCP_ROUTER_CHANGED",
                     "DHCP_DNS_CHANGED", "RESOLVER_CHANGED", "PROXY_ENABLED",
                     "DEFAULT_ROUTE_CHANGED", "IPV6_DEFAULT_ROUTE_APPEARED",
                     "DUPLICATE_IP")

    def initial_criteria(self, finding: Finding, cur: Observation) -> Dict[str, Any]:
        return {
            # 지금 무엇을 유의미한 신호로 보는가
            "watch_kinds": list(self.CORROBORATING),
            "watch_mac": True,
            "baseline_mac": unwrap(cur.get("arp", "gateway_mac")),
            "changes_seen": 1,
            "stable_for": 0,
            "corroborated": [],
            "seen_macs": [unwrap(cur.get("arp", "gateway_mac"))],
        }

    def step(self, inv, prev, cur, ctx, findings) -> List[Finding]:
        out: List[Finding] = []
        ts = cur.ts
        crit = inv.criteria
        mac = unwrap(cur.get("arp", "gateway_mac"))

        # --- 정체 추적 ---
        if crit.get("watch_mac") and mac:
            if mac != crit.get("baseline_mac"):
                crit["changes_seen"] = int(crit.get("changes_seen", 0)) + 1
                crit["stable_for"] = 0
                crit["baseline_mac"] = mac
                seen = crit.setdefault("seen_macs", [])
                if mac not in seen:
                    seen.append(mac)
                inv.note(ts, "게이트웨이 MAC 이 또 바뀜",
                         change_count=crit["changes_seen"], distinct=len(seen))
            else:
                crit["stable_for"] = int(crit.get("stable_for", 0)) + 1

        # --- 다른 신호가 따라오는가 ---
        new_corr = [f.kind for f in findings
                    if f.kind in crit.get("watch_kinds", []) and not f.attribution]
        if new_corr:
            crit.setdefault("corroborated", []).extend(new_corr)
            inv.note(ts, "다른 신호가 함께 나타남", kinds=new_corr)
            # 경로 설정까지 흔들렸다면 이제 DNS 와 경로도 유의미하게 본다.
            # 처음부터 이렇게 넓히면 평소 소음까지 다 걸린다.
            if not crit.get("widened"):
                out.append(self._retuned(inv, inv.retune(
                    ts,
                    "MAC 변경에 경로·이름 해석 변화가 겹쳤습니다. 감시 범위를 넓힙니다.",
                    widened=True,
                    watch_kinds=sorted(set(crit["watch_kinds"]) |
                                       {"DNS_LOCAL_PROXY_CHANGED", "IPV6_ROUTER_APPEARED",
                                        "WIFI_SECURITY_DOWNGRADE"}),
                )))

        # --- 결론 ---
        corr = list(dict.fromkeys(crit.get("corroborated", [])))
        flaps = int(crit.get("changes_seen", 0))

        if corr:
            inv.close(ts, CONCLUDED,
                      "경로를 쥔 무언가가 바뀜 — 중간자 가능성", SUSPECT)
            out.append(self._concluded(
                inv, SECURITY, HIGH, SUSPECT,
                "첫 홉의 정체가 바뀐 뒤 %s 가 함께 나타났습니다. 접속점 교체만으로는 "
                "설명되지 않습니다." % ", ".join(corr)))
            return out

        if flaps >= self.FLAP_THRESHOLD:
            inv.close(ts, CONCLUDED, "첫 홉의 정체가 요동침", SUSPECT)
            out.append(self._concluded(
                inv, SECURITY, MEDIUM, SUSPECT,
                "게이트웨이 MAC 이 %d번 바뀌었고 서로 다른 값 %d개가 나타났습니다. "
                "정상적인 접속점 교체는 이렇게 되돌아가지 않습니다."
                % (flaps, len(crit.get("seen_macs", [])))))
            return out

        if int(crit.get("stable_for", 0)) >= self.STABLE_CYCLES:
            inv.close(ts, CONCLUDED, "새 첫 홉으로 안정됨", POSSIBLE)
            out.append(self._concluded(
                inv, SECURITY, LOW, POSSIBLE,
                "새 게이트웨이 MAC 이 %d주기 동안 그대로이고 뒤따른 신호가 없습니다. "
                "접속점 교체로 보입니다. 다만 공격을 배제하지는 못합니다."
                % crit["stable_for"]))
        return out

    @staticmethod
    def _concluded(inv: Investigation, axis: str, severity: str,
                   confidence: str, summary: str) -> Finding:
        return Finding(
            axis=axis, kind="INVESTIGATION_CONCLUDED",
            confidence=confidence, severity=severity,
            summary="[%s] %s" % (inv.kind, summary),
            evidence={"investigation": inv.id, "trigger": inv.trigger,
                      "verdict": inv.verdict, "cycles": inv.cycles,
                      "criteria": inv.criteria, "evidence": inv.evidence[-8:]},
        )


class PathConfig(Playbook):
    """경로·이름 해석 설정이 바뀌었다 — 잠깐인가 자리 잡았는가.

    rogue DHCP 나 프록시 주입은 자리 잡아야 의미가 있다. 한 주기만 스쳤다가
    원래대로 돌아오는 것은 갱신이나 경합일 때가 많다.
    """

    name = "path_config"
    triggers = ("DHCP_SERVER_CHANGED", "DHCP_ROUTER_CHANGED", "DHCP_DNS_CHANGED",
                "RESOLVER_CHANGED", "PROXY_ENABLED", "PROXY_SETTINGS_CHANGED",
                "DEFAULT_ROUTE_CHANGED", "IPV6_DEFAULT_ROUTE_APPEARED")
    max_cycles = 40
    fast_interval = 3

    PERSIST_CYCLES = 12

    def initial_criteria(self, finding: Finding, cur: Observation) -> Dict[str, Any]:
        return {
            "watch_kinds": list(self.triggers),
            "snapshot": self._snapshot(cur),
            "persisted_for": 0,
            "reverted": False,
            "further_changes": 0,
        }

    @staticmethod
    def _snapshot(obs: Observation) -> Dict[str, Any]:
        return {
            "dhcp_server": str(unwrap(obs.get("dhcp", "server_identifier"))),
            "resolvers": [str(unwrap(r)) for r in (obs.get("dns", "resolvers") or [])],
            "proxy": obs.get("dns", "proxy") or {},
            "routes4": sorted("%s@%s" % (unwrap(r.get("gateway")), r.get("iface"))
                              for r in (obs.get("route", "default4") or [])),
        }

    def step(self, inv, prev, cur, ctx, findings) -> List[Finding]:
        out: List[Finding] = []
        ts, crit = cur.ts, inv.criteria
        now = self._snapshot(cur)

        if now == crit.get("snapshot"):
            crit["persisted_for"] = int(crit.get("persisted_for", 0)) + 1
        else:
            crit["further_changes"] = int(crit.get("further_changes", 0)) + 1
            crit["persisted_for"] = 0
            crit["snapshot"] = now
            inv.note(ts, "설정이 또 바뀜", count=crit["further_changes"])

        # 계속 흔들리면 한 번의 변화가 아니라 경합이다. 기준을 그쪽으로 옮긴다.
        if crit["further_changes"] == 2 and not crit.get("contested"):
            out.append(self._retuned(inv, inv.retune(
                ts, "설정이 반복해서 바뀝니다. 한 번의 변조가 아니라 경합으로 봅니다.",
                contested=True, persist_target=self.PERSIST_CYCLES * 2)))

        target = int(crit.get("persist_target", self.PERSIST_CYCLES))
        if int(crit["persisted_for"]) >= target:
            contested = bool(crit.get("contested"))
            inv.close(ts, CONCLUDED,
                      "바뀐 설정이 자리 잡음", CONFIRMED if not contested else SUSPECT)
            out.append(L2Identity._concluded(
                inv, SECURITY, MEDIUM if not contested else LOW,
                CONFIRMED if not contested else SUSPECT,
                "바뀐 경로·이름 해석 설정이 %d주기 동안 유지되고 있습니다%s."
                % (crit["persisted_for"],
                   " (그 전에 여러 번 흔들렸습니다)" if contested else "")))
        return out


class VpnDrop(Playbook):
    """VPN 이 끊겼다 — 한 번인가 되풀이인가.

    한 번의 끊김보다 **되풀이되는 끊김**이 더 많은 것을 말해 준다. 원래 이
    도구를 만들게 된 문제도 그것이었다.
    """

    name = "vpn_drop"
    triggers = ("VPN_DISCONNECTED",)
    max_cycles = 120
    fast_interval = 3

    REPEAT_THRESHOLD = 3

    def initial_criteria(self, finding: Finding, cur: Observation) -> Dict[str, Any]:
        ev = finding.evidence or {}
        return {
            "provider": ev.get("provider"),
            "drops": 1,
            "reconnects": 0,
            "first_hop_alive_at_drop": [ev.get("first_hop_alive")],
            "watch_kinds": ["VPN_DISCONNECTED", "VPN_RECONNECTED"],
            "still_down": True,
        }

    def step(self, inv, prev, cur, ctx, findings) -> List[Finding]:
        out: List[Finding] = []
        ts, crit = cur.ts, inv.criteria
        provider = crit.get("provider")

        for f in findings:
            if f.evidence.get("provider") != provider:
                continue
            if f.kind == "VPN_DISCONNECTED":
                crit["drops"] = int(crit.get("drops", 0)) + 1
                crit["still_down"] = True
                crit.setdefault("first_hop_alive_at_drop", []).append(
                    f.evidence.get("first_hop_alive"))
                inv.note(ts, "또 끊김", drops=crit["drops"])
            elif f.kind == "VPN_RECONNECTED":
                crit["reconnects"] = int(crit.get("reconnects", 0)) + 1
                crit["still_down"] = False
                inv.note(ts, "다시 연결됨", reconnects=crit["reconnects"])

        # 되풀이가 보이기 시작하면, 이제는 링크 품질까지 함께 본다.
        # 끊김이 한 번일 때는 링크 잡음이 섞여 들어와 쓸모가 없다.
        if int(crit.get("drops", 0)) == 2 and not crit.get("watch_link"):
            out.append(self._retuned(inv, inv.retune(
                ts, "끊김이 되풀이되고 있습니다. 무선 구간 품질도 함께 봅니다.",
                watch_link=True,
                watch_kinds=sorted(set(crit["watch_kinds"]) |
                                   {"FIRST_HOP_UNREACHABLE", "LATENCY_SPIKE",
                                    "DHCP_LEASE_RENEWED"}))))

        if crit.get("watch_link"):
            hits = [f.kind for f in findings if f.kind in crit["watch_kinds"]
                    and f.kind.startswith(("FIRST_HOP", "LATENCY", "DHCP_LEASE"))]
            if hits:
                crit["link_events"] = int(crit.get("link_events", 0)) + len(hits)
                inv.note(ts, "같은 구간에 링크 사건", kinds=hits)

        drops = int(crit.get("drops", 0))
        if drops >= self.REPEAT_THRESHOLD:
            link_events = int(crit.get("link_events", 0))
            alive = [a for a in crit.get("first_hop_alive_at_drop", []) if a is not None]
            tunnel_side = alive and all(alive)
            if tunnel_side and not link_events:
                verdict = "터널 쪽에서 되풀이되는 끊김 — 무선 구간은 매번 정상"
            elif link_events:
                verdict = "무선 구간 불안정과 함께 되풀이되는 끊김"
            else:
                verdict = "되풀이되는 끊김 — 구간을 가르지 못함"
            inv.close(ts, CONCLUDED, verdict, SUSPECT)
            out.append(L2Identity._concluded(
                inv, QUALITY, MEDIUM, SUSPECT,
                "%s 가 %d번 끊겼습니다. %s." % (provider, drops, verdict)))
        return out


ALL: List[Playbook] = [L2Identity(), PathConfig(), VpnDrop()]


def for_finding(finding: Finding) -> Optional[Playbook]:
    for pb in ALL:
        if finding.kind in pb.triggers:
            return pb
    return None


def by_name(name: str) -> Optional[Playbook]:
    for pb in ALL:
        if pb.name == name:
            return pb
    return None
