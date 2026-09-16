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

from .. import messages as msg
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
            summary=msg.INV_RETUNED % (inv.id, change["reason"]),
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
            # 이 조사가 MAC 변경으로 열렸는가. ARP 급증이나 IP 충돌로 열렸다면
            # 변경을 본 적이 없으므로 "교체됐다"고 말하면 안 된다.
            "mac_changed": finding.kind == "GW_MAC_CHANGED",
            "changes_seen": 1 if finding.kind == "GW_MAC_CHANGED" else 0,
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
                crit["mac_changed"] = True
                crit["stable_for"] = 0
                crit["baseline_mac"] = mac
                seen = crit.setdefault("seen_macs", [])
                if mac not in seen:
                    seen.append(mac)
                inv.note(ts, msg.INV_NOTE_MAC_AGAIN,
                         change_count=crit["changes_seen"], distinct=len(seen))
            else:
                crit["stable_for"] = int(crit.get("stable_for", 0)) + 1

        # --- 다른 신호가 따라오는가 ---
        new_corr = [f.kind for f in findings
                    if f.kind in crit.get("watch_kinds", []) and not f.attribution]
        if new_corr:
            crit.setdefault("corroborated", []).extend(new_corr)
            inv.note(ts, msg.INV_NOTE_CORROBORATED, kinds=new_corr)
            # 경로 설정까지 흔들렸다면 이제 DNS 와 경로도 유의미하게 본다.
            # 처음부터 이렇게 넓히면 평소 소음까지 다 걸린다.
            if not crit.get("widened"):
                out.append(self._retuned(inv, inv.retune(
                    ts,
                    msg.INV_L2_WIDEN,
                    widened=True,
                    watch_kinds=sorted(set(crit["watch_kinds"]) |
                                       {"DNS_LOCAL_PROXY_CHANGED", "IPV6_ROUTER_APPEARED",
                                        "WIFI_SECURITY_DOWNGRADE"}),
                )))

        # --- 결론 ---
        corr = list(dict.fromkeys(crit.get("corroborated", [])))
        flaps = int(crit.get("changes_seen", 0))

        if corr:
            inv.close(ts, CONCLUDED, msg.INV_L2_CORROBORATED_VERDICT, SUSPECT)
            out.append(self._concluded(
                inv, SECURITY, HIGH, SUSPECT,
                msg.INV_L2_CORROBORATED % ", ".join(corr)))
            return out

        if flaps >= self.FLAP_THRESHOLD:
            inv.close(ts, CONCLUDED, msg.INV_L2_FLAPPING_VERDICT, SUSPECT)
            out.append(self._concluded(
                inv, SECURITY, MEDIUM, SUSPECT,
                msg.INV_L2_FLAPPING % (flaps, len(crit.get("seen_macs", [])))))
            return out

        if int(crit.get("stable_for", 0)) >= self.STABLE_CYCLES:
            if crit.get("mac_changed"):
                inv.close(ts, CONCLUDED, msg.INV_L2_STABLE_VERDICT, POSSIBLE)
                summary = msg.INV_L2_STABLE % crit["stable_for"]
            else:
                # 애초에 MAC 이 바뀐 적이 없다. 접속점 교체를 주장할 근거가 없다.
                inv.close(ts, CONCLUDED, msg.INV_L2_NO_CHANGE_VERDICT, POSSIBLE)
                summary = msg.INV_L2_NO_CHANGE % crit["stable_for"]
            out.append(self._concluded(inv, SECURITY, LOW, POSSIBLE, summary))
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
    max_cycles = 120
    fast_interval = 3

    # **시간으로 센다.** 조사 중에는 측정 간격을 줄이므로 주기 수는 실제
    # 경과 시간과 무관해진다. 12주기를 3초 간격으로 세면 36초인데, 실측에서
    # WARP 가 49초 끊긴 동안 "설정이 자리 잡았다"고 결론 내고 12초 뒤에
    # 원래대로 돌아갔다.
    PERSIST_SECONDS = 300.0

    def initial_criteria(self, finding: Finding, cur: Observation) -> Dict[str, Any]:
        return {
            "watch_kinds": list(self.triggers),
            "snapshot": self._snapshot(cur),
            "persisted_for": 0,
            "persisted_seconds": 0.0,
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

        step_seconds = float(ctx.elapsed) if ctx.elapsed and ctx.elapsed > 0 else float(ctx.interval)
        if now == crit.get("snapshot"):
            crit["persisted_for"] = int(crit.get("persisted_for", 0)) + 1
            crit["persisted_seconds"] = float(crit.get("persisted_seconds", 0.0)) + step_seconds
        else:
            crit["further_changes"] = int(crit.get("further_changes", 0)) + 1
            crit["persisted_for"] = 0
            crit["persisted_seconds"] = 0.0
            crit["snapshot"] = now
            inv.note(ts, msg.INV_NOTE_CONFIG_AGAIN, count=crit["further_changes"])

        # 계속 흔들리면 한 번의 변화가 아니라 경합이다. 기준을 그쪽으로 옮긴다.
        if crit["further_changes"] == 2 and not crit.get("contested"):
            out.append(self._retuned(inv, inv.retune(
                ts, msg.INV_PATH_CONTESTED,
                contested=True, persist_target=self.PERSIST_SECONDS * 2)))

        target = float(crit.get("persist_target", self.PERSIST_SECONDS))
        if float(crit["persisted_seconds"]) >= target:
            contested = bool(crit.get("contested"))
            inv.close(ts, CONCLUDED, msg.INV_PATH_VERDICT,
                      CONFIRMED if not contested else SUSPECT)
            out.append(L2Identity._concluded(
                inv, SECURITY, MEDIUM if not contested else LOW,
                CONFIRMED if not contested else SUSPECT,
                msg.INV_PATH_PERSISTED
                % (crit["persisted_for"],
                   msg.INV_PATH_CONTESTED_NOTE if contested else "")))
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
    # 되풀이가 없더라도 이만큼 안정적이면 "한 번 끊겼다 복구됨"으로 닫는다.
    # 그러지 않으면 예산(120주기)을 다 쓰고 "판별 실패"로 끝난다 — 실제로
    # 49초짜리 끊김 하나에 대해 그렇게 끝났다.
    SETTLED_CYCLES = 40

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
                inv.note(ts, msg.INV_NOTE_DROP_AGAIN, drops=crit["drops"])
            elif f.kind == "VPN_RECONNECTED":
                crit["reconnects"] = int(crit.get("reconnects", 0)) + 1
                crit["still_down"] = False
                inv.note(ts, msg.INV_NOTE_RECONNECT, reconnects=crit["reconnects"])

        # 되풀이가 보이기 시작하면, 이제는 링크 품질까지 함께 본다.
        # 끊김이 한 번일 때는 링크 잡음이 섞여 들어와 쓸모가 없다.
        if int(crit.get("drops", 0)) == 2 and not crit.get("watch_link"):
            out.append(self._retuned(inv, inv.retune(
                ts, msg.INV_VPN_WIDEN,
                watch_link=True,
                watch_kinds=sorted(set(crit["watch_kinds"]) |
                                   {"FIRST_HOP_UNREACHABLE", "LATENCY_SPIKE",
                                    "DHCP_LEASE_RENEWED"}))))

        if crit.get("watch_link"):
            hits = [f.kind for f in findings if f.kind in crit["watch_kinds"]
                    and f.kind.startswith(("FIRST_HOP", "LATENCY", "DHCP_LEASE"))]
            if hits:
                crit["link_events"] = int(crit.get("link_events", 0)) + len(hits)
                inv.note(ts, msg.INV_NOTE_LINK_EVENT, kinds=hits)

        # 복구된 뒤 얼마나 조용한가
        if crit.get("still_down"):
            crit["settled_for"] = 0
        else:
            crit["settled_for"] = int(crit.get("settled_for", 0)) + 1

        drops = int(crit.get("drops", 0))
        if drops < self.REPEAT_THRESHOLD and int(crit.get("settled_for", 0)) >= self.SETTLED_CYCLES:
            alive = [a for a in crit.get("first_hop_alive_at_drop", []) if a is not None]
            leg = (msg.INV_VPN_VERDICT_TUNNEL if alive and all(alive)
                   else msg.INV_VPN_VERDICT_LINK if alive and not any(alive)
                   else msg.INV_VPN_VERDICT_UNKNOWN)
            inv.close(ts, CONCLUDED, msg.INV_VPN_VERDICT_SINGLE, SUSPECT)
            out.append(L2Identity._concluded(
                inv, QUALITY, INFO_SEV, SUSPECT,
                msg.INV_VPN_SINGLE_RESOLVED % (provider, crit["settled_for"], leg)))
            return out

        if drops >= self.REPEAT_THRESHOLD:
            link_events = int(crit.get("link_events", 0))
            alive = [a for a in crit.get("first_hop_alive_at_drop", []) if a is not None]
            tunnel_side = alive and all(alive)
            if tunnel_side and not link_events:
                verdict = msg.INV_VPN_VERDICT_TUNNEL
            elif link_events:
                verdict = msg.INV_VPN_VERDICT_LINK
            else:
                verdict = msg.INV_VPN_VERDICT_UNKNOWN
            inv.close(ts, CONCLUDED, verdict, SUSPECT)
            out.append(L2Identity._concluded(
                inv, QUALITY, MEDIUM, SUSPECT,
                msg.INV_VPN_REPEATED % (provider, drops, verdict)))
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
