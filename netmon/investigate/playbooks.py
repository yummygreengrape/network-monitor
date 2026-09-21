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
from ..liveness import METHOD_MESSAGES, evaluate, method_label
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
            # **무엇으로 도달성을 판정했는지도 함께 남긴다.** 끊길 때마다
            # 첫 홉이 살아 있었다는 말은 판정 기준을 빼면 뜻이 달라진다 —
            # ARP 로 판정하는 망에서는 같은 주기의 ICMP 가 전부 빠져 있어도
            # True 다(netmon/liveness.py).
            "first_hop_method_at_drop": [ev.get("first_hop_method")],
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
                crit.setdefault("first_hop_method_at_drop", []).append(
                    f.evidence.get("first_hop_method"))
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
            inv.close(ts, CONCLUDED, msg.INV_VPN_VERDICT_SETTLED % drops, SUSPECT)
            out.append(L2Identity._concluded(
                inv, QUALITY, INFO_SEV, SUSPECT,
                msg.INV_VPN_SETTLED % (provider, drops, crit["settled_for"],
                                       self._leg(crit))))
            return out

        if drops >= self.REPEAT_THRESHOLD:
            link_events = int(crit.get("link_events", 0))
            alive = [a for a in crit.get("first_hop_alive_at_drop", []) if a is not None]
            if alive and all(alive) and not link_events:
                # 첫 홉이 매번 응답했다는 **사실**까지만 적는다. 구간을
                # 지목하지 않는 이유는 _leg() 에 적었다.
                verdict = msg.INV_VPN_VERDICT_FIRST_HOP_OK
            elif link_events:
                verdict = msg.INV_VPN_VERDICT_LINK
            else:
                verdict = msg.INV_VPN_VERDICT_UNKNOWN
            inv.close(ts, CONCLUDED, verdict, SUSPECT)
            out.append(L2Identity._concluded(
                inv, QUALITY, MEDIUM, SUSPECT,
                msg.INV_VPN_REPEATED % (provider, drops, self._leg(crit))))
        return out

    @staticmethod
    def _leg(crit) -> str:
        """끊길 때 첫 홉이 어땠나.

        **횟수와 무관한 서술이다.** "되풀이" 같은 틀을 여기 섞으면 단발 결론에
        재사용할 때 "한 번 끊겼다 … 되풀이되는 끊김" 같은 자기모순이 된다.
        실제로 그렇게 났다.

        **구간도 지목하지 않는다.** 첫 홉이 응답했다는 것은 이 기기와 공유기
        사이가 살아 있었다는 뜻일 뿐, 터널 상대편 구간에 대해서는 아무것도
        재지 않았다. 되풀이된다고 해서 같은 증거가 다른 것을 말해 주지는
        않는다 — 한 묶음 ICMP 를 세 번 본 것이다. 같은 증거로 끊김 요약문
        (netmon/detect/vpn._likely)은 유보하므로, 조사 결론만 단정하면 한
        도구가 같은 관측을 두 가지 확신으로 말하게 된다.
        """
        alive = [a for a in crit.get("first_hop_alive_at_drop", []) if a is not None]
        link_events = int(crit.get("link_events", 0))
        if alive and all(alive) and not link_events:
            basis = VpnDrop._method_basis(crit)
            if basis:
                return msg.INV_VPN_LEG_FIRST_HOP_OK % basis
            return msg.INV_VPN_LEG_FIRST_HOP_OK_PLAIN
        if link_events or (alive and not any(alive)):
            return msg.INV_VPN_LEG_LINK
        return msg.INV_VPN_LEG_UNKNOWN

    @staticmethod
    def _method_basis(crit) -> str:
        """무엇으로 첫 홉 도달성을 판정했는가.

        끊김마다 다를 수 있어(보정이 ICMP 와 ARP 사이를 오간다) 본 것을 모두
        적는다. 이름표가 없는 값(보정 중 `unknown`, 옛 기록의 None)은 적지
        않는다 — 하나도 없으면 기준을 밝히지 않는 문구를 쓴다.

        **판정한 끊김의 방법만 모은다.** 두 리스트는 같은 끊김을 같은 자리에
        적으므로 짝지어 훑는다. `first_hop_alive` 가 None 인 끊김은 아무것도
        판정하지 못한 주기인데(ICMP 로 보정된 망에서 게이트웨이를 못 잰
        주기가 그렇다), 그 주기의 방법을 함께 적으면 판정한 적 없는 것을
        판정 기준으로 내세우게 된다. 이 함수를 부르는 쪽(_leg)이 세는 것도
        None 을 뺀 끊김들이다.

        길이가 어긋나면 짝을 믿을 수 없으므로(한쪽만 기록된 옛 조사, 복원된
        상태) 기준을 적지 않는다.
        """
        alive = crit.get("first_hop_alive_at_drop", []) or []
        methods = crit.get("first_hop_method_at_drop", []) or []
        if len(alive) != len(methods):
            return ""
        labels: List[str] = []
        for judged, method in zip(alive, methods):
            if judged is None or method not in METHOD_MESSAGES:
                continue
            label = method_label(method)
            if label not in labels:
                labels.append(label)
        return "·".join(labels)


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
