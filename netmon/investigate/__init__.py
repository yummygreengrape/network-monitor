"""유의미한 신호가 잡히면 조사를 이어 간다.

한 주기의 판정으로 끝나지 않는 신호가 있다. 게이트웨이 MAC 이 바뀌었다는
관측은 확정이지만 그것이 공격인지 접속점 교체인지는 **그 다음에 일어나는
일**로만 갈린다. 조사는 그 다음을 계속 보다가 결론을 내고 닫는다.

  1. triggers.is_meaningful 이 조사를 열 신호를 고른다
  2. playbook 이 조사마다 자기 기준(criteria)을 세운다
  3. 주기마다 step() 이 돌면서, 알게 된 것에 따라 **기준을 고친다**
  4. 결론이 나거나 예산을 다 쓰면 닫는다

조사는 state.json 에 남아 에이전트를 재시작해도 이어진다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..model import (CONFIRMED, INFO, INFO_SEV, LOW, POSSIBLE, Finding,
                     Observation)
from . import playbooks, triggers
from .model import ABANDONED, CONCLUDED, OPEN, Investigation, make_id

STATE_KEY = "investigations"
COOLDOWN_KEY = "investigation_cooldown"

DEFAULTS: Dict[str, Any] = {
    "enabled": True,
    # 동시에 열어 둘 조사 수. 넘치면 새 신호는 기존 조사에 증거로만 붙는다.
    "max_open": 3,
    # 닫힌 조사를 몇 개까지 기억할 것인가 (보고용)
    "keep_closed": 20,
    # 같은 종류의 조사를 끝낸 뒤 이만큼의 주기 동안은 다시 열지 않는다.
    # 없으면 되풀이되는 문제에서 조사가 끝없이 새로 열린다 — 결론을 낸 바로
    # 그 주기에 같은 신호로 또 열리기까지 한다.
    "cooldown_cycles": 30,
    "open_on": {},
}


def settings(cfg_block: Any) -> Dict[str, Any]:
    out = dict(DEFAULTS)
    if isinstance(cfg_block, dict):
        out.update({k: v for k, v in cfg_block.items() if k in DEFAULTS})
    return out


class Investigator:
    """열린 조사들을 굴린다. 명령을 실행하지 않는다 — 순수 계산이다."""

    def __init__(self, conf: Dict[str, Any]) -> None:
        self.conf = settings(conf)
        self.rules = triggers.merge_rules(self.conf.get("open_on"))

    # --- 상태 ---
    @staticmethod
    def load(state: Dict[str, Any]) -> List[Investigation]:
        return [Investigation.from_dict(d) for d in (state.get(STATE_KEY) or [])]

    def save(self, state: Dict[str, Any], invs: List[Investigation]) -> None:
        keep = self.conf["keep_closed"]
        open_ones = [i for i in invs if i.open]
        closed = [i for i in invs if not i.open][-keep:]
        state[STATE_KEY] = [i.as_dict() for i in open_ones + closed]

    # --- 한 주기 ---
    def run(self, prev: Optional[Observation], cur: Observation, ctx,
            findings: List[Finding], state: Dict[str, Any]
            ) -> Tuple[List[Finding], Dict[str, Any]]:
        if not self.conf.get("enabled", True):
            return [], {}

        invs = self.load(state)
        out: List[Finding] = []

        cooldown: Dict[str, int] = dict(state.get(COOLDOWN_KEY) or {})
        for key in list(cooldown):
            cooldown[key] = int(cooldown[key]) - 1
            if cooldown[key] <= 0:
                del cooldown[key]

        # 네트워크가 바뀌면 조사 대상 자체가 사라진다. 조용히 버리지 않고
        # "중단했다"고 남긴다 — 무엇을 못 보고 넘어갔는지가 기록에 있어야 한다.
        for inv in invs:
            if inv.open and ctx.network and inv.network != ctx.network:
                inv.close(cur.ts, ABANDONED, "네트워크가 바뀌어 중단", POSSIBLE)
                out.append(Finding(
                    axis=INFO, kind="INVESTIGATION_ABANDONED",
                    confidence=CONFIRMED, severity=INFO_SEV,
                    summary="조사 %s 를 중단했다. 네트워크가 바뀌어 대상이 사라졌다."
                            % inv.id,
                    evidence={"investigation": inv.id, "kind": inv.kind,
                              "cycles": inv.cycles, "criteria": inv.criteria},
                ))

        # 열려 있는 조사를 굴린다
        for inv in [i for i in invs if i.open]:
            pb = playbooks.by_name(inv.kind)
            if pb is None:
                inv.close(cur.ts, ABANDONED, "조사 지침을 찾을 수 없음", POSSIBLE)
                continue
            inv.cycles += 1
            try:
                out.extend(pb.step(inv, prev, cur, ctx, findings) or [])
            except Exception as exc:
                inv.close(cur.ts, ABANDONED, "조사 중 오류: %s" % str(exc)[:80], POSSIBLE)
                out.append(Finding(
                    axis=INFO, kind="INVESTIGATION_ERROR",
                    confidence=CONFIRMED, severity=LOW,
                    summary="조사 %s 가 예외로 멈췄다: %s" % (inv.id, str(exc)[:100]),
                    evidence={"investigation": inv.id, "error": repr(exc)[:200]},
                ))
            if not inv.open and inv.closed_at == cur.ts:
                cooldown[inv.kind] = int(self.conf["cooldown_cycles"])
            if inv.open and inv.cycles >= pb.max_cycles:
                inv.close(cur.ts, CONCLUDED,
                          "예산 안에 결론이 나지 않음 (%d주기)" % inv.cycles, POSSIBLE)
                cooldown[inv.kind] = int(self.conf["cooldown_cycles"])
                out.append(Finding(
                    axis=INFO, kind="INVESTIGATION_CONCLUDED",
                    confidence=POSSIBLE, severity=INFO_SEV,
                    summary="[%s] %d주기를 봤지만 가르지 못했다. 관측을 남기고 닫는다."
                            % (inv.kind, inv.cycles),
                    evidence={"investigation": inv.id, "trigger": inv.trigger,
                              "criteria": inv.criteria,
                              "evidence": inv.evidence[-8:]},
                ))

        # 새 조사를 연다
        open_count = len([i for i in invs if i.open])
        for f in triggers.meaningful(findings, self.rules):
            pb = playbooks.for_finding(f)
            if pb is None:
                continue
            existing = next((i for i in invs
                             if i.open and i.kind == pb.name), None)
            if existing is not None:
                # 같은 종류의 조사가 이미 열려 있다. 새로 열지 않고 증거로 붙인다.
                existing.note(cur.ts, "같은 종류의 신호가 또 나타남", kind=f.kind)
                continue
            if cooldown.get(pb.name, 0) > 0:
                # 조용히 넘기지 않는다. 무엇을 안 열었는지가 기록에 있어야 한다.
                if not state.get("_cooldown_noted", {}).get(pb.name):
                    state.setdefault("_cooldown_noted", {})[pb.name] = True
                    out.append(Finding(
                        axis=INFO, kind="INVESTIGATION_COOLDOWN",
                        confidence=CONFIRMED, severity=INFO_SEV,
                        summary="%s 조사를 방금 끝냈다. %d주기 동안 같은 종류를 "
                                "다시 열지 않는다 (%s 신호는 기록에 남는다)."
                                % (pb.name, cooldown[pb.name], f.kind),
                        evidence={"playbook": pb.name, "trigger": f.kind,
                                  "cooldown_left": cooldown[pb.name]},
                    ))
                continue
            if open_count >= int(self.conf["max_open"]):
                continue
            inv = Investigation(
                id=make_id(pb.name, cur.ts, ctx.network or "-"),
                kind=pb.name, trigger=f.kind, opened_at=cur.ts,
                network=ctx.network or "-",
                criteria=pb.initial_criteria(f, cur),
            )
            inv.note(cur.ts, "조사 시작", trigger=f.kind, summary=f.summary)
            invs.append(inv)
            open_count += 1
            out.append(Finding(
                axis=INFO, kind="INVESTIGATION_OPENED",
                confidence=CONFIRMED, severity=INFO_SEV,
                summary="%s 때문에 조사 %s 를 연다. 결론이 날 때까지 계속 본다."
                        % (f.kind, inv.id),
                evidence={"investigation": inv.id, "kind": pb.name,
                          "trigger": f.kind, "criteria": inv.criteria,
                          "max_cycles": pb.max_cycles},
            ))

        for name in list((state.get("_cooldown_noted") or {})):
            if cooldown.get(name, 0) <= 0:
                state["_cooldown_noted"].pop(name, None)
        state[COOLDOWN_KEY] = cooldown
        self.save(state, invs)
        return out, self.needs(invs)

    # --- 엔진에 보내는 요청 ---
    @staticmethod
    def needs(invs: List[Investigation]) -> Dict[str, Any]:
        """조사 중에 측정을 어떻게 바꿀지. 가장 급한 값을 고른다."""
        need: Dict[str, Any] = {}
        for inv in invs:
            if not inv.open:
                continue
            pb = playbooks.by_name(inv.kind)
            if pb is None:
                continue
            for key, value in pb.needs(inv).items():
                if key == "interval":
                    need["interval"] = min(need.get("interval", value), value)
                else:
                    need[key] = value
        if need:
            need["open"] = len([i for i in invs if i.open])
        return need


def open_investigations(state: Dict[str, Any]) -> List[Investigation]:
    return [i for i in Investigator.load(state) if i.open]


def describe_rules(conf: Any) -> str:
    return triggers.describe(triggers.merge_rules(settings(conf).get("open_on")))
