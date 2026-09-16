"""조사의 자료 구조.

한 번의 판정으로 끝나지 않는 신호가 있다. 게이트웨이 MAC 이 바뀌었다는 사실은
확정이지만, 그것이 공격인지 접속점 교체인지는 **그 다음에 일어나는 일**로만
갈린다. 조사는 그 "다음"을 계속 보는 장치다.

조사마다 **자기 기준을 가진다.** 무엇을 유의미한 신호로 볼지가 조사 종류마다
다르고, 같은 조사 안에서도 알게 된 것에 따라 달라진다. 기준이 바뀌면 바뀐
사실과 이유를 기록에 남긴다 — 나중에 판단을 되짚을 때 기준이 언제 어떻게
움직였는지가 가장 중요한 단서이기 때문이다.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

OPEN = "open"
CONCLUDED = "concluded"
ABANDONED = "abandoned"   # 네트워크가 바뀌는 등 대상 자체가 사라짐


def make_id(kind: str, ts: str, network: str) -> str:
    seed = "%s|%s|%s" % (kind, ts, network)
    return "%s-%s" % (kind, hashlib.sha1(seed.encode()).hexdigest()[:6])


@dataclass
class Investigation:
    id: str
    kind: str                      # 어느 조사 지침(playbook)인가
    trigger: str                   # 무엇이 조사를 열었나
    opened_at: str
    network: str
    status: str = OPEN
    cycles: int = 0
    # 이 조사가 "유의미하다"고 보는 기준. 조사 중에 바뀔 수 있다.
    criteria: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    verdict: Optional[str] = None
    confidence: Optional[str] = None
    closed_at: Optional[str] = None

    # --- 기록 ---
    def note(self, ts: str, what: str, **detail: Any) -> None:
        """조사 중에 알게 된 것을 남긴다."""
        entry = {"ts": ts, "what": what}
        if detail:
            entry.update(detail)
        self.evidence.append(entry)

    def retune(self, ts: str, reason: str, **changes: Any) -> Dict[str, Any]:
        """기준을 바꾼다. 바뀐 내용과 이유를 반드시 남긴다.

        조용히 기준을 바꾸면 나중에 "왜 이건 잡고 저건 놓쳤나"를 설명할 수 없다.
        """
        before = {k: self.criteria.get(k) for k in changes}
        self.criteria.update(changes)
        self.note(ts, "기준 변경", reason=reason, before=before, after=dict(changes))
        return {"reason": reason, "before": before, "after": dict(changes)}

    def close(self, ts: str, status: str, verdict: str, confidence: str) -> None:
        self.status = status
        self.verdict = verdict
        self.confidence = confidence
        self.closed_at = ts

    @property
    def open(self) -> bool:
        return self.status == OPEN

    # --- 직렬화 (state.json 에 남아 에이전트 재시작을 견딘다) ---
    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "trigger": self.trigger,
            "opened_at": self.opened_at, "network": self.network,
            "status": self.status, "cycles": self.cycles,
            "criteria": self.criteria, "evidence": self.evidence,
            "verdict": self.verdict, "confidence": self.confidence,
            "closed_at": self.closed_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Investigation":
        return cls(
            id=d["id"], kind=d["kind"], trigger=d.get("trigger", "?"),
            opened_at=d.get("opened_at", ""), network=d.get("network", ""),
            status=d.get("status", OPEN), cycles=int(d.get("cycles", 0)),
            criteria=dict(d.get("criteria") or {}),
            evidence=list(d.get("evidence") or []),
            verdict=d.get("verdict"), confidence=d.get("confidence"),
            closed_at=d.get("closed_at"),
        )
