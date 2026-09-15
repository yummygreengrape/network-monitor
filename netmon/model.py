"""관측·판정의 자료 구조.

식별자는 값을 그냥 두지 않고 종류를 붙여서 담는다. 그래야 내보낼 때
어떤 필드를 가려야 하는지 코드가 알 수 있다 (netmon.redact).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# 가려야 하는 식별자 종류
ID_KINDS = ("ipv4", "ipv6", "mac", "ssid", "bssid", "hostname", "path", "user", "serviceid")

# 축: 연결 품질과 보안을 섞지 않는다
QUALITY = "quality"
SECURITY = "security"
INFO = "info"
AXES = (QUALITY, SECURITY, INFO)

# 확신도. 이 셋을 섞어 쓰지 않는 것이 이 도구의 핵심 규칙이다.
POSSIBLE = "possible"    # 구조적으로 가능하다. 이 네트워크에서 일어날 수 있다. 증거는 없다.
SUSPECT = "suspect"      # 관측이 기준선과 어긋난다. 양성 오류의 여지가 있다.
CONFIRMED = "confirmed"  # 관측만으로 사실이라고 말할 수 있다. 원인은 별개다.
CONFIDENCES = (POSSIBLE, SUSPECT, CONFIRMED)

INFO_SEV, LOW, MEDIUM, HIGH = "info", "low", "medium", "high"
SEVERITIES = (INFO_SEV, LOW, MEDIUM, HIGH)


def ident(kind: str, value: Any) -> Dict[str, Any]:
    """식별자 값을 종류와 함께 감싼다."""
    if kind not in ID_KINDS:
        raise ValueError("알 수 없는 식별자 종류: %s" % kind)
    return {"id": kind, "v": value}


def unwrap(value: Any) -> Any:
    """ident() 로 감싼 값이면 원래 값을, 아니면 그대로 돌려준다."""
    if isinstance(value, dict) and "id" in value and "v" in value:
        return value["v"]
    return value


@dataclass
class Finding:
    """판정 하나.

    `attribution` 은 "이 변화가 사용자 자신의 행동으로 설명된다"는 표시다.
    분류를 덮어쓰지 않고 따로 붙는다 — 억제된 판정도 기록은 남아서
    나중에 다시 볼 수 있다.
    """

    axis: str
    kind: str
    confidence: str
    severity: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    attribution: Optional[str] = None
    network: Optional[str] = None

    def __post_init__(self) -> None:
        if self.axis not in AXES:
            raise ValueError("알 수 없는 축: %s" % self.axis)
        if self.confidence not in CONFIDENCES:
            raise ValueError("알 수 없는 확신도: %s" % self.confidence)
        if self.severity not in SEVERITIES:
            raise ValueError("알 수 없는 심각도: %s" % self.severity)

    @property
    def suppressed(self) -> bool:
        return self.attribution is not None

    def as_dict(self, ts: Optional[str] = None) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "axis": self.axis,
            "kind": self.kind,
            "confidence": self.confidence,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence,
            "attribution": self.attribution,
        }
        if self.network:
            d["network"] = self.network
        if ts:
            d = dict(ts=ts, **d)
        return d


@dataclass
class Observation:
    """한 주기에 수집한 것 전부. 수집기 이름 → 그 수집기의 결과."""

    ts: str
    data: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)

    def get(self, collector: str, key: str = None, default: Any = None) -> Any:
        block = self.data.get(collector)
        if block is None:
            return default
        if key is None:
            return block
        return block.get(key, default)

    def as_dict(self) -> Dict[str, Any]:
        d = {"ts": self.ts, "data": self.data}
        if self.errors:
            d["errors"] = self.errors
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Observation":
        return cls(ts=d["ts"], data=d.get("data", {}), errors=d.get("errors", {}))
