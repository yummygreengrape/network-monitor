"""무엇을 "유의미한 신호"로 볼 것인가 — 조사를 여는 기준.

이 기준은 세 층에서 정해진다.

  1. 기본값          보안 축의 high·medium, 그리고 몇몇 품질 신호
  2. 사용자 설정     config 의 investigate.open_on 으로 덮어쓴다
  3. 조사 자신의 기준 조사가 열린 뒤에는 그 조사의 criteria 가 쓰인다
                     (netmon/investigate/model.py 의 retune)

억제된 판정(attribution 이 붙은 것)은 기본적으로 조사를 열지 않는다. 사용자
행동으로 설명되는 변화까지 조사하면 장소를 옮길 때마다 조사가 쏟아진다.
다만 설정으로 켤 수 있게 두었다 — 억제 판단 자체가 틀렸을 때를 위해서다.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..model import Finding

DEFAULT_RULES: Dict[str, Any] = {
    # 축 + 심각도 조합
    "axes": ["security"],
    "severities": ["high", "medium"],
    # 축·심각도와 무관하게 언제나 조사를 여는 판정
    "kinds": [
        "EVIL_TWIN_CANDIDATE",
        "DUPLICATE_IP",
        "ARP_REPLY_SPIKE",
        "VPN_DISCONNECTED",
        "FIRST_HOP_UNREACHABLE",
    ],
    # 절대 조사를 열지 않는 판정 (kinds 보다 우선)
    "never": [
        "MEASUREMENT_GAP",
        "GATEWAY_ICMP_SILENT",
        "GATEWAY_ICMP_OK",
        "MULTIPLE_DEFAULT_ROUTES",
        "VPN_STATE_UNKNOWN",
        "INVESTIGATION_OPENED",
        "INVESTIGATION_UPDATED",
        "INVESTIGATION_CONCLUDED",
        "INVESTIGATION_RETUNED",
    ],
    # 억제된 판정도 조사할 것인가
    "include_attributed": False,
}


def merge_rules(user: Any) -> Dict[str, Any]:
    rules = {k: (list(v) if isinstance(v, list) else v)
             for k, v in DEFAULT_RULES.items()}
    if isinstance(user, dict):
        for key, value in user.items():
            if key in rules:
                rules[key] = value
    return rules


def is_meaningful(finding: Finding, rules: Dict[str, Any]) -> bool:
    """이 판정이 조사를 열 만한가."""
    if finding.kind in rules.get("never", []):
        return False
    if finding.attribution and not rules.get("include_attributed"):
        return False
    if finding.kind in rules.get("kinds", []):
        return True
    return (finding.axis in rules.get("axes", [])
            and finding.severity in rules.get("severities", []))


def meaningful(findings: List[Finding], rules: Dict[str, Any]) -> List[Finding]:
    return [f for f in findings if is_meaningful(f, rules)]


def describe(rules: Dict[str, Any]) -> str:
    return ("축 %s 의 심각도 %s, 그리고 %s. 제외: %s. 억제된 판정 포함: %s"
            % (", ".join(rules.get("axes", [])),
               ", ".join(rules.get("severities", [])),
               ", ".join(rules.get("kinds", [])) or "없음",
               ", ".join(rules.get("never", [])) or "없음",
               "예" if rules.get("include_attributed") else "아니오"))
