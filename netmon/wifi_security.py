"""Wi-Fi 암호화 방식이 **노출에 어떤 뜻인지** 분류한다.

강도 순서(detect/wifi.py 의 rank)와는 다른 질문이다. 여기서 묻는 것은
"이 방식에서 남이 내 트래픽으로 무엇을 할 수 있나" 이고, 그 답이 방식마다
질적으로 다르다.

  개방              같은 전파 범위의 누구나 그냥 읽는다
  공유 비밀번호     비밀번호를 아는 사람이 handshake 를 잡으면 **수동으로 복호**한다
  (WEP/WPA/WPA2)    별도 공격 없이 조용히 읽힌다
  WPA3-SAE          비밀번호를 알아도 수동 복호는 안 된다. 세션마다 키가 다르다.
                    다만 접속은 할 수 있으므로 같은 L2 에서 **능동적으로**
                    가로채는 것(ARP 스푸핑 등)은 여전히 가능하다
  개인별 자격증명   접속 자체가 사람마다 갈린다
  (Enterprise/EAP)

수동으로 읽히는 것과 능동적 공격이 필요한 것을 같은 말로 적으면 WPA3 에서
사실이 아닌 서술이 된다.
"""
from __future__ import annotations

import re
from typing import Optional

OPEN = "open"
SHARED_PASSIVE = "shared_passive"
SHARED_SAE = "shared_sae"
PER_USER = "per_user"
UNKNOWN = "unknown"


def classify(security: Optional[str]) -> str:
    key = re.sub(r"[^a-z0-9]", "", (security or "").lower())
    if not key or key == "unknown":
        return UNKNOWN
    if key in ("none", "open"):
        return OPEN
    if "enterprise" in key or "eap" in key or "8021x" in key:
        return PER_USER

    has_sae = "sae" in key or "wpa3" in key
    rest = key.replace("wpa3", "").replace("sae", "")
    # 혼합 모드(WPA2/WPA3)는 약한 쪽으로 친다. WPA2 로 붙을 수 있으면
    # 그 세션은 수동으로 복호된다.
    if "wep" in key or "wpa2" in rest or "wpa" in rest:
        return SHARED_PASSIVE
    if has_sae:
        return SHARED_SAE
    return UNKNOWN


def passively_readable(security: Optional[str]) -> bool:
    """별도 공격 없이 조용히 읽히는가."""
    return classify(security) in (OPEN, SHARED_PASSIVE)


def joinable_by_others(security: Optional[str]) -> Optional[bool]:
    """비밀번호를 아는 사람이 같은 L2 에 들어올 수 있는가. 모르면 None."""
    kind = classify(security)
    if kind == UNKNOWN:
        return None
    return kind != PER_USER
