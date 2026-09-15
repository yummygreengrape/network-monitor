"""수집기.

각 수집기는 두 부분으로 나뉜다.

  parse_*(text) -> dict   순수 함수. 명령 출력 문자열만 받는다.
  collect(ctx)  -> dict   명령을 실행하고 parse_* 에 넘긴다.

이렇게 나누는 이유는 테스트다. 현장에서 명령 출력을 한 번 떠 오면
(합성값으로 치환한 뒤) 이후 판정 수정은 네트워크 없이 재현할 수 있다.
"""
from __future__ import annotations

from typing import Dict, List

from . import arp, dhcp, dns, iface, link, route, wifi  # noqa: F401

# 실행 순서가 있다. iface 가 먼저 돌아야 나머지가 대상 인터페이스를 안다.
REGISTRY = [iface, arp, dhcp, route, dns, wifi, link]


def by_name() -> Dict[str, object]:
    return {m.NAME: m for m in REGISTRY}


def names() -> List[str]:
    return [m.NAME for m in REGISTRY]
