"""사용자에게 보이는 문구.

문구를 고치려면 언어별 카탈로그 한 파일만 열면 된다.

    netmon/messages/ko.py   한국어
    netmon/messages/en.py   English

쓰는 쪽은 언어를 신경 쓰지 않는다. `msg.LATENCY_SPIKE` 처럼 이름으로 부르면
지금 정해진 언어의 문구가 나온다 — 모듈 수준 __getattr__ 로 늦게 묶기
때문에, 설정을 읽어 언어를 정하는 시점이 import 보다 뒤여도 된다.

언어 결정 순서
    NETMON_LANG 환경 변수  >  설정 파일의 language  >  기본값(ko)

카탈로그에 없는 이름은 기본 언어에서 찾고, 거기에도 없으면 AttributeError 를
낸다. 조용히 빈 문자열을 돌려주면 화면에서 문구가 사라진 것을 알아채기 어렵다.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional

from . import en, ko

CATALOGUES = {"ko": ko, "en": en}
NAMES = {"ko": "한국어", "en": "English"}
DEFAULT = "ko"
ENV = "NETMON_LANG"

_active = DEFAULT


def available() -> List[str]:
    return sorted(CATALOGUES)


def language() -> str:
    return _active


def display_name(code: str) -> str:
    return NAMES.get(code, code)


def resolve(configured: Optional[str] = None) -> str:
    """환경 변수 > 설정 > 기본값."""
    for value in (os.environ.get(ENV), configured):
        if value and value.lower() in CATALOGUES:
            return value.lower()
    return DEFAULT


def set_language(code: Optional[str]) -> str:
    """활성 언어를 정한다. 모르는 코드면 기본값으로 둔다."""
    global _active
    _active = code.lower() if code and code.lower() in CATALOGUES else DEFAULT
    return _active


def use_config(configured: Optional[str] = None) -> str:
    return set_language(resolve(configured))


def keys(code: str) -> List[str]:
    cat = CATALOGUES[code]
    return sorted(k for k in vars(cat) if k.isupper() and not k.startswith("_"))


def get(name: str, code: Optional[str] = None) -> str:
    cat = CATALOGUES.get(code or _active, CATALOGUES[DEFAULT])
    if hasattr(cat, name):
        return getattr(cat, name)
    fallback = CATALOGUES[DEFAULT]
    if hasattr(fallback, name):
        return getattr(fallback, name)
    raise AttributeError("알 수 없는 문구 이름: %s" % name)


def __getattr__(name: str) -> str:
    if name.startswith("_") or not name.isupper():
        raise AttributeError(name)
    return get(name)
