"""식별자 가리기.

로그에는 원문을 남긴다. 기록 시점에 해시하면 "MAC 이 a 에서 b 로 바뀜"은
남지만 그 b 가 어제 본 AP 인지 내 폰의 핫스팟인지 사람이 판단할 수 없게 된다.
대신 남에게 보낼 때 이 모듈로 가린다.

같은 값은 같은 토큰이 되므로 "바뀌었다가 원래대로 돌아왔다" 같은 관계는
가린 뒤에도 보존된다.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from typing import Any, Dict, Optional

from .model import ID_KINDS

TOKEN_LEN = 8


def load_or_create_salt(path: str) -> bytes:
    """로컬 솔트를 읽는다. 없으면 만든다. 저장소 밖에 mode 600 으로 둔다."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
    if os.path.exists(path):
        with open(path, "rb") as fh:
            salt = fh.read().strip()
        if salt:
            return salt
    salt = secrets.token_hex(32).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(salt)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return salt


def token(salt: bytes, kind: str, value: Any) -> str:
    """식별자 하나를 안정적인 토큰으로. 종류를 섞어 넣어 교차 대조를 막는다."""
    msg = ("%s\x00%s" % (kind, value)).encode("utf-8", "replace")
    digest = hmac.new(salt, msg, hashlib.sha256).hexdigest()
    return "%s:%s" % (kind, digest[:TOKEN_LEN])


def redact(obj: Any, salt: bytes, kinds: Optional[set] = None) -> Any:
    """ident() 로 감싼 값을 재귀적으로 토큰으로 바꾼다.

    kinds 를 주면 그 종류만 가린다. 감싸지 않은 값은 건드리지 않는다 —
    가려야 할 값을 감싸지 않은 것은 스키마 쪽 버그이고, 여기서
    문자열을 뒤져 추측하면 조용히 반쯤 가려진 로그가 나온다.
    """
    active = kinds if kinds is not None else set(ID_KINDS)
    if isinstance(obj, dict):
        if "id" in obj and "v" in obj and obj["id"] in ID_KINDS:
            if obj["id"] in active and obj["v"] not in (None, "", "-"):
                return {"id": obj["id"], "v": token(salt, obj["id"], obj["v"])}
            return dict(obj)
        return {k: redact(v, salt, kinds) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, salt, kinds) for v in obj]
    return obj


def describe(kinds: Optional[set] = None) -> str:
    active = sorted(kinds if kinds is not None else set(ID_KINDS))
    return "가림 대상: " + ", ".join(active)


def tagged_values(obj: Any, out: Optional[Dict[str, set]] = None) -> Dict[str, set]:
    """감싼 식별자를 종류별로 모은다. 검사·보고용."""
    if out is None:
        out = {}
    if isinstance(obj, dict):
        if "id" in obj and "v" in obj and obj["id"] in ID_KINDS:
            out.setdefault(obj["id"], set()).add(str(obj["v"]))
            return out
        for v in obj.values():
            tagged_values(v, out)
    elif isinstance(obj, list):
        for v in obj:
            tagged_values(v, out)
    return out
