"""식별자 가리기.

로그에는 원문을 남긴다. 기록 시점에 해시하면 "MAC 이 a 에서 b 로 바뀜"은
남지만 그 b 가 어제 본 AP 인지 내 폰의 핫스팟인지 사람이 판단할 수 없게 된다.
대신 남에게 보낼 때 이 모듈로 가린다.

같은 값은 같은 토큰이 되므로 "바뀌었다가 원래대로 돌아왔다" 같은 관계는
가린 뒤에도 보존된다.

가리는 것은 두 갈래다. **`ident()` 로 감싼 값**은 통째로 토큰이 된다. **공급자·
데몬이 준 자유 문자열**(`FREE_TEXT_KEYS`, `LINE_LIST_KEYS`)은 우리가 모양을 정할 수
없어 감쌀 수 없으므로, 그 안의 IPv4·IPv6 주소만 찾아 같은 방식의 토큰으로 바꾼다.
그 밖의 감싸지 않은 값은 건드리지 않는다(`redact` 참조).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import stat
from typing import Any, Callable, Dict, Optional

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


# 공급자·데몬이 준 자유 문자열. 여기서만 문자열 속 주소를 찾아 가린다.
# `reason` 은 공급자 사유(예: WARP 의 "Performing happy eyeballs to <주소>:<포트>"),
# `provider_reason` 은 그것을 옮긴 판정 증거, 줄 목록은 WARP 데몬 로그에서 도려낸 줄이다.
FREE_TEXT_KEYS = frozenset(("reason", "provider_reason"))
LINE_LIST_KEYS = frozenset(("lines", "daemon_lines", "daemon_transitions"))

# 대괄호 IPv6 | IPv4 | 맨 IPv6. 후보는 ipaddress 로 한 번 더 검증한다 — 시각
# (`12:34:56`)·MAC(`00:00:5e:00:53:01`)·모듈 경로의 `::` 는 주소가 아니다.
# 앞뒤 둘러보기로 영숫자 한가운데서 시작하지 않게 해 긴 입력에서도 선형으로 끝난다.
# 경계는 ASCII 영숫자·점(IPv6 은 콜론까지)만 본다 — 밑줄·한글 조사·문장 끝 마침표에
# 붙은 주소도 가린다. 뒤의 점은 숫자(IPv6 은 영숫자)가 이어질 때만 막는다(`192.0.2.1.5`).
# 이 경계 때문에 앞뒤가 영숫자·점(IPv6 은 콜론까지)으로 이어진 주소(`ip192.0.2.1`,
# `host.192.0.2.1`, `addr:2001:db8::7`)는 못 가린다. ipaddress 가 거부하는 모양(잘린 조각,
# 0으로 시작하는 옥텟, 포트가 콜론으로 붙은 8그룹 IPv6)도 그대로 남는다(README "개인정보").
# IPv4 를 품은 IPv6 표기(`2001:db8::192.0.2.1`, `::ffff:192.0.2.1`)는 따로 갈래(`v6e`)로 통째로 잡는다 — 없으면 뒤의 IPv4 만
# 가려 IPv6 앞부분이 남는다. 이 갈래는 뒤에 `:<숫자>`(포트)가 와도 된다. 후보가 IPv6 로 유효하지 않거나(`:::192.0.2.1`)
# IPv6 을 가리지 않는 종류 필터면 뒤의 IPv4 만 옛 경로처럼 가린다(작업 2026-09-23-warp-daemon-log DEV-10).
_ADDR = re.compile(
    r"\[(?P<b6>[0-9A-Fa-f:.]+(?:%[\w.]+)?)\]"
    r"|(?<![0-9A-Za-z.])(?P<v4>\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z]|\.\d)"
    r"|(?<![0-9A-Za-z:.])(?P<v6e>(?:[0-9A-Fa-f]{0,4}:){2,7}(?P<v6e4>\d{1,3}(?:\.\d{1,3}){3})(?:%\w+)?)"
    r"(?![0-9A-Za-z]|\.[0-9A-Za-z]|:(?!\d))"
    r"|(?<![0-9A-Za-z:.])(?P<v6>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?)"
    r"(?![0-9A-Za-z:]|\.[0-9A-Za-z])")


def _address_kind(text: str) -> Optional[str]:
    base = text.split("%", 1)[0]
    try:
        ipaddress.IPv4Address(base)
        return "ipv4"
    except ValueError:
        pass
    if not re.search(r"[0-9A-Fa-f]", base):
        return None                     # `::` 혼자는 가릴 것이 없다
    try:
        ipaddress.IPv6Address(base)
        return "ipv6"
    except ValueError:
        return None


def replace_addresses(text: str, fn: Callable[[str, str], Optional[str]]) -> str:
    """자유 문자열 속 IPv4·IPv6 주소마다 `fn(종류, 값)` 으로 바꾼다. None 이면 그대로 둔다.

    대괄호 IPv6 는 괄호를 남기고 안쪽만 바꾼다. 포트·나머지 글자는 건드리지 않는다.
    내보낼 때의 가림(`redact_text`)과 WARP 데몬 줄 도려내기(netmon/vpn)가 같은 판별을 쓴다.
    """
    def one(m: "re.Match[str]") -> str:
        if m.group("v6e"):
            value = m.group("v6e")
            kind = _address_kind(value)
            rep = fn(kind, value) if kind == "ipv6" else None
            if rep is not None:
                return rep
            # IPv6 로 유효하지 않거나 IPv6 을 가리지 않으면 뒤의 IPv4 만 — 이 갈래가 없던 때와 같다.
            v4 = m.group("v6e4")
            rep4 = fn("ipv4", v4) if _address_kind(v4) == "ipv4" else None
            if rep4 is None:
                return m.group(0)
            a, b = m.start("v6e4") - m.start(), m.end("v6e4") - m.start()
            return m.group(0)[:a] + rep4 + m.group(0)[b:]
        value = m.group("b6") or m.group("v4") or m.group("v6")
        kind = _address_kind(value)
        if kind is None and m.group("b6"):
            # 대괄호 안이 IPv6 하나가 아니면(`[<IPv4>:<포트>]` 등) 안쪽을 다시 훑는다.
            # 안쪽에는 대괄호가 없어 한 번으로 끝난다.
            return "[%s]" % _ADDR.sub(one, value)
        rep = fn(kind, value) if kind is not None else None
        if rep is None:
            return m.group(0)
        return "[%s]" % rep if m.group("b6") else rep

    return _ADDR.sub(one, text)


def redact_text(text: str, salt: bytes, kinds: Optional[set] = None) -> str:
    """자유 문자열 속 IPv4·IPv6 주소를 토큰으로 바꾼다. 포트·나머지 글자는 그대로 둔다.

    같은 주소는 `ident()` 로 감싼 값과 같은 토큰이 된다(`token` 이 종류와 값만 본다).
    """
    active = kinds if kinds is not None else set(ID_KINDS)
    return replace_addresses(
        text, lambda kind, value: token(salt, kind, value) if kind in active else None)


def redact(obj: Any, salt: bytes, kinds: Optional[set] = None) -> Any:
    """ident() 로 감싼 값을 재귀적으로 토큰으로 바꾼다.

    kinds 를 주면 그 종류만 가린다. **감싸지 않은 값은 건드리지 않는다** —
    가려야 할 값을 감싸지 않은 것은 스키마 쪽 버그이고, 여기서 아무 문자열이나
    뒤져 추측하면 조용히 반쯤 가려진 로그가 나온다. 예외는 공급자·데몬이 준 자유
    문자열 필드(`FREE_TEXT_KEYS`, `LINE_LIST_KEYS` 안의 `text`)뿐이다 — 그 모양은
    우리가 정할 수 없어 감쌀 수 없고, 그대로 두면 사유에 적힌 주소가 내보낸 기록에
    남는다(사용자 결정 2026-09-21 "로컬 원문·내보낼 때 가림"). 그 필드에서는
    `redact_text` 로 주소만 가린다.
    """
    active = kinds if kinds is not None else set(ID_KINDS)
    if isinstance(obj, dict):
        if "id" in obj and "v" in obj and obj["id"] in ID_KINDS:
            if obj["id"] in active and obj["v"] not in (None, "", "-"):
                return {"id": obj["id"], "v": token(salt, obj["id"], obj["v"])}
            return dict(obj)
        out = {}
        for k, v in obj.items():
            if k in FREE_TEXT_KEYS and isinstance(v, str):
                out[k] = redact_text(v, salt, kinds)
            elif k in LINE_LIST_KEYS and isinstance(v, list):
                out[k] = [_redact_line(item, salt, kinds) for item in v]
            else:
                out[k] = redact(v, salt, kinds)
        return out
    if isinstance(obj, list):
        return [redact(v, salt, kinds) for v in obj]
    return obj


def _redact_line(item: Any, salt: bytes, kinds: Optional[set]) -> Any:
    """데몬 줄 하나(`{ts, kind, text}`)의 `text` 속 주소를 가린다. 모양이 다르면 일반 규칙."""
    if isinstance(item, dict) and isinstance(item.get("text"), str):
        out = redact(item, salt, kinds)
        out["text"] = redact_text(item["text"], salt, kinds)
        return out
    return redact(item, salt, kinds)


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
