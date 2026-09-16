"""위치 권한 헬퍼 앱과의 통신.

macOS 의 위치 권한은 **앱 단위**다. 터미널에서 돌리는 파이썬은 권한을 요청할
주체가 없고, 권한을 받은 다른 앱의 승인을 물려받지도 못한다. 실측:

  - 단일 실행 파일로 requestWhenInUseAuthorization 호출 → 75초 동안 창 없음
  - 앱 번들을 LaunchServices 로 띄움 → 창이 뜨고 authorized-always 획득
  - 그 상태에서도 터미널의 `ipconfig getsummary` 는 여전히 <redacted>

그래서 권한을 가진 쪽이 값을 읽어서 넘긴다. 헬퍼는 SSID 와 BSSID 만 돌려주고,
위치 좌표도 주변 AP 목록도 읽지 않는다.

`open -n` 으로 새 인스턴스를 띄운다. `-n` 이 없으면 이미 실행 중인 인스턴스가
그냥 다시 활성화될 뿐 새 인자가 전달되지 않는다.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from typing import Dict, Optional

APP_NAME = "NetworkMonitorLocation.app"

# 헬퍼 한 번 실행에 0.5초쯤 걸린다. 매 주기 호출하면 앱 실행이 쌓이므로
# 이 간격 안에서는 직전 값을 다시 쓴다.
DEFAULT_MIN_INTERVAL = 15.0

_cache: Dict[str, object] = {"at": 0.0, "value": None}


def app_path(config_home: str) -> str:
    return os.path.join(os.path.expanduser(config_home), APP_NAME)


def installed(config_home: str) -> bool:
    return os.path.isdir(app_path(config_home))


def parse_output(text: str) -> Dict[str, str]:
    """헬퍼가 남긴 `key=value` 줄을 dict 로. 순수 함수 — 테스트용."""
    parsed: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            parsed[k.strip()] = v.strip()
    return parsed


def _run(config_home: str, args, timeout: float) -> Dict[str, str]:
    """헬퍼를 띄우고 결과 파일을 읽는다."""
    app = app_path(config_home)
    if not os.path.isdir(app):
        return {"error": "helper-missing"}

    fd, out = tempfile.mkstemp(prefix="netmon-loc-", suffix=".txt")
    os.close(fd)
    os.unlink(out)
    try:
        argv = ["open", "-n", "-a", app, "--args"] + list(args) + ["--out", out]
        try:
            subprocess.run(argv, capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return {"error": "launch-failed"}

        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(out):
                with open(out, encoding="utf-8", errors="replace") as fh:
                    parsed = parse_output(fh.read())
                return parsed or {"error": "empty"}
            time.sleep(0.2)
        return {"error": "timeout"}
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


def status(config_home: str, timeout: float = 10.0) -> str:
    """현재 권한 상태. 요청 창을 띄우지 않는다."""
    r = _run(config_home, ["--status"], timeout)
    return r.get("status") or r.get("error") or "unknown"


def request(config_home: str, timeout: float = 120.0) -> str:
    """권한 요청 창을 띄우고 사용자의 응답을 기다린다."""
    r = _run(config_home, ["--timeout", str(int(timeout))], timeout + 10)
    return r.get("status") or r.get("error") or "unknown"


def wifi(config_home: str, min_interval: float = DEFAULT_MIN_INTERVAL,
         force: bool = False, timeout: float = 8.0) -> Optional[Dict[str, str]]:
    """SSID 와 BSSID. 권한이 없거나 Wi-Fi 가 아니면 None.

    min_interval 안에서는 캐시된 값을 돌려준다.
    """
    now = time.time()
    if not force and _cache["value"] is not None:
        if now - float(_cache["at"]) < min_interval:
            return dict(_cache["value"])  # type: ignore[arg-type]

    r = _run(config_home, ["--wifi"], timeout)
    if r.get("error") or r.get("wifi") == "none":
        return None
    ssid = r.get("ssid") or None
    bssid = r.get("bssid") or None
    if not ssid and not bssid:
        return None
    value = {"ssid": ssid, "bssid": bssid}
    _cache["at"] = now
    _cache["value"] = value
    return dict(value)


def reset_cache() -> None:
    _cache["at"] = 0.0
    _cache["value"] = None
