"""상시 실행 등록 (launchd LaunchAgent).

사용자가 **명시적으로 선택했을 때만** 등록한다. 기본값은 등록하지 않는 것이다.
남의 기계에 로그인할 때마다 뜨는 프로세스를 심는 일이라, 무엇을 어디에
쓰는지 먼저 보여 주고 확인을 받는다.

plist 는 문자열로 짜지 않고 plistlib 로 만든다. 경로에 따옴표나 &,
한글이 들어가도 깨지지 않게 하기 위해서다.
"""
from __future__ import annotations

import os
import plistlib
from typing import Any, Dict, List, Optional

from .util import run

LABEL = "io.github.network-monitor"


def plist_path(label: str = LABEL) -> str:
    return os.path.join(os.path.expanduser("~/Library/LaunchAgents"), "%s.plist" % label)


def domain() -> str:
    return "gui/%d" % os.getuid()


def service_target(label: str = LABEL) -> str:
    return "%s/%s" % (domain(), label)


def plist_dict(script: str, log_dir: str, label: str = LABEL,
               env: Optional[Dict[str, str]] = None,
               interval: Optional[int] = None) -> Dict[str, Any]:
    """LaunchAgent 정의를 만든다. 순수 함수 — 파일을 쓰지 않는다."""
    args: List[str] = ["/bin/bash", script, "run"]
    if interval:
        args += ["--interval", str(int(interval))]

    d: Dict[str, Any] = {
        "Label": label,
        "ProgramArguments": args,
        # 로그인할 때 시작하고, 죽으면 다시 띄운다. 감시 도구가 조용히 멈춰 있는
        # 것이 가장 나쁜 실패다.
        "RunAtLoad": True,
        "KeepAlive": True,
        # 배터리와 다른 작업을 방해하지 않도록 우선순위를 낮춘다.
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 5,
        "StandardOutPath": os.path.join(log_dir, "agent.out.log"),
        "StandardErrorPath": os.path.join(log_dir, "agent.err.log"),
        "WorkingDirectory": os.path.dirname(script) or "/",
    }
    if env:
        d["EnvironmentVariables"] = dict(env)
    return d


def render(plist: Dict[str, Any]) -> bytes:
    return plistlib.dumps(plist, sort_keys=True)


def installed(label: str = LABEL) -> bool:
    return os.path.exists(plist_path(label))


def loaded(label: str = LABEL) -> bool:
    return run(["launchctl", "print", service_target(label)], timeout=8).rc == 0


def describe(label: str = LABEL) -> Dict[str, Any]:
    """등록 상태를 사람이 읽을 수 있게."""
    path = plist_path(label)
    out: Dict[str, Any] = {"label": label, "plist": path,
                           "installed": os.path.exists(path), "loaded": False,
                           "pid": None, "state": None, "script": None,
                           "script_exists": None}
    if out["installed"]:
        try:
            with open(path, "rb") as fh:
                d = plistlib.load(fh)
            args = d.get("ProgramArguments") or []
            if len(args) > 1:
                out["script"] = args[1]
                out["script_exists"] = os.path.exists(args[1])
        except Exception:
            pass

    r = run(["launchctl", "print", service_target(label)], timeout=8)
    if r.rc == 0:
        out["loaded"] = True
        for line in r.out.splitlines():
            s = line.strip()
            if s.startswith("pid = "):
                out["pid"] = s.split("=", 1)[1].strip()
            elif s.startswith("state = "):
                out["state"] = s.split("=", 1)[1].strip()
    return out


def install(script: str, log_dir: str, label: str = LABEL,
            env: Optional[Dict[str, str]] = None,
            interval: Optional[int] = None) -> Dict[str, Any]:
    """plist 를 쓰고 launchd 에 등록한다."""
    script = os.path.abspath(os.path.expanduser(script))
    log_dir = os.path.abspath(os.path.expanduser(log_dir))
    os.makedirs(log_dir, exist_ok=True)

    path = plist_path(label)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = render(plist_dict(script, log_dir, label, env, interval))
    with open(path, "wb") as fh:
        fh.write(data)

    # 이미 떠 있으면 내리고 다시 올린다
    run(["launchctl", "bootout", service_target(label)], timeout=10)
    r = run(["launchctl", "bootstrap", domain(), path], timeout=15)
    return {"plist": path, "ok": r.rc == 0,
            "error": (r.err or r.out).strip()[:200] if r.rc != 0 else ""}


def uninstall(label: str = LABEL) -> Dict[str, Any]:
    r = run(["launchctl", "bootout", service_target(label)], timeout=10)
    path = plist_path(label)
    removed = False
    if os.path.exists(path):
        os.remove(path)
        removed = True
    return {"plist": path, "removed": removed, "booted_out": r.rc == 0}


def restart(label: str = LABEL) -> bool:
    return run(["launchctl", "kickstart", "-k", service_target(label)], timeout=15).rc == 0


def stop(label: str = LABEL) -> bool:
    return run(["launchctl", "bootout", service_target(label)], timeout=10).rc == 0


def start(label: str = LABEL) -> bool:
    path = plist_path(label)
    if not os.path.exists(path):
        return False
    return run(["launchctl", "bootstrap", domain(), path], timeout=15).rc == 0
