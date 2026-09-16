"""어디서나 `netmon` 으로 부를 수 있게 하는 심볼릭 링크.

`./netmon.sh` 는 저장소 안에서만 통한다. 다른 디렉터리에서 치면 셸이
`no such file or directory` 를 낸다 — 이 단계에서는 우리 코드가 아직 돌지
않으므로 친절한 안내를 띄울 수도 없다. 그래서 PATH 에 있는 디렉터리에
링크를 걸어 둔다.

링크로 부르면 `$0` 이 링크가 되므로 실행기(netmon.sh)가 링크를 끝까지
따라가서 저장소를 찾는다.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

NAME = "netmon"

# 찾아볼 순서. 앞쪽일수록 PATH 에 이미 있을 가능성이 높다.
CANDIDATES = (
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "~/.local/bin",
    "~/bin",
)


def path_dirs(path_value: Optional[str] = None) -> List[str]:
    """PATH 의 디렉터리들. 중복은 지운다 — 같은 곳이 두 번 있으면 링크도
    두 번 찾은 것처럼 보인다."""
    raw = path_value if path_value is not None else os.environ.get("PATH", "")
    out, seen = [], set()
    for d in raw.split(os.pathsep):
        if not d:
            continue
        key = os.path.realpath(os.path.expanduser(d))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def choose_dir(candidates=CANDIDATES, path_value: Optional[str] = None,
               is_writable=None, exists=None) -> Tuple[Optional[str], str]:
    """링크를 걸 곳을 고른다. (디렉터리, 사유).

    PATH 에 있으면서 쓸 수 있는 곳이 1순위다. 없으면 만들 수 있는 곳을
    고르고, 그 경우 PATH 에 추가하라고 알려 줘야 한다.
    """
    is_writable = is_writable or (lambda d: os.access(d, os.W_OK))
    exists = exists or os.path.isdir
    on_path = set(path_dirs(path_value))

    resolved = [(c, os.path.expanduser(c)) for c in candidates]
    for _, d in resolved:
        if d in on_path and exists(d) and is_writable(d):
            return d, "PATH 에 있고 쓸 수 있는 곳"
    for _, d in resolved:
        if exists(d) and is_writable(d):
            return d, "쓸 수 있지만 PATH 에는 없는 곳"
    for _, d in resolved:
        parent = os.path.dirname(d)
        if exists(parent) and is_writable(parent):
            return d, "새로 만들어야 하는 곳"
    return None, "쓸 수 있는 곳을 찾지 못함"


def link_path(directory: str) -> str:
    return os.path.join(os.path.expanduser(directory), NAME)


def status(directory: Optional[str] = None) -> Dict[str, object]:
    """이미 걸려 있는지, 어디를 가리키는지."""
    found = []
    for d in path_dirs():
        p = os.path.join(d, NAME)
        if os.path.lexists(p):
            found.append({"path": p,
                          "target": os.path.realpath(p),
                          "is_link": os.path.islink(p)})
    return {"found": found, "on_path": bool(found)}


def install(launcher: str, directory: str) -> Dict[str, object]:
    """링크를 건다. 이미 있으면 덮어쓴다."""
    directory = os.path.expanduser(directory)
    launcher = os.path.abspath(os.path.expanduser(launcher))
    if not os.path.exists(launcher):
        return {"ok": False, "error": "실행기를 찾을 수 없습니다: %s" % launcher}
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": "디렉터리를 만들지 못했습니다: %s" % exc}

    dest = os.path.join(directory, NAME)
    if os.path.lexists(dest):
        if not os.path.islink(dest):
            return {"ok": False, "error":
                    "%s 에 링크가 아닌 파일이 이미 있습니다. 직접 확인해 주세요." % dest}
        try:
            os.unlink(dest)
        except OSError as exc:
            return {"ok": False, "error": "기존 링크를 지우지 못했습니다: %s" % exc}
    try:
        os.symlink(launcher, dest)
    except OSError as exc:
        return {"ok": False, "error": "링크를 만들지 못했습니다: %s" % exc}

    return {"ok": True, "path": dest, "target": launcher,
            "on_path": directory in path_dirs()}


def remove() -> Dict[str, object]:
    """PATH 에 걸린 netmon 링크를 지운다. 링크가 아닌 파일은 건드리지 않는다."""
    removed, skipped = [], []
    for entry in status()["found"]:  # type: ignore[index]
        if entry["is_link"]:
            try:
                os.unlink(entry["path"])
                removed.append(entry["path"])
            except OSError:
                skipped.append(entry["path"])
        else:
            skipped.append(entry["path"])
    return {"removed": removed, "skipped": skipped}


def path_hint(directory: str, shell: Optional[str] = None) -> str:
    """PATH 에 없는 곳에 걸었을 때 알려 줄 한 줄."""
    shell = shell or os.path.basename(os.environ.get("SHELL", "zsh"))
    rc = {"zsh": "~/.zshrc", "bash": "~/.bash_profile"}.get(shell, "~/.profile")
    return 'echo \'export PATH="%s:$PATH"\' >> %s' % (directory, rc)
