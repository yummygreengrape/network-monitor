"""관측·판정·기준선 저장.

형식은 JSON Lines. 하루 한 파일, 보존 기간이 지나면 지운다.
로그 경로는 항상 설정으로 받는다 — 저장소 안에 실행 데이터를 남기지 않는다.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional

from .model import Finding, Observation


def today() -> str:
    """기록 파일이 쓰는 날짜. **UTC 기준이다.**

    관측의 ts 가 UTC 이므로 파일 이름도 UTC 로 맞춘다. 읽는 쪽이 현지
    날짜를 쓰면 시차만큼 어긋난 파일을 찾는다 — 한국 시간에서는 오전
    9시부터 하루 종일 "기록이 없습니다" 가 나왔다.
    """
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _day(ts: str) -> str:
    return ts[:10] if len(ts) >= 10 else today()


class Store:
    def __init__(self, log_dir: str) -> None:
        self.dir = os.path.expanduser(log_dir)
        os.makedirs(self.dir, exist_ok=True)

    # --- 경로 ---
    def samples_path(self, day: str) -> str:
        return os.path.join(self.dir, "samples-%s.jsonl" % day)

    def events_path(self, day: str) -> str:
        return os.path.join(self.dir, "events-%s.jsonl" % day)

    @property
    def state_path(self) -> str:
        return os.path.join(self.dir, "state.json")

    # --- 쓰기 ---
    def _append(self, path: str, obj: Dict[str, Any]) -> None:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=False, sort_keys=True))
            fh.write("\n")

    def write_sample(self, obs: Observation) -> None:
        self._append(self.samples_path(_day(obs.ts)), obs.as_dict())

    def write_findings(self, ts: str, findings: Iterable[Finding]) -> int:
        n = 0
        path = self.events_path(_day(ts))
        for f in findings:
            self._append(path, f.as_dict(ts=ts))
            n += 1
        return n

    # --- 읽기 ---
    def _read(self, path: str) -> Iterator[Dict[str, Any]]:
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue  # 실행 중 잘린 마지막 줄

    def samples(self, day: str) -> Iterator[Dict[str, Any]]:
        return self._read(self.samples_path(day))

    def events(self, day: str) -> Iterator[Dict[str, Any]]:
        return self._read(self.events_path(day))

    def days(self) -> List[str]:
        out = set()
        for name in os.listdir(self.dir):
            if name.startswith(("samples-", "events-")) and name.endswith(".jsonl"):
                out.add(name.split("-", 1)[1][: -len(".jsonl")])
        return sorted(out)

    # --- 기준선 ---
    def load_state(self) -> Dict[str, Any]:
        if not os.path.exists(self.state_path):
            return {}
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    @property
    def baseline_path(self) -> str:
        return os.path.join(self.dir, "baseline.json")

    def load_baseline(self) -> Dict[str, Any]:
        """재시작을 건너뛸 비교 기준. 없거나 깨졌으면 빈 dict."""
        if not os.path.exists(self.baseline_path):
            return {}
        try:
            with open(self.baseline_path, encoding="utf-8") as fh:
                got = json.load(fh)
            return got if isinstance(got, dict) else {}
        except (ValueError, OSError):
            return {}

    def save_baseline(self, data: Dict[str, Any]) -> None:
        """관측 하나(6KB 남짓)라 state.json 과 섞지 않는다.

        state.json 은 매 주기 다시 쓰이므로, 여기에 관측을 넣으면 쓰기량이
        20배가 된다. 파일을 나누고 저장 주기도 따로 둔다.
        """
        tmp = self.baseline_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, self.baseline_path)

    def save_state(self, state: Dict[str, Any]) -> None:
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, sort_keys=True, indent=1)
            fh.write("\n")
        os.replace(tmp, self.state_path)

    # --- 보존 ---
    AGENT_LOG_MAX = 5 * 1024 * 1024

    def rotate_agent_logs(self) -> int:
        """상시 실행 로그가 무한히 커지지 않게 자른다.

        launchd 의 StandardOutPath 는 회전되지 않는다. 몇 달 켜 두면 수 GB 가
        된다. 최근 절반만 남기고 앞을 버린다.
        """
        trimmed = 0
        for name in os.listdir(self.dir):
            if not (name.startswith("agent.") and name.endswith(".log")):
                continue
            path = os.path.join(self.dir, name)
            try:
                if os.path.getsize(path) <= self.AGENT_LOG_MAX:
                    continue
                with open(path, "rb") as fh:
                    fh.seek(-self.AGENT_LOG_MAX // 2, os.SEEK_END)
                    fh.readline()  # 잘린 첫 줄은 버린다
                    tail = fh.read()
                with open(path, "wb") as fh:
                    fh.write("... (앞부분을 잘랐다)\n".encode("utf-8"))
                    fh.write(tail)
                trimmed += 1
            except OSError:
                pass
        return trimmed

    def prune(self, retention_days: int) -> int:
        """보존 기간이 지난 기록을 지운다.

        **파일 이름의 날짜로 판단한다.** 수정 시각(mtime)은 백업·동기화·복사가
        건드리므로 기준이 될 수 없다. 이름은 UTC 날짜로 붙으므로(today())
        문자열 비교만으로 충분하다.

        보존 기간은 최소 1일로 묶는다. 설정에 0 이 들어가면 방금 쓴 오늘
        기록까지 지워진다 — 테스트가 실제로 그것을 잡았다.
        """
        import datetime

        keep_days = max(1, int(retention_days))
        cutoff = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(days=keep_days)).strftime("%Y-%m-%d")
        removed = 0
        for name in os.listdir(self.dir):
            if not name.endswith(".jsonl"):
                continue
            if not name.startswith(("samples-", "events-")):
                continue
            day = name.split("-", 1)[1][: -len(".jsonl")]
            if len(day) != 10 or day >= cutoff:
                continue
            try:
                os.remove(os.path.join(self.dir, name))
                removed += 1
            except OSError:
                pass
        self.rotate_agent_logs()
        return removed


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    out = []
    with open(os.path.expanduser(path), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def observations_from(path: str) -> List[Observation]:
    """캡처 파일을 관측 목록으로. 판정 재현·회귀 테스트에 쓴다."""
    return [Observation.from_dict(d) for d in read_jsonl(path)]
