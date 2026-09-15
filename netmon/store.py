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


def _day(ts: str) -> str:
    return ts[:10] if len(ts) >= 10 else time.strftime("%Y-%m-%d")


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

    def save_state(self, state: Dict[str, Any]) -> None:
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, sort_keys=True, indent=1)
            fh.write("\n")
        os.replace(tmp, self.state_path)

    # --- 보존 ---
    def prune(self, retention_days: int) -> int:
        cutoff = time.time() - retention_days * 86400
        removed = 0
        for name in os.listdir(self.dir):
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(self.dir, name)
            try:
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    removed += 1
            except OSError:
                pass
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
