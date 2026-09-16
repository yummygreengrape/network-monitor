"""처음 켰을 때의 설정 마법사.

질문 흐름과 입출력을 분리한다. `Wizard.run()` 은 답을 모아 `Plan` 을 돌려줄
뿐이고 아무것도 바꾸지 않는다. 실제 반영은 `apply()` 가 한다. 그래야 질문
순서와 기본값을 시스템을 건드리지 않고 테스트할 수 있다.

기본값의 원칙은 **최소 권한**이다. 아무 생각 없이 엔터만 눌러도 sudo 를 쓰지
않고, 외부로 요청을 보내지 않고, 상시 실행으로 등록되지 않는다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import config as configmod
from . import messages as msg
from . import messages as _messages_mod
from . import service, vpn

MAX_RETRIES = 5


@dataclass
class Plan:
    """마법사가 모은 답. 이것만으로는 아무것도 바뀌지 않는다."""

    language: str = "ko"
    interval: int = 5
    log_dir: str = ""
    retention_days: int = 14
    want_location: bool = False
    want_vpn: bool = False
    vpn_providers: List[str] = field(default_factory=lambda: ["auto"])
    want_external: bool = False
    want_agent: bool = False
    want_link: bool = True
    confirmed: bool = False

    def summary_lines(self) -> List[str]:
        def mark(on: bool) -> str:
            return msg.WZ_ON if on else msg.WZ_OFF
        return [
            msg.WZ_ROW_LANGUAGE % _messages_mod.display_name(self.language),
            msg.WZ_ROW_INTERVAL % self.interval,
            msg.WZ_ROW_LOGDIR % self.log_dir,
            msg.WZ_ROW_RETENTION % self.retention_days,
            msg.WZ_ROW_LOCATION % mark(self.want_location),
            msg.WZ_ROW_VPN % (mark(self.want_vpn),
                              ", ".join(self.vpn_providers) if self.want_vpn else "-"),
            msg.WZ_ROW_EXTERNAL % mark(self.want_external),
            msg.WZ_ROW_AGENT % mark(self.want_agent),
            msg.WZ_ROW_LINK % mark(self.want_link),
        ]


class Wizard:
    def __init__(self, ask: Callable[[str], str], say: Callable[[str], None],
                 default_log_dir: str, installed_vpn: Optional[List[str]] = None) -> None:
        self.ask = ask
        self.say = say
        self.default_log_dir = default_log_dir
        self.installed_vpn = installed_vpn if installed_vpn is not None else [
            p.name for p in vpn.installed_providers()]

    # --- 입력 도우미 ---
    def _choice(self, question: str, options: Sequence[Tuple[str, str]], default: int) -> int:
        self.say("")
        self.say(question)
        for i, (label, note) in enumerate(options, 1):
            star = msg.WZ_DEFAULT_MARK if i == default else ""
            self.say("  %d) %-10s %s%s" % (i, label, note, star))
        for _ in range(MAX_RETRIES):
            raw = self.ask(msg.WZ_PICK % default).strip()
            if not raw:
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return int(raw)
            self.say(msg.WZ_PICK_RANGE % len(options))
        return default

    def _yes_no(self, question: str, default: bool) -> bool:
        hint = "Y/n" if default else "y/N"
        for _ in range(MAX_RETRIES):
            raw = self.ask("%s (%s): " % (question, hint)).strip().lower()
            if not raw:
                return default
            if raw in ("y", "yes", "예", "ㅇ"):
                return True
            if raw in ("n", "no", "아니오", "ㄴ"):
                return False
            self.say(msg.WZ_YES_NO)
        return default

    def _text(self, question: str, default: str) -> str:
        raw = self.ask("%s [%s]: " % (question, default)).strip()
        return raw or default

    # --- 질문 흐름 ---
    def run(self) -> Plan:
        plan = Plan(log_dir=self.default_log_dir)

        # 1. 언어 — 가장 먼저 묻고 즉시 반영한다. 나머지 질문이 그 언어로 나온다.
        codes = _messages_mod.available()
        idx = self._choice(
            msg.WZ_LANG_Q,
            [(_messages_mod.display_name(c), "") for c in codes],
            default=codes.index(_messages_mod.language()) + 1
            if _messages_mod.language() in codes else 1)
        plan.language = codes[idx - 1]
        _messages_mod.set_language(plan.language)

        self.say("")
        self.say(msg.WZ_TITLE)
        for line in msg.WZ_INTRO.splitlines():
            self.say(line)

        # 2. 측정 간격
        idx = self._choice(msg.WZ_INTERVAL_Q, [
            ("3s", msg.WZ_INTERVAL_3), ("5s", msg.WZ_INTERVAL_5),
            ("10s", msg.WZ_INTERVAL_10), ("30s", msg.WZ_INTERVAL_30)], default=2)
        plan.interval = [3, 5, 10, 30][idx - 1]

        # 3. 기록 위치
        plan.log_dir = self._text(msg.WZ_LOGDIR_Q, self.default_log_dir)

        # 4. 보존 기간
        idx = self._choice(msg.WZ_RETENTION_Q, [
            ("7", msg.WZ_RETENTION_7), ("14", msg.WZ_RETENTION_14),
            ("30", msg.WZ_RETENTION_30), ("90", msg.WZ_RETENTION_90)], default=2)
        plan.retention_days = [7, 14, 30, 90][idx - 1]

        # 5. 위치 권한
        self.say("")
        self.say(msg.WZ_LOCATION_HEAD)
        for line in msg.WZ_LOCATION_BODY.splitlines():
            self.say(line)
        plan.want_location = self._yes_no(msg.WZ_LOCATION_Q, default=False)

        # 6. VPN
        self.say("")
        if self.installed_vpn:
            self.say(msg.WZ_VPN_HEAD % ", ".join(self.installed_vpn))
            self.say(msg.WZ_VPN_BODY)
            plan.want_vpn = self._yes_no(msg.WZ_VPN_Q, default=False)
        else:
            self.say(msg.WZ_VPN_NONE)
            plan.want_vpn = False

        # 7. 외부 요청
        self.say("")
        self.say(msg.WZ_EXTERNAL_HEAD)
        for line in msg.WZ_EXTERNAL_BODY.splitlines():
            self.say(line)
        plan.want_external = self._yes_no(msg.WZ_EXTERNAL_Q, default=False)

        # 8. 상시 실행
        self.say("")
        self.say(msg.WZ_AGENT_HEAD)
        for line in msg.WZ_AGENT_BODY.splitlines():
            self.say(line)
        plan.want_agent = self._yes_no(msg.WZ_AGENT_Q, default=False)

        # 9. 어디서나 실행
        self.say("")
        self.say(msg.WZ_LINK_HEAD)
        for line in msg.WZ_LINK_BODY.splitlines():
            self.say(line)
        plan.want_link = self._yes_no(msg.WZ_LINK_Q, default=True)

        # 10. 확인
        self.say("")
        self.say(msg.WZ_SUMMARY_HEAD)
        for line in plan.summary_lines():
            self.say("  " + line)
        plan.confirmed = self._yes_no(msg.WZ_CONFIRM_Q, default=True)
        return plan


def apply(plan: Plan, cfg: configmod.Config) -> Dict[str, Any]:
    """Plan 을 설정에 반영한다. 권한 요청과 상시 실행 등록은 호출자가 한다.

    돌려주는 dict 는 "호출자가 이어서 해야 할 일"이다. 권한 요청처럼 사용자와
    상호작용이 필요한 것을 여기서 하지 않는 이유는, 이 함수를 테스트에서
    그대로 부를 수 있게 하기 위해서다.
    """
    cfg.data["language"] = plan.language
    cfg.data["interval"] = int(plan.interval)
    cfg.data["retention_days"] = int(plan.retention_days)
    cfg.data["log_dir"] = plan.log_dir

    cfg.set_feature("vpn.enabled", bool(plan.want_vpn))
    if plan.want_vpn:
        cfg.set_feature("vpn.providers", list(plan.vpn_providers))

    if plan.want_external:
        cfg.grant("external_probes", note="초기 설정에서 선택")
        for feat in configmod.CONSENTS["external_probes"]["enables"]:
            if feat in cfg.data.get("features", {}):
                cfg.set_feature(feat, True)
    else:
        cfg.revoke("external_probes")

    if not plan.want_location:
        cfg.revoke("location")

    cfg.save()
    return {
        "needs_location_request": plan.want_location,
        "needs_agent_install": plan.want_agent,
        "needs_link": plan.want_link,
        "log_dir": plan.log_dir,
    }


def default_log_dir(config_home: str) -> str:
    return os.environ.get("NETMON_LOG_DIR") or os.path.join(config_home, "data")
