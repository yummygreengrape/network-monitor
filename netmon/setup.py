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
from . import service, vpn

MAX_RETRIES = 5


@dataclass
class Plan:
    """마법사가 모은 답. 이것만으로는 아무것도 바뀌지 않는다."""

    interval: int = 5
    log_dir: str = ""
    retention_days: int = 14
    want_location: bool = False
    want_vpn: bool = False
    vpn_providers: List[str] = field(default_factory=lambda: ["auto"])
    want_external: bool = False
    want_agent: bool = False
    confirmed: bool = False

    def summary_lines(self) -> List[str]:
        def mark(on: bool) -> str:
            return "켬" if on else "끔"
        return [
            "측정 간격        %d초" % self.interval,
            "기록 위치        %s" % self.log_dir,
            "보존 기간        %d일" % self.retention_days,
            "위치 권한        %s  (evil twin 탐지)" % mark(self.want_location),
            "VPN 감시         %s  (%s)" % (mark(self.want_vpn),
                                           ", ".join(self.vpn_providers) if self.want_vpn else "-"),
            "외부 점검 요청   %s  (DNS·TLS 가로채기, 공인 IP)" % mark(self.want_external),
            "상시 실행        %s  (로그인할 때 자동 시작)" % mark(self.want_agent),
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
            star = " (기본)" if i == default else ""
            self.say("  %d) %-10s %s%s" % (i, label, note, star))
        for _ in range(MAX_RETRIES):
            raw = self.ask("선택 [%d]: " % default).strip()
            if not raw:
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return int(raw)
            self.say("  1에서 %d 사이의 번호를 넣으세요." % len(options))
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
            self.say("  y 또는 n 으로 답하세요.")
        return default

    def _text(self, question: str, default: str) -> str:
        raw = self.ask("%s [%s]: " % (question, default)).strip()
        return raw or default

    # --- 질문 흐름 ---
    def run(self) -> Plan:
        plan = Plan(log_dir=self.default_log_dir)

        self.say("netmon 초기 설정")
        self.say("엔터만 누르면 기본값입니다. 기본값은 sudo 를 쓰지 않고, 외부로")
        self.say("요청을 보내지 않고, 상시 실행으로 등록하지도 않습니다.")

        # 1. 측정 간격
        idx = self._choice(
            "얼마나 자주 측정할까요?",
            [("3초", "변화를 빨리 잡습니다. 배터리를 조금 더 씁니다"),
             ("5초", "대부분의 경우에 적당합니다"),
             ("10초", "배터리를 아낍니다. 짧은 끊김을 놓칠 수 있습니다"),
             ("30초", "아주 가볍게. 품질 판정은 거칠어집니다")],
            default=2)
        plan.interval = [3, 5, 10, 30][idx - 1]

        # 2. 기록 위치
        plan.log_dir = self._text("\n기록을 어디에 둘까요?", self.default_log_dir)

        # 3. 보존 기간
        idx = self._choice(
            "기록을 며칠 보관할까요?",
            [("7일", "가볍게"), ("14일", "기본"), ("30일", "오래 되짚어 보려면"),
             ("90일", "디스크를 꽤 씁니다")],
            default=2)
        plan.retention_days = [7, 14, 30, 90][idx - 1]

        # 4. 위치 권한
        self.say("")
        self.say("[위치 권한]  Wi-Fi 이름(SSID)과 접속점 식별자(BSSID)를 읽습니다.")
        self.say("  같은 이름을 쓰는 가짜 접속점(evil twin)과 정상적인 접속점 전환을")
        self.say("  구분하는 데 씁니다. 위치 좌표는 읽지 않고, 값은 이 기계 밖으로")
        self.say("  나가지 않습니다. macOS 권한이 앱 단위라 작은 헬퍼 앱을 만듭니다.")
        plan.want_location = self._yes_no("  위치 권한을 쓸까요?", default=False)

        # 5. VPN
        self.say("")
        if self.installed_vpn:
            self.say("[VPN 감시]  이 기계에서 찾은 VPN: %s" % ", ".join(self.installed_vpn))
            self.say("  연결 상태와 끊김을 함께 기록합니다. 외부로 나가는 요청은 없습니다.")
            plan.want_vpn = self._yes_no("  VPN 감시를 켤까요?", default=False)
        else:
            self.say("[VPN 감시]  설치된 VPN 을 찾지 못해 건너뜁니다.")
            plan.want_vpn = False

        # 6. 외부 요청
        self.say("")
        self.say("[외부 점검 요청]  DNS 응답을 기준값과 비교하고(가로채기 탐지),")
        self.say("  고정 호스트의 TLS 발급자와 공인 IP 변화를 봅니다.")
        self.say("  고정된 조회 이름과 이 기계의 출발지 IP 가 밖으로 나갑니다.")
        self.say("  SSID·BSSID·MAC 같은 네트워크 식별자는 보내지 않습니다.")
        plan.want_external = self._yes_no("  외부 점검 요청을 켤까요?", default=False)

        # 7. 상시 실행
        self.say("")
        self.say("[상시 실행]  로그인할 때 자동으로 시작하고, 멈추면 다시 띄웁니다.")
        self.say("  ~/Library/LaunchAgents 에 파일 하나를 만듭니다. sudo 는 쓰지 않고,")
        self.say("  나중에 netmon.sh service uninstall 로 되돌릴 수 있습니다.")
        plan.want_agent = self._yes_no("  항상 켜 둘까요?", default=False)

        # 8. 확인
        self.say("")
        self.say("이대로 적용합니다:")
        for line in plan.summary_lines():
            self.say("  " + line)
        plan.confirmed = self._yes_no("\n적용할까요?", default=True)
        return plan


def apply(plan: Plan, cfg: configmod.Config) -> Dict[str, Any]:
    """Plan 을 설정에 반영한다. 권한 요청과 상시 실행 등록은 호출자가 한다.

    돌려주는 dict 는 "호출자가 이어서 해야 할 일"이다. 권한 요청처럼 사용자와
    상호작용이 필요한 것을 여기서 하지 않는 이유는, 이 함수를 테스트에서
    그대로 부를 수 있게 하기 위해서다.
    """
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
        "log_dir": plan.log_dir,
    }


def default_log_dir(config_home: str) -> str:
    return os.environ.get("NETMON_LOG_DIR") or os.path.join(config_home, "data")
