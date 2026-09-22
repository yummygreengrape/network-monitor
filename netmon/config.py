"""설정과 동의.

두 가지를 분리한다.
  - 기능 켜짐/꺼짐 (features)
  - 그 기능이 필요로 하는 권한에 대한 사용자 동의 (consents)

동의한 항목이 실제로 켜져 있을 때만 해당 접근을 한다. 필요 조건 이상은
쓰지 않는다 — 위치 권한은 BSSID 탐지가 켜져 있는 동안에만 쓴다.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .util import ts_now

APP = "network-monitor"

# 동의가 필요한 항목. 무엇에 쓰는지, 무엇이 밖으로 나가는지 함께 적는다.
CONSENTS = {
    "location": {
        "title": "위치 서비스 권한",
        "why": "Wi-Fi 이름(SSID)과 접속점 식별자(BSSID)를 읽어, 같은 이름을 쓰는 "
               "가짜 접속점(evil twin)과 정상적인 접속점 전환을 구분합니다. "
               "권한이 없으면 macOS 가 두 값을 <redacted> 로 가립니다.",
        "sends_out": "없습니다. 값은 이 기기 밖으로 나가지 않습니다.",
        "enables": ["wifi.bssid", "detect.evil_twin"],
    },
    "external_probes": {
        "title": "외부로 나가는 점검 요청",
        # **아래 두 문구의 터널 엔드포인트 문장은 README·초기 설정 마법사와
        # 글자 그대로 같아야 한다.** 네 곳이 갈리면 어느 것이 실제 동작인지
        # 읽는 사람이 알 수 없다 (AC-4 수정분, tests/test_privacy.py 가 고정).
        "why": "DNS 응답을 DoH 기준값과 비교하고(가로채기 탐지), 고정 호스트의 "
               "TLS 발급자 변화와 공인 IP·ASN 변화를 봅니다. VPN 이 연결돼 있지 "
               "않은 동안(끊김·재협상)에는 공급자가 알려 준 터널 상대편"
               "(엔드포인트)에 도달하는지도 재서, 문제가 이 기기 쪽인지 터널 "
               "상대편 쪽인지 가릴 근거를 남깁니다.",
        "sends_out": "고정된 조회 대상 이름과 이 기기의 출발지 IP 입니다. "
                     "VPN 이 연결돼 있지 않은 동안(끊김·재협상) 공급자가 사유에 "
                     "적어 준 터널 상대편(엔드포인트) 주소로 ICMP 를 보냅니다"
                     "(ping_count 만큼, 기본 1발). 보낼지는 직전 주기의 상태로 "
                     "정하므로 다시 연결된 직후 첫 주기에도 한 번 나가고, "
                     "공급자마다 한 끊김에 최대 12발까지만 보냅니다. 새 조회 "
                     "이름은 늘지 "
                     "않습니다. SSID·BSSID·MAC 같은 네트워크 식별자는 보내지 않습니다.",
        "enables": ["detect.dns_intercept", "detect.tls_intercept", "detect.public_ip",
                    "vpn.tunnel_probe"],
    },
}

DEFAULTS: Dict[str, Any] = {
    "version": 1,
    # 문구 언어. NETMON_LANG 환경 변수가 이 값을 덮어쓴다.
    # 카탈로그는 netmon/messages/<코드>.py 에 있다.
    "language": "ko",
    "interval": 5,
    "retention_days": 14,
    # 비워 두면 설정 파일 옆의 data/ 를 쓴다
    "log_dir": "",
    # 위치 헬퍼 앱 호출 간격(초). 한 번에 0.5초쯤 걸려서 매 주기 부르지 않는다.
    # 게이트웨이 MAC·DHCP 가 흔들린 직후에는 이 간격과 무관하게 즉시 다시 읽는다.
    "wifi_helper_interval": 60,
    # 주기마다 쏘는 ping 개수. macOS 는 패킷 간격이 1초 고정이라 2 이상이면
    # 한 주기가 그만큼 길어진다.
    "ping_count": 1,
    # 유의미한 신호가 잡히면 조사를 이어 간다. 무엇을 유의미하다고 볼지는
    # investigate.open_on 으로 바꾼다 (netmon/investigate/triggers.py 참조).
    "investigate": {"enabled": True, "max_open": 3, "keep_closed": 20, "open_on": {}},
    "consents": {},
    "features": {
        # VPN 감시는 사람마다 쓰는지조차 다르므로 기본은 꺼짐.
        "vpn.enabled": False,
        "vpn.providers": ["auto"],
        # 끊긴 동안 터널 상대편에 도달하는지 재는 것. 동의(external_probes)가
        # 있어야 하고, 기본은 꺼짐이다 — 공급자가 사유에 적어 준 제3자 주소로
        # 나가기 때문이다.
        "vpn.tunnel_probe": False,
        # 위치 권한이 필요한 탐지. 동의 전에는 켜도 동작하지 않는다.
        "detect.evil_twin": False,
        # 외부 요청이 필요한 탐지.
        "detect.dns_intercept": False,
        "detect.tls_intercept": False,
        "detect.public_ip": False,
        # 기본으로 켜지는 것 — 전부 로컬 관측, sudo 불필요, 외부 요청 없음.
        "detect.l2": True,
        "detect.dhcp": True,
        "detect.dns": True,
        "detect.route": True,
        "detect.wifi": True,
        "detect.quality": True,
        # 2단계 항목은 구현된 뒤에 여기 추가한다. 없는 기능을 켜진 것으로
        # 보고하면 doctor 가 거짓말을 한다.
    },
}

# 기능 → 그 기능이 요구하는 동의
FEATURE_CONSENT = {
    "detect.evil_twin": "location",
    "detect.dns_intercept": "external_probes",
    "detect.tls_intercept": "external_probes",
    "detect.public_ip": "external_probes",
    # 터널 엔드포인트 측정도 밖으로 나가는 요청이다. **기존 동의에 묶는다** —
    # 이미 동의한 사람에게 다시 묻지 않고, 대신 무엇이 나가는지를 위 설명에
    # 적는다 (AC-13). 동의가 있어도 이 기능을 켜지 않으면 아무것도 나가지
    # 않는다(기본 꺼짐).
    "vpn.tunnel_probe": "external_probes",
}


def config_home() -> str:
    env = os.environ.get("NETMON_HOME")
    if env:
        return os.path.expanduser(env)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, APP)


@dataclass
class Config:
    path: str
    data: Dict[str, Any]

    # --- 기능 ---
    def feature(self, name: str) -> bool:
        return bool(self.data.get("features", {}).get(name, DEFAULTS["features"].get(name, False)))

    def set_feature(self, name: str, value: Any) -> None:
        self.data.setdefault("features", {})[name] = value

    def effective(self, name: str) -> bool:
        """켜져 있고, 필요한 동의도 받았는가."""
        if not self.feature(name):
            return False
        need = FEATURE_CONSENT.get(name)
        return self.consented(need) if need else True

    def blocked_reason(self, name: str) -> Optional[str]:
        if not self.feature(name):
            return "꺼져 있음"
        need = FEATURE_CONSENT.get(name)
        if need and not self.consented(need):
            return "동의 필요: %s" % need
        return None

    # --- 동의 ---
    def consented(self, name: Optional[str]) -> bool:
        if not name:
            return True
        rec = self.data.get("consents", {}).get(name)
        return bool(rec and rec.get("granted"))

    def grant(self, name: str, note: str = "") -> None:
        if name not in CONSENTS:
            raise KeyError(name)
        self.data.setdefault("consents", {})[name] = {
            "granted": True, "at": ts_now(), "note": note,
        }

    def revoke(self, name: str) -> None:
        if name not in CONSENTS:
            raise KeyError(name)
        self.data.setdefault("consents", {})[name] = {
            "granted": False, "at": ts_now(), "note": "철회",
        }
        # 그 동의에 딸린 기능도 함께 내린다. 동의를 물린 뒤에도 기능이
        # 켜진 채로 남아 있으면 다음에 동의할 때 조용히 되살아난다.
        for feat, need in FEATURE_CONSENT.items():
            if need == name:
                self.set_feature(feat, False)

    @property
    def language(self) -> str:
        return str(self.data.get("language") or "ko")

    @property
    def interval(self) -> int:
        return int(self.data.get("interval", DEFAULTS["interval"]))

    def save(self) -> None:
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.path)


def load(path: Optional[str] = None) -> Config:
    path = path or os.path.join(config_home(), "config.json")
    data = json.loads(json.dumps(DEFAULTS))  # 깊은 복사
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                on_disk = json.load(fh)
        except (OSError, ValueError):
            on_disk = {}
        for k, v in on_disk.items():
            if isinstance(v, dict) and isinstance(data.get(k), dict):
                data[k].update(v)
            else:
                data[k] = v
    return Config(path=path, data=data)
