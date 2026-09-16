"""설정 마법사와 상시 실행 등록.

마법사는 답만 모으고 아무것도 바꾸지 않는다. 그래서 시스템을 건드리지 않고
질문 순서와 기본값을 그대로 검증할 수 있다.
"""
from __future__ import annotations

import os
import plistlib
import tempfile
import unittest

from netmon import config as configmod
from netmon import messages as msg
from netmon import messages
from netmon import service, setup as setupmod


class ScriptedIO:
    """미리 정한 답을 순서대로 돌려준다. 답이 떨어지면 엔터(기본값)로 친다."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.said = []
        self.asked = []

    def ask(self, prompt):
        self.asked.append(prompt)
        return self.answers.pop(0) if self.answers else ""

    def say(self, line):
        self.said.append(line)

    @property
    def transcript(self):
        return "\n".join(self.said)


def wizard(answers, vpn_installed=("warp",), language=""):
    """답을 순서대로 넣고 마법사를 돌린다.

    첫 질문은 언어다. 기본값(엔터)이면 지금 언어가 그대로 유지된다.
    언어는 전역 상태이므로 시작 전에 한국어로 맞춰 둔다.
    """
    messages.set_language("ko")
    io = ScriptedIO([language] + list(answers))
    w = setupmod.Wizard(ask=io.ask, say=io.say, default_log_dir="/tmp/netmon-test",
                        installed_vpn=list(vpn_installed))
    try:
        return w.run(), io
    finally:
        messages.set_language("ko")


class TestWizardDefaults(unittest.TestCase):
    def test_all_enter_gives_least_privilege(self):
        """엔터만 누르면 선택 기능이 하나도 켜지지 않아야 한다."""
        plan, _ = wizard([])
        self.assertEqual(plan.interval, 5)
        self.assertEqual(plan.retention_days, 14)
        self.assertFalse(plan.want_location)
        self.assertFalse(plan.want_vpn)
        self.assertFalse(plan.want_external)
        self.assertFalse(plan.want_agent, "상시 실행은 명시적으로 골라야 켜진다")
        self.assertTrue(plan.confirmed, "마지막 확인의 기본값은 적용")

    def test_choices_are_applied_in_order(self):
        # 언어 기본, 간격 3초, 기록 기본, 보존 30일, 위치 y, VPN y, 외부 n,
        # 상시 y, 링크 y, 확인 y
        plan, _ = wizard(["1", "", "3", "y", "y", "n", "y", "y", "y"])
        self.assertEqual(plan.interval, 3)
        self.assertEqual(plan.retention_days, 30)
        self.assertTrue(plan.want_location)
        self.assertTrue(plan.want_vpn)
        self.assertFalse(plan.want_external)
        self.assertTrue(plan.want_agent)
        self.assertTrue(plan.want_link)

    def test_invalid_choice_is_reasked(self):
        plan, io = wizard(["99", "abc", "1"])
        self.assertEqual(plan.interval, 3)
        self.assertIn(msg.WZ_PICK_RANGE % 4, io.transcript)

    def test_declining_at_the_end_leaves_plan_unconfirmed(self):
        # 위치·VPN·외부·상시·링크에 모두 n, 마지막 확인에도 n
        plan, _ = wizard(["", "", "", "n", "n", "n", "n", "n", "n"])
        self.assertFalse(plan.confirmed)

    def test_command_registration_is_offered_and_defaults_on(self):
        """`./netmon.sh` 는 저장소 안에서만 통한다. 기본값은 링크를 거는 쪽이다."""
        plan, io = wizard([])
        self.assertTrue(plan.want_link)
        self.assertIn(msg.WZ_LINK_Q, io.transcript + " ".join(io.asked))
        self.assertIn("netmon link remove", io.transcript)

    def test_command_registration_can_be_declined(self):
        plan, _ = wizard(["", "", "", "n", "n", "n", "n", "n"])
        self.assertFalse(plan.want_link)

    def test_vpn_question_skipped_when_none_installed(self):
        plan, io = wizard([], vpn_installed=())
        self.assertFalse(plan.want_vpn)
        self.assertIn(msg.WZ_VPN_NONE, io.transcript)

    def test_external_probe_question_states_what_leaves_the_machine(self):
        _, io = wizard([])
        for line in msg.WZ_EXTERNAL_BODY.splitlines():
            self.assertIn(line, io.transcript)


class TestLanguageQuestion(unittest.TestCase):
    def tearDown(self):
        messages.set_language("ko")

    def test_language_is_asked_first_in_both_languages(self):
        _, io = wizard([])
        self.assertIn(msg.WZ_LANG_Q, io.transcript)
        self.assertIn("English", io.transcript)
        self.assertIn("한국어", io.transcript)

    def test_choosing_english_switches_the_rest_of_the_wizard(self):
        codes = messages.available()
        plan, io = wizard([], language=str(codes.index("en") + 1))
        self.assertEqual(plan.language, "en")
        self.assertIn("netmon first-run setup", io.transcript)

    def test_language_is_saved_to_config(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            cfg = configmod.load(os.path.join(d, "config.json"))
            setupmod.apply(setupmod.Plan(language="en", log_dir=d, confirmed=True), cfg)
            self.assertEqual(configmod.load(os.path.join(d, "config.json")).language, "en")


class TestApply(unittest.TestCase):
    def _cfg(self, d):
        return configmod.load(os.path.join(d, "config.json"))

    def test_apply_writes_config_without_touching_the_system(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            plan = setupmod.Plan(interval=10, retention_days=30,
                                 log_dir=os.path.join(d, "data"),
                                 want_vpn=True, confirmed=True)
            todo = setupmod.apply(plan, cfg)
            again = self._cfg(d)
            self.assertEqual(again.interval, 10)
            self.assertEqual(again.data["retention_days"], 30)
            self.assertTrue(again.feature("vpn.enabled"))
            self.assertFalse(todo["needs_agent_install"])
            self.assertFalse(todo["needs_location_request"])

    def test_declining_external_revokes_previous_consent(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            cfg.grant("external_probes")
            cfg.set_feature("detect.public_ip", True)
            setupmod.apply(setupmod.Plan(log_dir=d, want_external=False, confirmed=True), cfg)
            again = self._cfg(d)
            self.assertFalse(again.consented("external_probes"))
            self.assertFalse(again.feature("detect.public_ip"))

    def test_accepting_external_enables_its_features(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            setupmod.apply(setupmod.Plan(log_dir=d, want_external=True, confirmed=True), cfg)
            again = self._cfg(d)
            self.assertTrue(again.consented("external_probes"))
            self.assertTrue(again.effective("detect.dns_intercept"))


class TestLaunchAgentPlist(unittest.TestCase):
    def test_plist_is_valid_and_has_what_launchd_needs(self):
        d = service.plist_dict("/opt/netmon/netmon.sh", "/var/tmp/netmon",
                               env={"NETMON_HOME": "/opt/cfg"}, interval=5)
        parsed = plistlib.loads(service.render(d))
        self.assertEqual(parsed["Label"], service.LABEL)
        self.assertEqual(parsed["ProgramArguments"][:3],
                         ["/bin/bash", "/opt/netmon/netmon.sh", "run"])
        self.assertIn("--interval", parsed["ProgramArguments"])
        self.assertTrue(parsed["RunAtLoad"])
        self.assertTrue(parsed["KeepAlive"])
        self.assertEqual(parsed["ProcessType"], "Background")
        self.assertEqual(parsed["EnvironmentVariables"]["NETMON_HOME"], "/opt/cfg")

    def test_paths_with_awkward_characters_survive(self):
        """plist 를 문자열로 짜면 이런 경로에서 깨진다."""
        odd = "/opt/a b/설정 & 기록/netmon.sh"  # 홈 경로는 누출 검사가 막는다
        d = service.plist_dict(odd, "/tmp/x")
        parsed = plistlib.loads(service.render(d))
        self.assertEqual(parsed["ProgramArguments"][1], odd)

    def test_no_interval_means_no_flag(self):
        d = service.plist_dict("/x/netmon.sh", "/tmp/x")
        self.assertNotIn("--interval", d["ProgramArguments"])


if __name__ == "__main__":
    unittest.main()
