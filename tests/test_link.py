"""어디서나 netmon 으로 실행되게 하는 링크.

`./netmon.sh` 는 저장소 안에서만 통한다. 다른 곳에서 치면 셸이
`no such file or directory` 를 내는데, 이 단계에서는 우리 코드가 아직 돌지
않아 안내를 띄울 수도 없다. 그래서 링크가 필요하다.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from netmon import link


class TestChooseDir(unittest.TestCase):
    def test_prefers_a_writable_dir_already_on_path(self):
        d, why = link.choose_dir(
            candidates=("/a", "/b"), path_value="/x:/b",
            is_writable=lambda p: p in ("/a", "/b"), exists=lambda p: True)
        self.assertEqual(d, "/b")
        self.assertIn("PATH", why)

    def test_falls_back_to_writable_but_not_on_path(self):
        d, why = link.choose_dir(
            candidates=("/a",), path_value="/x",
            is_writable=lambda p: p == "/a", exists=lambda p: True)
        self.assertEqual(d, "/a")
        self.assertIn("PATH 에는 없는", why)

    def test_can_propose_creating_a_dir(self):
        d, why = link.choose_dir(
            candidates=("/parent/child",), path_value="",
            is_writable=lambda p: p == "/parent",
            exists=lambda p: p == "/parent")
        self.assertEqual(d, "/parent/child")
        self.assertIn("만들어야", why)

    def test_reports_failure_instead_of_guessing(self):
        d, _ = link.choose_dir(candidates=("/a",), path_value="",
                               is_writable=lambda p: False, exists=lambda p: False)
        self.assertIsNone(d)

    def test_duplicate_path_entries_are_collapsed(self):
        """PATH 에 같은 곳이 두 번 있으면 링크도 두 번 찾은 것처럼 보인다."""
        self.assertEqual(link.path_dirs("/usr/bin:/usr/bin:/bin"), ["/usr/bin", "/bin"])


class TestInstall(unittest.TestCase):
    def _launcher(self, d):
        p = os.path.join(d, "netmon.sh")
        with open(p, "w") as fh:
            fh.write("#!/bin/bash\n")
        os.chmod(p, 0o755)
        return p

    def test_creates_a_symlink_to_the_launcher(self):
        with tempfile.TemporaryDirectory() as d:
            launcher = self._launcher(d)
            target = os.path.join(d, "bin")
            r = link.install(launcher, target)
            self.assertTrue(r["ok"], r.get("error"))
            self.assertTrue(os.path.islink(r["path"]))
            self.assertEqual(os.path.realpath(r["path"]), os.path.realpath(launcher))

    def test_replaces_an_existing_link(self):
        with tempfile.TemporaryDirectory() as d:
            launcher = self._launcher(d)
            target = os.path.join(d, "bin")
            link.install(launcher, target)
            r = link.install(launcher, target)
            self.assertTrue(r["ok"])

    def test_refuses_to_clobber_a_real_file(self):
        """링크가 아닌 파일이 있으면 건드리지 않는다. 남의 netmon 일 수 있다."""
        with tempfile.TemporaryDirectory() as d:
            launcher = self._launcher(d)
            target = os.path.join(d, "bin")
            os.makedirs(target)
            with open(os.path.join(target, "netmon"), "w") as fh:
                fh.write("다른 프로그램")
            r = link.install(launcher, target)
            self.assertFalse(r["ok"])
            self.assertIn("링크가 아닌 파일", r["error"])

    def test_missing_launcher_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            r = link.install(os.path.join(d, "없는파일.sh"), d)
            self.assertFalse(r["ok"])

    def test_path_hint_matches_the_shell(self):
        self.assertIn(".zshrc", link.path_hint("/opt/x", shell="zsh"))
        self.assertIn(".bash_profile", link.path_hint("/opt/x", shell="bash"))
        self.assertIn("/opt/x", link.path_hint("/opt/x", shell="zsh"))


if __name__ == "__main__":
    unittest.main()
