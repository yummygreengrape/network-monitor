"""netmon 명령줄.

  netmon doctor              이 기계에서 무엇이 되고 무엇이 안 되는지
  netmon once                한 주기만 측정하고 판정을 출력
  netmon run                 계속 측정 (Ctrl+C 로 종료)
  netmon report [날짜]        하루치 요약
  netmon consent list|grant|revoke <항목>
  netmon capture N [-o 파일]  관측 N주기를 픽스처로 저장
  netmon replay 파일          저장한 관측을 다시 판정 (네트워크 불필요)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import List, Optional

from . import (__version__, config as configmod, redact as redactmod, service,
               setup as setupmod, vpn, wifi_helper)
from .collect import REGISTRY as COLLECTORS
from .engine import Engine, replay as replay_engine
from .model import Observation
from .report import exposure_notes, render
from .store import Store, observations_from
from .util import NEEDS_CONSENT, NEEDS_SUDO, OK, UNSUPPORTED


def default_log_dir() -> str:
    return os.environ.get("NETMON_LOG_DIR") or os.path.join(configmod.config_home(), "data")


def _cfg(args) -> configmod.Config:
    return configmod.load(args.config)


def log_dir_for(args, cfg: configmod.Config) -> str:
    """--log-dir > NETMON_LOG_DIR > 설정 파일 > 기본값."""
    return (args.log_dir
            or os.environ.get("NETMON_LOG_DIR")
            or cfg.data.get("log_dir")
            or os.path.join(os.path.dirname(cfg.path), "data"))


def _store(args, cfg: Optional[configmod.Config] = None) -> Store:
    cfg = cfg or _cfg(args)
    return Store(log_dir_for(args, cfg))


# ---------------------------------------------------------------- doctor
def cmd_doctor(args) -> int:
    cfg = _cfg(args)
    print("netmon %s" % __version__)
    print("설정   %s" % cfg.path)
    print("데이터 %s" % log_dir_for(args, cfg))
    print()

    # 수집기가 무엇을 볼 수 있는지 알려면 먼저 인터페이스를 정해야 한다
    from .collect import iface as iface_mod
    base = iface_mod.collect({})
    ctx = {"primary": base.get("primary"), "primary_kind": base.get("primary_kind"),
           "config_home": os.path.dirname(cfg.path)}
    print("주 인터페이스  %s (%s), 상태 %s" % (
        base.get("primary") or "없음", base.get("primary_kind"), base.get("primary_status")))
    if base.get("tunnel_iface"):
        print("기본 경로가 터널 %s 에 있다. 물리 경로를 따로 찾아서 본다."
              % base["tunnel_iface"])
    print()

    print("수집기")
    for mod in COLLECTORS:
        try:
            cap = mod.probe(ctx) if mod.__name__.endswith("wifi") else mod.probe()
        except Exception as exc:
            print("  %-8s ?        탐침 실패: %s" % (mod.NAME, str(exc)[:50]))
            continue
        mark = {OK: "예", UNSUPPORTED: "해당없음", NEEDS_CONSENT: "동의필요",
                NEEDS_SUDO: "sudo필요"}.get(cap.status, cap.status)
        print("  %-8s %-8s %s" % (cap.name, mark, cap.detail))
        if cap.hint:
            print("           └ %s" % cap.hint)

    print()
    print("VPN 공급자  (감시 %s)" % ("켜짐" if cfg.feature("vpn.enabled") else "꺼짐 — 기본값"))
    for cap in vpn.probe_all():
        mark = "설치됨" if cap.status == OK else "없음"
        print("  %-14s %-8s %s" % (cap.name, mark, cap.detail))

    print()
    print("탐지 기능")
    for name in sorted(k for k in cfg.data.get("features", {}) if k.startswith("detect.")):
        reason = cfg.blocked_reason(name)
        print("  %-24s %s" % (name, "켜짐" if reason is None else "꺼짐 (%s)" % reason))

    print()
    svc = service.describe()
    if svc["installed"]:
        state = "실행 중 (pid %s)" % svc["pid"] if svc["pid"] else (
            "등록됨, 실행 대기" if svc["loaded"] else "등록 파일만 있고 launchd 에 없음")
        print("상시 실행     %s" % state)
        if svc["script_exists"] is False:
            print("              └ 등록된 실행 파일이 없다: %s" % svc["script"])
            print("                저장소를 옮겼다면 netmon.sh service install 로 다시 등록한다")
    else:
        print("상시 실행     등록 안 됨 — netmon.sh service install 로 켠다")

    print()
    home = os.path.dirname(cfg.path)
    if wifi_helper.installed(home):
        print("위치 권한 헬퍼  설치됨, 상태 %s" % wifi_helper.status(home))
    else:
        print("위치 권한 헬퍼  없음 — netmon.sh location setup 으로 만든다")

    print()
    print("동의")
    for name, meta in configmod.CONSENTS.items():
        print("  %-18s %s  — %s" % (name,
                                    "동의함" if cfg.consented(name) else "동의 안 함",
                                    meta["title"]))
    return 0


# ---------------------------------------------------------------- consent
def cmd_consent(args) -> int:
    cfg = _cfg(args)
    if args.action == "list" or not args.item:
        for name, meta in configmod.CONSENTS.items():
            print("%s  [%s]" % (name, "동의함" if cfg.consented(name) else "동의 안 함"))
            print("  무엇      %s" % meta["title"])
            print("  왜        %s" % meta["why"])
            print("  밖으로    %s" % meta["sends_out"])
            print("  켜지는 것 %s" % ", ".join(meta["enables"]))
            print()
        return 0

    if args.item not in configmod.CONSENTS:
        print("알 수 없는 동의 항목: %s" % args.item, file=sys.stderr)
        return 2

    if args.action == "grant":
        meta = configmod.CONSENTS[args.item]
        print("동의 항목: %s" % meta["title"])
        print("  왜     %s" % meta["why"])
        print("  밖으로 %s" % meta["sends_out"])
        cfg.grant(args.item, note=args.note or "")
        if args.enable:
            for feat in meta["enables"]:
                if feat in cfg.data.get("features", {}):
                    cfg.set_feature(feat, True)
        cfg.save()
        print("동의를 기록했다 → %s" % cfg.path)
        if not args.enable:
            print("관련 기능은 아직 꺼져 있다. --enable 을 붙이거나 설정에서 켠다:")
            for feat in meta["enables"]:
                print("    %s" % feat)
    else:
        cfg.revoke(args.item)
        cfg.save()
        print("동의를 철회하고 관련 기능도 껐다 → %s" % cfg.path)
    return 0


# ---------------------------------------------------------------- setup
def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def launcher_path() -> str:
    return os.path.join(repo_root(), "netmon.sh")


def _install_agent(cfg: configmod.Config, log_dir: str, quiet: bool = False) -> int:
    script = launcher_path()
    if not os.path.exists(script):
        print("실행기를 찾을 수 없다: %s" % script, file=sys.stderr)
        return 2
    env = {
        "NETMON_HOME": os.path.dirname(cfg.path),
        "NETMON_LOG_DIR": log_dir,
        # launchd 아래에서는 stdout 이 파이프라 버퍼링된다. 버퍼를 끄지 않으면
        # 로그가 한참 뒤에야 나타나서 "멈춘 것처럼" 보인다.
        "PYTHONUNBUFFERED": "1",
    }
    r = service.install(script, log_dir, env=env, interval=cfg.interval)
    if not r["ok"]:
        print("등록 실패: %s" % r["error"], file=sys.stderr)
        return 2
    if not quiet:
        print("상시 실행으로 등록했다.")
        print("  정의 파일  %s" % r["plist"])
        print("  실행       %s run" % script)
        print("  기록       %s" % log_dir)
        print("  해제       netmon.sh service uninstall")
    return 0


def cmd_setup(args) -> int:
    cfg = _cfg(args)
    home = os.path.dirname(cfg.path)
    default_dir = log_dir_for(args, cfg)

    if args.defaults:
        plan = setupmod.Plan(log_dir=default_dir, confirmed=True)
        plan.interval = cfg.interval
        plan.retention_days = int(cfg.data.get("retention_days", 14))
    else:
        # 파이프로 답을 넣어 자동 설치하는 것도 허용한다. 답이 떨어지면
        # input() 이 EOFError 를 내고 아래에서 취소로 처리된다.
        wiz = setupmod.Wizard(ask=input, say=print, default_log_dir=default_dir)
        try:
            plan = wiz.run()
        except (KeyboardInterrupt, EOFError):
            print("\n취소했다. 아무것도 바꾸지 않았다.")
            return 1

    if not plan.confirmed:
        print("취소했다. 아무것도 바꾸지 않았다.")
        return 1

    todo = setupmod.apply(plan, cfg)
    print()
    print("설정을 저장했다 → %s" % cfg.path)

    if todo["needs_location_request"]:
        print()
        print("위치 권한 헬퍼를 만든다...")
        rc = cmd_location(argparse.Namespace(
            config=args.config, log_dir=args.log_dir, action="setup", timeout=120))
        if rc != 0:
            print("위치 권한을 받지 못했다. 나머지 탐지는 그대로 동작한다.")

    if todo["needs_agent_install"]:
        print()
        rc = _install_agent(cfg, todo["log_dir"])
        if rc != 0:
            return rc

    print()
    print("끝났다. 확인:  netmon.sh doctor")
    if not todo["needs_agent_install"]:
        print("측정 시작:     netmon.sh run")
    return 0


# ---------------------------------------------------------------- service
def cmd_service(args) -> int:
    cfg = _cfg(args)
    log_dir = log_dir_for(args, cfg)

    if args.action == "status":
        d = service.describe()
        print("이름   %s" % d["label"])
        print("정의   %s%s" % (d["plist"], "" if d["installed"] else "  (없음)"))
        if d["script"]:
            print("실행   %s%s" % (d["script"],
                                   "" if d["script_exists"] else "  (파일 없음)"))
        print("상태   %s" % ("실행 중 (pid %s)" % d["pid"] if d["pid"]
                             else "등록됨, 실행 대기" if d["loaded"] else "등록 안 됨"))
        return 0 if d["installed"] else 1

    if args.action == "install":
        print("로그인할 때 자동으로 시작하고, 멈추면 다시 띄운다.")
        print("~/Library/LaunchAgents 에 파일 하나를 만든다. sudo 는 쓰지 않는다.")
        return _install_agent(cfg, log_dir)

    if args.action == "uninstall":
        r = service.uninstall()
        print("해제했다." if r["removed"] else "등록되어 있지 않았다.")
        print("기록은 %s 에 그대로 남아 있다." % log_dir)
        return 0

    if args.action == "restart":
        return 0 if service.restart() else 1
    if args.action == "start":
        return 0 if service.start() else 1
    if args.action == "stop":
        return 0 if service.stop() else 1
    return 2


# ---------------------------------------------------------------- location
def cmd_location(args) -> int:
    cfg = _cfg(args)
    home = os.path.dirname(cfg.path)

    if args.action == "status":
        if not wifi_helper.installed(home):
            print("헬퍼 앱 없음 — netmon.sh location setup")
            return 1
        print("헬퍼 %s" % wifi_helper.app_path(home))
        print("상태 %s" % wifi_helper.status(home))
        return 0

    if args.action == "setup":
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "tools", "location-helper", "build.sh")
        if not os.path.exists(script):
            print("빌드 스크립트를 찾을 수 없다: %s" % script, file=sys.stderr)
            return 2
        print("헬퍼 앱을 만든다 → %s" % home)
        r = subprocess.run(["bash", script, home], capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stderr.strip() or "빌드 실패", file=sys.stderr)
            return 2
        print("만들었다: %s" % r.stdout.strip())
        print()
        print("이어서 권한을 요청한다. 창이 뜨면 허용을 누르세요.")
        args.action = "request"

    if args.action == "request":
        if not wifi_helper.installed(home):
            print("헬퍼 앱 없음 — netmon.sh location setup", file=sys.stderr)
            return 2
        meta = configmod.CONSENTS["location"]
        print("무엇      %s" % meta["title"])
        print("왜        %s" % meta["why"])
        print("밖으로    %s" % meta["sends_out"])
        print()
        st = wifi_helper.request(home, timeout=args.timeout)
        print("결과: %s" % st)
        if st.startswith("authorized"):
            cfg.grant("location", note="헬퍼 앱으로 요청, 결과 %s" % st)
            cfg.set_feature("detect.evil_twin", True)
            cfg.save()
            print("동의를 기록하고 detect.evil_twin 을 켰다 → %s" % cfg.path)
            probe = wifi_helper.wifi(home, force=True)
            if probe and (probe.get("ssid") or probe.get("bssid")):
                print("확인: SSID·BSSID 를 읽을 수 있다.")
            else:
                print("주의: 권한은 받았으나 Wi-Fi 값을 읽지 못했다 "
                      "(유선 연결이거나 Wi-Fi 미접속일 수 있다).")
            return 0
        if st == "denied":
            print("거부됨. 시스템 설정 > 개인정보 보호 및 보안 > 위치 서비스에서 "
                  "'Network Monitor 위치 권한'을 켤 수 있다.")
        return 1

    return 2


# ---------------------------------------------------------------- once / run
def _print_findings(findings, obs: Observation) -> None:
    if not findings:
        print("  판정 없음")
        return
    for f in findings:
        tag = " (억제: %s)" % f.attribution if f.attribution else ""
        print("  [%s/%s/%s] %s%s" % (f.axis, f.confidence, f.severity, f.summary, tag))


def cmd_once(args) -> int:
    cfg = _cfg(args)
    store = _store(args, cfg)
    eng = Engine(cfg, store)
    obs, findings = eng.cycle()
    if not args.no_write:
        eng.persist(obs, findings)
    print("%s  네트워크 %s" % (obs.ts, eng.state.get("network")))
    if obs.errors:
        for name, err in obs.errors.items():
            print("  수집 실패 %s: %s" % (name, err))
    _print_findings(findings, obs)
    if args.json:
        print(json.dumps(obs.as_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_run(args) -> int:
    cfg = _cfg(args)
    store = _store(args, cfg)
    interval = args.interval or cfg.interval
    eng = Engine(cfg, store)
    store.prune(int(cfg.data.get("retention_days", 14)))
    print("측정 시작 — 간격 %ds, 기록 %s  (Ctrl+C 로 종료)" % (interval, store.dir))
    n = 0
    last_prune_day = time.strftime("%Y-%m-%d")
    try:
        while True:
            start = time.time()
            day = time.strftime("%Y-%m-%d")
            if day != last_prune_day:
                store.prune(int(cfg.data.get("retention_days", 14)))
                last_prune_day = day
            obs, findings = eng.cycle(start)
            eng.persist(obs, findings)
            n += 1
            for f in findings:
                if f.attribution and not args.verbose:
                    continue
                tag = " (억제: %s)" % f.attribution if f.attribution else ""
                print("%s  [%s/%s] %s%s" % (obs.ts[11:19], f.axis, f.severity, f.summary, tag))
            if args.count and n >= args.count:
                break
            time.sleep(max(0.0, interval - (time.time() - start)))
    except KeyboardInterrupt:
        print()
    print("%d주기 기록함 → %s" % (n, store.dir))
    return 0


# ---------------------------------------------------------------- report
def cmd_report(args) -> int:
    store = _store(args)
    day = args.day or time.strftime("%Y-%m-%d")
    events = list(store.events(day))
    samples = list(store.samples(day))
    if not events and not samples:
        print("%s 기록 없음 (%s)" % (day, store.dir))
        return 1

    if args.redact:
        salt = redactmod.load_or_create_salt(os.path.join(configmod.config_home(), "salt"))
        events = [redactmod.redact(e, salt) for e in events]
        samples = [redactmod.redact(s, salt) for s in samples]

    print(render(day, events, len(samples), exposure_notes(samples[-1] if samples else None)))
    if args.redact:
        print()
        print("-- 식별자를 가린 출력이다. %s --" % redactmod.describe())
    return 0


# ---------------------------------------------------------------- capture / replay
def cmd_capture(args) -> int:
    cfg = _cfg(args)
    out_path = args.out or os.path.join(default_log_dir(), "capture-%d.jsonl" % int(time.time()))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    eng = Engine(cfg, Store(args.log_dir or default_log_dir()))
    salt = None
    if args.redact:
        salt = redactmod.load_or_create_salt(os.path.join(configmod.config_home(), "salt"))

    print("관측 %d주기를 %s 로 뜬다 (간격 %ds)%s"
          % (args.count, out_path, args.interval or cfg.interval,
             ", 식별자 가림" if salt else ""))
    with open(out_path, "w", encoding="utf-8") as fh:
        for i in range(args.count):
            start = time.time()
            obs, _ = eng.cycle(start)
            d = obs.as_dict()
            if salt:
                d = redactmod.redact(d, salt)
            fh.write(json.dumps(d, ensure_ascii=False, sort_keys=True) + "\n")
            fh.flush()
            print("  %d/%d" % (i + 1, args.count), end="\r", flush=True)
            if i + 1 < args.count:
                time.sleep(max(0.0, (args.interval or cfg.interval) - (time.time() - start)))
    print("\n저장함 → %s" % out_path)
    return 0


def cmd_replay(args) -> int:
    cfg = _cfg(args)
    obs_list = observations_from(args.path)
    print("%d주기 재생 — %s" % (len(obs_list), args.path))
    total = 0
    for obs, findings in replay_engine(cfg, obs_list):
        for f in findings:
            if f.attribution and not args.verbose:
                continue
            total += 1
            tag = " (억제: %s)" % f.attribution if f.attribution else ""
            print("  %s [%s/%s/%s] %s%s" % (obs.ts[11:19], f.axis, f.confidence,
                                            f.severity, f.summary, tag))
    print("판정 %d건" % total)
    return 0


# ---------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netmon", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", help="설정 파일 경로")
    p.add_argument("--log-dir", help="기록 디렉터리")
    p.add_argument("--version", action="version", version="netmon %s" % __version__)
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("doctor", help="이 기계에서 무엇이 되는지 점검").set_defaults(func=cmd_doctor)

    c = sub.add_parser("consent", help="권한 동의 관리")
    c.add_argument("action", choices=["list", "grant", "revoke"])
    c.add_argument("item", nargs="?")
    c.add_argument("--enable", action="store_true", help="동의와 함께 관련 기능도 켠다")
    c.add_argument("--note", help="기록에 남길 메모")
    c.set_defaults(func=cmd_consent)

    st = sub.add_parser("setup", help="처음 켤 때의 설정 마법사")
    st.add_argument("--defaults", action="store_true",
                    help="묻지 않고 기본값으로 설정 (모든 선택 기능은 꺼짐)")
    st.set_defaults(func=cmd_setup)

    sv = sub.add_parser("service", help="상시 실행 등록 관리")
    sv.add_argument("action",
                    choices=["install", "uninstall", "status", "start", "stop", "restart"])
    sv.set_defaults(func=cmd_service)

    lo = sub.add_parser("location", help="위치 권한 헬퍼 (evil twin 탐지용)")
    lo.add_argument("action", choices=["setup", "request", "status"])
    lo.add_argument("--timeout", type=int, default=120, help="권한 응답 대기 초")
    lo.set_defaults(func=cmd_location)

    o = sub.add_parser("once", help="한 주기만 측정")
    o.add_argument("--json", action="store_true", help="관측 원본도 출력")
    o.add_argument("--no-write", action="store_true", help="기록하지 않는다")
    o.set_defaults(func=cmd_once)

    r = sub.add_parser("run", help="계속 측정")
    r.add_argument("--interval", type=int)
    r.add_argument("--count", type=int, help="이 횟수만큼만 측정하고 종료")
    r.add_argument("-v", "--verbose", action="store_true", help="억제된 판정도 출력")
    r.set_defaults(func=cmd_run)

    rp = sub.add_parser("report", help="하루치 요약")
    rp.add_argument("day", nargs="?", help="YYYY-MM-DD (기본: 오늘)")
    rp.add_argument("--redact", action="store_true", help="식별자를 가려서 출력")
    rp.set_defaults(func=cmd_report)

    cp = sub.add_parser("capture", help="관측을 픽스처로 저장")
    cp.add_argument("count", type=int)
    cp.add_argument("-o", "--out", help="저장 경로")
    cp.add_argument("--interval", type=int)
    cp.add_argument("--redact", action="store_true", help="식별자를 가려서 저장")
    cp.set_defaults(func=cmd_capture)

    rep = sub.add_parser("replay", help="저장한 관측을 다시 판정")
    rep.add_argument("path")
    rep.add_argument("-v", "--verbose", action="store_true")
    rep.set_defaults(func=cmd_replay)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "func", None):
        return args.func(args)

    # 인자 없이 켰다. 설정이 아직 없으면 마법사를 권한다.
    cfg = _cfg(args)
    if not os.path.exists(cfg.path):
        print("netmon %s — 처음 실행입니다." % __version__)
        print()
        if sys.stdin.isatty():
            ans = input("설정 마법사를 시작할까요? (Y/n): ").strip().lower()
            if ans in ("", "y", "yes", "예", "ㅇ"):
                args.defaults = False
                return cmd_setup(args)
        print("설정: netmon.sh setup     점검: netmon.sh doctor")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
