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
import sys
import time
from typing import List, Optional

from . import __version__, config as configmod, redact as redactmod, vpn
from .collect import REGISTRY as COLLECTORS
from .engine import Engine, replay as replay_engine
from .model import Observation
from .report import exposure_notes, render
from .store import Store, observations_from
from .util import NEEDS_CONSENT, NEEDS_SUDO, OK, UNSUPPORTED


def default_log_dir() -> str:
    return os.environ.get("NETMON_LOG_DIR") or os.path.join(configmod.config_home(), "data")


def _store(args) -> Store:
    return Store(args.log_dir or default_log_dir())


def _cfg(args) -> configmod.Config:
    return configmod.load(args.config)


# ---------------------------------------------------------------- doctor
def cmd_doctor(args) -> int:
    cfg = _cfg(args)
    print("netmon %s" % __version__)
    print("설정   %s" % cfg.path)
    print("데이터 %s" % (args.log_dir or default_log_dir()))
    print()

    # 수집기가 무엇을 볼 수 있는지 알려면 먼저 인터페이스를 정해야 한다
    from .collect import iface as iface_mod
    base = iface_mod.collect({})
    ctx = {"primary": base.get("primary"), "primary_kind": base.get("primary_kind")}
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


# ---------------------------------------------------------------- once / run
def _print_findings(findings, obs: Observation) -> None:
    if not findings:
        print("  판정 없음")
        return
    for f in findings:
        tag = " (억제: %s)" % f.attribution if f.attribution else ""
        print("  [%s/%s/%s] %s%s" % (f.axis, f.confidence, f.severity, f.summary, tag))


def cmd_once(args) -> int:
    cfg, store = _cfg(args), _store(args)
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
    cfg, store = _cfg(args), _store(args)
    interval = args.interval or cfg.interval
    eng = Engine(cfg, store)
    store.prune(int(cfg.data.get("retention_days", 14)))
    print("측정 시작 — 간격 %ds, 기록 %s  (Ctrl+C 로 종료)" % (interval, store.dir))
    n = 0
    try:
        while True:
            start = time.time()
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
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
