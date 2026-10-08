"""Headless harness: run every probe, print timings, prove the sanitizer holds.

This exists because a GUI cannot be reviewed on hardware you do not own. Use:
    py -3 selftest.py            # probes + sanitizer regression, no GUI, no writes
"""

import os
import sys
import time
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from sysprobe import evtlog, native, probes, rules  # noqa: E402
from sysprobe.model import Status  # noqa: E402
from sysprobe.sanitizer import Sanitizer  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
MARK = {Status.RED: "[需处理]", Status.YELLOW: "[留意] ", Status.GREEN: "[正常] ",
        Status.GRAY: "[未取] "}


def build_ctx():
    return types.SimpleNamespace(
        root=ROOT,
        temp_dir=tempfile.gettempdir(),
        rules=rules.load(ROOT),
        win11=probes.win11(),
        app_codes=set(),
        started=time.time(),
    )


def run_probes(ctx):
    total = []
    print("== 探针耗时（非管理员，本机实测）==")
    for pid, title, fn, needs_admin in probes.PROBES:
        t0 = time.perf_counter()
        try:
            got = fn(ctx)
            err = ""
        except Exception as exc:
            got, err = [], "%s: %s" % (type(exc).__name__, exc)
        ms = (time.perf_counter() - t0) * 1000
        total.extend(got)
        flag = "ADMIN" if needs_admin else "     "
        print("  %-9s %-12s %6.0f ms  findings=%d %s%s"
              % (pid, flag, ms, len(got), "", err if err else ""))
        if err:
            print("     ^^ 探针抛异常，应当被上层兜住并降级为『未获取』")
    return total


def show(findings, san):
    print("\n== 结论（已过脱敏闸）==")
    order = [Status.RED, Status.YELLOW, Status.GREEN, Status.GRAY]
    for f in sorted(findings, key=lambda x: order.index(x.status)):
        if f.skip:
            continue
        print("%s %s" % (MARK[f.status], san.text(f.headline)))
        if f.plain:
            print("        %s" % san.text(f.plain)[:120])
        if f.native:
            print("        native=%s" % str(san.deep(f.native))[:160])
    skipped = [f for f in findings if f.skip]
    print("\n== 折叠项（skip，只进报告不进看板）%d 条 ==" % len(skipped))
    for f in skipped:
        print("   %s" % san.text(f.headline))


def encoding_check():
    """wevtutil writes the OEM codepage; prove Chinese survives the round trip."""
    print("\n== wevtutil 输出编码实测 ==")
    san = Sanitizer()
    rows = evtlog.query("System", evtlog.build("EventID=7036", days=3), max_records=3)
    for row in rows[:3]:
        computer = row["computer"]
        masked = san.text("on " + computer)
        print("   provider=%s 原样含中文=%s 脱敏后变化=%s"
              % (row["provider"],
                 any("\u4e00" <= c <= "\u9fff" for c in computer),
                 computer.lower() not in masked.lower()))
    if rows and ("\ufffd" in rows[0]["computer"]):
        print("   !! 解码失败：需要调整 native._decode 的编码顺序")


def live_identity_check(findings):
    """The only regression that matters: this machine's own names must not survive."""
    print("\n== 本机身份实跑校验 ==")
    san = Sanitizer()
    live = [v for v, _ in san._live]
    parts = []
    for f in findings:
        parts.extend([f.headline, f.plain, f.why, f.copy_cmd])
        parts.extend(f.steps)
        parts.append(str(san.deep(f.native)))
    blob = " \n ".join(san.text(p) for p in parts if p)
    leaked = [len(v) for v in live if v.lower() in blob.lower()]
    print("   参与校验的本机身份值: %d 只（最短 %s 字）"
          % (len(live), min([len(v) for v in live], default="-")))
    print("   实跑结论里残留的本机身份: %s" % ("有，长度=%s" % leaked if leaked else "无"))
    return not leaked


LEAK_CORPUS = [
    "C:\\Users\\zhangsan\\AppData\\Roaming\\foo\\bar.exe",
    "S-1-5-21-1234567890-1234567890-1234567890-1001",
    "192.168.10.23:7897",
    "00-1A-2B-3C-4D-5E",
    "ProxyServer=http://alice:SuperSecret1@10.0.0.9:7890",
    "dGhpcyBpcyBBIFRoaXMgaXMgVGhlVG9rZW4xMjM0",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abcDEF123",
    "fe80::1234:5678:9abc:def0%12",
    "token: hunter2secret",
]

MUST_SURVIVE = [
    # evidence the report needs; a lazy sanitizer eats these
    "0xc0000005",
    "{12345678-1234-1234-1234-123456789abc}",
    "224.0.0.0",
    "127.0.0.1",
]


def sanitizer_check():
    print("\n== 脱敏闸回归 ==")
    san = Sanitizer(seed_extra=("zhangsan", "alice", "SuperSecret1", "hunter2secret"))
    for line in LEAK_CORPUS:
        out = san.text(line)
        print("   IN : %s" % line)
        print("   OUT: %s" % out)
    joined = " \n ".join(san.text(x) for x in LEAK_CORPUS)
    banned = ["zhangsan", "alice", "SuperSecret1", "hunter2secret", "1234567890",
              "192.168.10.23", "00-1A-2B-3C-4D-5E",
              "dGhpcyBpcyBBIFRoaXMgaXMgVGhlVG9rZW4xMjM0"]
    leaked = [b for b in banned if b.lower() in joined.lower()]
    print("   泄露项: %s" % (leaked or "无"))
    keep_ok = []
    for token in MUST_SURVIVE:
        if token in san.text("异常代码 %s 位于 %s 网卡 224.0.0.0 与 127.0.0.1" % (token, token)):
            keep_ok.append(token)
    print("   证据保留: %s / %s" % (len(keep_ok), len(MUST_SURVIVE)))
    print("   %s" % san.summary())
    return not leaked


def main():
    ctx = build_ctx()
    print("SysProbe-Lite selftest  |  python %s  |  %s  |  win11=%s"
          % (sys.version.split()[0], probes.os_label(), ctx.win11))
    if ctx.rules.load_error:
        print("规则库回退内置：%s" % ctx.rules.load_error)
    print("规则库版本 %s（%s 校订）" % (ctx.rules.version, ctx.rules.reviewed))
    ps = native.power_status()
    print("电池断言: %r" % (ps,))

    findings = run_probes(ctx)
    san = Sanitizer()
    encoding_check()
    show(findings, san)
    ok = sanitizer_check() and live_identity_check(findings)
    print("\n合计 %d 条结论，脱敏 %d 处，回归%s"
          % (len(findings), sum(san.stats.values()), "通过" if ok else "失败"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
