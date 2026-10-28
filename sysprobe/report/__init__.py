"""Report package: sanitize, build the shared meta, write both files.

The GUI and the headless selftest go through here so that what a person sees
on screen and what lands in the file cannot drift apart.
"""

import os
import time

from ..model import Status
from .. import paths
from . import html as html_mod
from . import plain as plain_mod

TOOL_VERSION = "1.1.0"


def sanitize_findings(findings, san):
    """Return copies whose every human-visible field has passed the gate."""
    clean = []
    for f in findings:
        g = san.deep(f.to_dict())
        clean.append(type(f).from_dict(g))
    return clean


def verdict(items):
    """One line over every conclusion, suppressed rows included.

    Callers must not pass only the visible cards: with a feed of cards only, the
    gray branch below can never fire and the line reads "所有检查项都正常" while
    four readings were never obtained.
    """
    red = sum(1 for f in items if f.status is Status.RED)
    yellow = sum(1 for f in items if f.status is Status.YELLOW)
    if red:
        return ("有 %d 项建议尽快处理，另有 %d 项留意一下。"
                "先做最上面那一项，做完再重新体检一次。" % (red, yellow))
    if yellow:
        return ("没有发现必须马上处理的问题，但有 %d 项值得留意。"
                "不急着动手，先按建议观察几天。" % yellow)
    gray = sum(1 for f in items if f.status is Status.GRAY)
    if gray:
        return ("已检查的 %d 项都正常，另有 %d 项这台机器上看不到，"
                "看不到不等于有问题。" % (red + yellow + sum(
                    1 for f in items if f.status is Status.GREEN), gray))
    return "所有检查项都正常，没有发现问题。"


def build_meta(ctx, findings, san, elapsed_ms, extra=None):
    from .. import probes as _p
    from .. import quicklook as _ql
    admin = paths.running_as_admin()
    meta = {
        "title": "系统简易体检仪 · 体检报告",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "os_label": _p.os_label(),
        "admin_text": "管理员（能看到全部检查项）" if admin
                      else "普通用户（有 %d 项看不全，属正常）" % sum(
                          1 for f in findings if f.needs_admin),
        "san_summary": san.summary(),
        "tool_version": TOOL_VERSION,
        "rules_version": ctx.rules.version,
        "rules_reviewed": ctx.rules.reviewed,
        "rules_error": ctx.rules.load_error,
        "verdict": verdict(findings),
        "probe_count": len(_p.PROBES),
        # Taken here instead of handed in by the caller: the window and the
        # no-screen run both build meta through this one place, so a report can
        # never be written without the line, and the numbers are as fresh as
        # the rest of the report.
        "quicklook_line": _ql.glance() or "",
        "elapsed_text": "%.1f 秒" % (elapsed_ms / 1000.0),
        "counts": {s: sum(1 for f in findings if f.status is s) for s in Status},
    }
    meta.update(extra or {})
    return meta


def write(findings, meta, want_html=True, want_plain=True):
    """Write the two report files. Returns the paths actually written."""
    directory, in_place = paths.report_dir()
    meta = dict(meta)
    meta["in_place"] = in_place
    stamp = time.strftime("%Y%m%d-%H%M%S")
    written = {}
    if want_html:
        name = "体检报告-%s.html" % stamp
        target = os.path.join(directory, name)
        meta["report_path"] = target
        _write_bytes(target, html_mod.render(findings, meta))
        written["html"] = target
    if want_plain:
        name2 = "体检结果-%s.txt" % stamp
        target2 = os.path.join(directory, name2)
        meta["report_path"] = target2
        _write_bytes(target2, plain_mod.render(findings, meta))
        written["plain"] = target2
    meta["report_path"] = written.get("html", written.get("plain", ""))
    written["dir"] = directory
    written["in_place"] = in_place
    return written


def _write_bytes(path, text):
    # BOM: the report is opened by Notepad and by Windows Defender's report
    # viewer alike, and both guess wrong on a bare UTF-8 Chinese file.
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        handle.write(text)
