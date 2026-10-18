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


def verdict(shown):
    red = sum(1 for f in shown if f.status is Status.RED)
    yellow = sum(1 for f in shown if f.status is Status.YELLOW)
    if red:
        return ("有 %d 项建议尽快处理，另有 %d 项留意一下。"
                "先做最上面那一项，做完再重新体检一次。" % (red, yellow))
    if yellow:
        return ("没有发现必须马上处理的问题，但有 %d 项值得留意。"
                "不急着动手，先按建议观察几天。" % yellow)
    gray = sum(1 for f in shown if f.status is Status.GRAY)
    if gray:
        return ("已检查的 %d 项都正常，另有 %d 项这台机器上看不到，"
                "看不到不等于有问题。" % (red + yellow + sum(
                    1 for f in shown if f.status is Status.GREEN), gray))
    return "所有检查项都正常，没有发现问题。"


def build_meta(ctx, findings, san, elapsed_ms, extra=None):
    shown = [f for f in findings if not f.skip]
    from .. import probes as _p
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
        "verdict": verdict(shown),
        "probe_count": len(_p.PROBES),
        "elapsed_text": "%.1f 秒" % (elapsed_ms / 1000.0),
        "counts": {s: sum(1 for f in shown if f.status is s) for s in Status},
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
