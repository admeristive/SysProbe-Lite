"""One scan, shared by the GUI and the headless selftest.

A probe that raises becomes a gray "未获取" row instead of an empty list: a
silent gap in the dashboard reads as "checked and clean", which is the one
wrong answer this tool must never give.
"""

import tempfile
import time
import types

from . import paths, probes, rules
from .model import failed


def build_ctx(root=None):
    # app_root(), not __file__: frozen, __file__ points inside _internal, and a
    # ctx rooted there makes the packaged build look for 故障规则库.json next to
    # the dlls instead of next to the exe - so the user's edits would be
    # silently ignored and the built-in defaults used instead.
    root = root or paths.app_root()
    return types.SimpleNamespace(
        root=root,
        temp_dir=tempfile.gettempdir(),
        rules=rules.load(root),
        win11=probes.win11(),
        app_codes=set(),
        started=time.time(),
    )


def run(ctx, hook=None):
    """hook(title, index, total) is called before each probe starts."""
    findings = []
    total = len(probes.PROBES)
    for index, (pid, title, fn, _needs_admin) in enumerate(probes.PROBES):
        if hook:
            try:
                hook(title, index, total)
            except Exception:
                pass
        try:
            got = fn(ctx)
        except Exception:
            got = [failed(pid, "这一项没有取到数据")]
            if not got[0].plain:
                got[0].plain = "其他检查项不受影响，可以照常看结果。"
        findings.extend(got or [failed(pid, "这一项没有取到数据")])
    if hook:
        try:
            hook("完成", total, total)
        except Exception:
            pass
    return findings
