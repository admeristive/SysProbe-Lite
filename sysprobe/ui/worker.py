"""Scan thread.

Every probe runs off the UI thread: the slowest one takes a few hundred
milliseconds on a healthy machine and several seconds on a machine that is
actually in trouble, which is exactly when a frozen window is most alarming.
An exception here must never reach Qt's default handler - it is logged and
turned into a gray row.
"""

import time
import traceback

from PySide6.QtCore import QThread, Signal

from .. import paths, scan
from ..sanitizer import Sanitizer


class ScanWorker(QThread):
    progress = Signal(str, int, int)
    done = Signal(object, object, object, float)
    broken = Signal(str)

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self._ctx = ctx

    def run(self):
        san = Sanitizer()
        started = time.perf_counter()
        try:
            findings = scan.run(self._ctx, hook=self._hook)
            elapsed = (time.perf_counter() - started) * 1000.0
            clean = [san.deep(f.to_dict()) for f in findings]
            self.done.emit(clean, san, elapsed, len(findings))
        except Exception as exc:
            _log(exc, traceback.format_exc())
            self.broken.emit("%s：%s" % (type(exc).__name__, exc))

    def _hook(self, title, index, total):
        self.progress.emit(title, index + 1, total)


def _log(exc, text):
    try:
        target = paths.crash_log_path()
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("\n[worker] %s\n%s\n" % (exc, text))
    except OSError:
        pass
