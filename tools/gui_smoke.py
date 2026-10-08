"""GUI smoke test that never opens a visible window.

Offscreen Qt proves the wiring a user actually depends on: the thread starts,
signals land, the board renders, the report button writes files, the copy
button produces text. It also machine-checks the product rule that raw
Windows vocabulary must stay out of the window.

Run:  py -3 tools/gui_smoke.py
"""

import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402
from sysprobe import probes, scan  # noqa: E402
from sysprobe.ui.main_window import FindingCard, MainWindow  # noqa: E402

# Words the window must never show. The report's collapsed appendix is where
# these belong; a novice screen that says WHEA is a design failure.
BANNED_ON_SCREEN = ["WHEA", "TDR", "0x", "sfc", "sc query", "PowerShell",
                    "EventID", "Registry", "HKLM", "HKCU", "ctypes", "XPath",
                    "Defender"]


def wait_until(window, seconds=90.0):
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        QApplication.processEvents()
        if window.findings and not window.worker.isRunning():
            return True
        time.sleep(0.02)
    return False


def labels(window):
    out = []
    for widget in window.findChildren(QLabel):
        text = widget.text()
        if text:
            out.append((widget.objectName() or "label", text))
    return out


def main():
    app = QApplication(sys.argv)
    ctx = scan.build_ctx()
    window = MainWindow(ctx, entry_script=sys.argv[0])
    window.show()

    print("窗口标题：%s ｜ 大小 %dx%d" % (window.windowTitle(),
                                          window.width(), window.height()))
    print("按钮：主=%s 报告=%s 复制=%s 打开=%s 提权=%s"
          % (window.run_btn.text(), window.report_btn.text(),
             window.copy_btn.text(), window.open_btn.text(),
             window.admin_btn.text()))
    print("报告/复制按钮初始可用：", window.report_btn.isEnabled(),
          window.copy_btn.isEnabled(), "（应为 False False）")

    window.start_scan()
    ok = wait_until(window)
    cards = window.findChildren(FindingCard)
    print("\n扫描完成：%s ｜ 看板卡片 %d 张" % (ok, len(cards)))
    print("进度：%d / %d ｜ 状态行：%s"
          % (window.progress.value(), window.progress.maximum(),
             window.step_label.text()))
    print("总评：%s" % window.verdict.text())
    print("状态栏：%s" % window.statusBar().currentMessage())

    text_labels = labels(window)
    dirty = [(name, t) for name, t in text_labels
             for word in BANNED_ON_SCREEN if word.lower() in t.lower()]
    print("\n界面上出现的底层词汇：%s" % ("无" if not dirty else dirty[:4]))

    window.make_report()
    folder_ok = os.path.isdir(window.report_folder)
    produced = [n for n in os.listdir(window.report_folder)
                if n.startswith(("体检报告-", "体检结果-"))] if folder_ok else []
    print("报告按钮写出文件：%d 个于 %s ｜ %s"
          % (len(produced), window.report_folder, window.step_label.text()[:50]))

    blob = window.plain_text()
    print("复制按钮产出：%d 行 / %d 字，开头=%r"
          % (blob.count("\n") + 1, len(blob), blob.splitlines()[0]))

    from sysprobe.sanitizer import Sanitizer
    live = [v for v, _ in Sanitizer()._live]
    leak = [len(v) for v in live if v.lower() in blob.lower()]
    print("剪贴板文本里的本机身份：%s" % ("无" if not leak else leak))

    fails = []
    if not ok:
        fails.append("线程没完成")
    if not cards:
        fails.append("看板是空的")
    if dirty:
        fails.append("界面出现底层词汇")
    if not window.report_written or len(produced) < 2:
        fails.append("报告没写出两个文件")
    if leak:
        fails.append("剪贴板泄露本机身份")
    print("\n%s（检查项 %d 只，结论 %d 条）"
          % ("通过" if not fails else "失败：" + "、".join(fails),
             len(probes.PROBES), len(window.findings)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
