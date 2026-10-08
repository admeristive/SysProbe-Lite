"""Entry point for 双击运行体检.exe.

Responsibilities, in order: install the crash sink first (a window that
vanishes teaches a novice nothing), start at ordinary privileges, and hand the
screen to the UI. Nothing here reads the network, and nothing here writes
outside its own report folder.
"""

import os
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CRASH_NOTE = (
    "这个文件记录程序没能完成的步骤，只写在电脑本地。\n"
    "写入前已过一遍脱敏；但错误记录里仍可能出现本机的文件夹路径，\n"
    "所以先发给你信任的人，不要直接贴到公开场合。\n")


def _crash_sink():
    def write(kind, text):
        target = ""
        try:
            from sysprobe import paths
            target = paths.crash_log_path()
        except OSError:
            return ""
        # A traceback is the one place C:\Users\<name> reaches a file without
        # passing the report pipeline, and this log is meant to be shareable.
        # If the sanitizer itself blows up we still write - losing the record
        # of a crash is worse than a scrubbed path.
        try:
            from sysprobe.sanitizer import Sanitizer
            text = Sanitizer().text(text)
        except Exception:
            pass
        try:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            fresh = (not os.path.exists(target)) or os.path.getsize(target) == 0
            with open(target, "a", encoding="utf-8") as handle:
                if fresh:
                    handle.write(CRASH_NOTE)
                handle.write("\n[%s] %s\n%s\n" % (stamp, kind, text))
        except OSError:
            pass
        return target

    def hook(exc_type, exc, tb):
        write("未处理异常", "".join(traceback.format_exception(exc_type, exc, tb)))

    sys.excepthook = hook
    import threading
    threading.excepthook = lambda args: write(
        "后台线程异常", "".join(traceback.format_exception(
            args.exc_type, args.exc_value, args.exc_traceback)))
    return write


def _parse(argv):
    flags = {"elevated": False, "headless": False, "guicheck": False, "help": False}
    for item in argv:
        low = item.lower()
        if low in ("--elevated", "/elevated"):
            flags["elevated"] = True
        elif low == "--no-gui":
            flags["headless"] = True
        elif low in ("--gui-check", "--gui_check"):
            flags["guicheck"] = True
        elif low in ("--help", "-h", "/?"):
            flags["help"] = True
    return flags


def _headless(flags, log):
    """Run one scan and write the reports. Used for verification without a screen."""
    from sysprobe import probes, report, scan
    from sysprobe.model import Finding
    from sysprobe.sanitizer import Sanitizer

    ctx = scan.build_ctx()
    san = Sanitizer()
    started = time.perf_counter()
    findings = scan.run(ctx)
    elapsed = (time.perf_counter() - started) * 1000.0
    shown = [Finding.from_dict(san.deep(f.to_dict())) for f in findings]
    meta = report.build_meta(ctx, shown, san, elapsed)
    written = report.write(shown, meta)
    print("检查项 %d 个，用时 %.0f ms，结论 %d 条"
          % (len(probes.PROBES), elapsed, len(shown)))
    print(meta["verdict"])
    print(san.summary())
    print("HTML: %s" % written.get("html", ""))
    print("TXT : %s" % written.get("plain", ""))
    print("就地写入: %s" % written.get("in_place"))
    return 0


def _gui_check():
    """Bring the real window up without a screen, run one scan, write a verdict.

    A frozen windowed build has no console, so the only way to prove the Qt
    half survived packaging - platform plugin found, widgets construct, the
    worker thread delivers - is to let it write what it saw to its own folder.
    """
    import time as _t
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QLabel
    from sysprobe import scan
    from sysprobe.ui.main_window import FindingCard, MainWindow

    banned = ["WHEA", "TDR", "0x", "sfc", "sc query", "PowerShell", "EventID",
              "HKLM", "HKCU", "ctypes", "XPath", "Defender"]
    app = QApplication(sys.argv)
    window = MainWindow(scan.build_ctx(), entry_script=sys.argv[0])
    window.show()
    window.start_scan()
    seen = {"done": False, "broken": ""}
    if window.worker is not None:
        window.worker.done.connect(
            lambda _d, _s, _e, _c: seen.__setitem__("done", True))
        window.worker.broken.connect(lambda r: seen.__setitem__("broken", r))
    deadline = _t.perf_counter() + 120
    while _t.perf_counter() < deadline and not seen["done"] and not seen["broken"]:
        app.processEvents()
        _t.sleep(0.02)
    # the window's own slots are queued too - pump until the board is built
    for _ in range(60):
        app.processEvents()
        _t.sleep(0.01)
    finished = bool(window.findings)
    cards = len(window.findChildren(FindingCard))
    dirty = [t for _n, t in [(w.objectName(), w.text())
                             for w in window.findChildren(QLabel)]
             for word in banned if word.lower() in t.lower()]
    ok = finished and cards > 0 and not dirty and not seen["broken"]
    line = "gui-check %s | 结论 %d 条 | 看板卡片 %d 张 | 底层词汇命中 %d 处 | 平台 %s%s" % (
        "PASS" if ok else "FAIL", len(window.findings), cards, len(dirty),
        os.environ.get("QT_QPA_PLATFORM", ""),
        "" if not seen["broken"] else " | 线程异常：%s" % seen["broken"])
    try:
        from sysprobe import paths
        folder, _ = paths.report_dir()
        with open(os.path.join(folder, "gui_check.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass
    return 0 if ok else 1


def main():
    log = _crash_sink()
    flags = _parse(sys.argv[1:])
    if flags["help"]:
        print("系统简易体检仪\n"
              "  直接双击运行即可，普通权限能完成大部分检查。\n"
              "  --no-gui    不开窗口，跑一遍并把报告写到本机（用于验证）\n"
              "  --gui-check 离屏起一次真窗口并把验收结果写到 gui_check.txt\n"
              "  --elevated  由程序自己请求管理员权限后重启时使用，不建议手输\n")
        return 0
    if flags["headless"]:
        return _headless(flags, log)
    if flags.get("guicheck"):
        return _gui_check()

    from PySide6.QtWidgets import QApplication
    from sysprobe import paths, scan
    from sysprobe.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("系统简易体检仪")
    app.setOrganizationName("SysProbe-Lite")
    app.setQuitOnLastWindowClosed(True)
    try:
        app.setStyle("Fusion")
    except Exception:
        pass

    ctx = scan.build_ctx()
    window = MainWindow(ctx, entry_script=sys.argv[0], note=log)
    window.show()
    if flags["elevated"]:
        window.step_label.setText("已用管理员权限打开，能看到全部检查项。")
        # Proof the handoff actually landed: this line only exists when a
        # process is running with an elevated token, and the title is the
        # window's own - so the two instances are told apart without a screen.
        log("提权实例已启动", "pid=%d 管理员=%s 标题=%s"
            % (os.getpid(), paths.running_as_admin(), window.windowTitle()))
    return app.exec()


if __name__ == "__main__":
    try:
        code = main()
    except SystemExit:
        raise
    except Exception as exc:
        _crash_sink()("启动失败", traceback.format_exc())
        try:
            from PySide6.QtWidgets import QApplication, QMessageBox
            if QApplication.instance() is None:
                QApplication([])
            QMessageBox.warning(
                None, "系统简易体检仪",
                "程序这次没能打开：%s\n\n详情已经写在电脑本地的日志文件里，"
                "不需要截图，重新双击一次通常就好了。" % type(exc).__name__)
        except Exception:
            pass
        code = 1
    sys.exit(code)
