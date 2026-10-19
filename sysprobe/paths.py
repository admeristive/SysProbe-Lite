"""Where the three root files live, and where a report may be written.

Frozen: the root is the folder holding 双击运行体检.exe, not the _internal
bundle. Reports go beside it when that folder is writable (so a novice finds
the report next to the icon they double-clicked), and fall back to %TEMP%
when it is not (Program Files, a read-only USB stick, a work folder with
strict ACLs). The fallback is reported in the UI rather than hidden.
"""

import os
import sys
import tempfile

REPORT_DIR_NAME = "体检报告"


def packaged():
    return bool(getattr(sys, "frozen", False))


def app_root():
    if packaged():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def internal_bundle():
    return getattr(sys, "_MEIPASS", "") if packaged() else app_root()


def asset_path(name):
    """A bundled picture, read-only, inside the _internal bundle.

    The same lookup works unpacked because internal_bundle() is the repository
    root there, and assets/ sits next to sysprobe/.
    """
    return os.path.join(internal_bundle(), "assets", name)


def running_as_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def report_dir():
    """(path, in_place). Never raises: %TEMP% always accepts a mkdir."""
    primary = os.path.join(app_root(), REPORT_DIR_NAME)
    if _writable_mkdir(primary):
        return primary, True
    fallback = os.path.join(tempfile.gettempdir(), "SysProbe-Lite")
    _writable_mkdir(fallback)
    return fallback, False


def crash_log_path():
    path, _ = report_dir()
    return os.path.join(path, "local_crash.log")


def _writable_mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".sysprobe_write_test")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        return True
    except OSError:
        return False
