"""UAC handoff: ask once, then let the new window take over.

The parent never polls the child and never waits on a pipe. If the elevation
succeeds the parent exits; if the user clicks 否 the parent keeps running at
ordinary privileges, because 80% of the checks work there and closing the
window on a declined prompt would be the worst possible outcome.
"""

import ctypes
import os
import sys

SW_SHOWNORMAL = 1
ELEVATED_FLAG = "--elevated"
ERROR_CANCELLED = 1223

# Only the documented ShellExecute failure values (2..32) belong here. 1223 is a
# GetLastError code, not a return value, so the 否 branch is read from the last
# error - a table entry for it could never fire, and a value above 32 would have
# been misread as "elevation succeeded" and closed the window on a declined
# prompt.
_MEANING = {
    2: "找不到要启动的程序",
    3: "系统不允许这样启动",
    5: "被系统拒绝",
    22: "路径有问题",
    31: "这台机器上没有可用的“以管理员身份运行”",
    32: "共享权限不允许",
}


def requested_elevated(argv=None):
    return ELEVATED_FLAG in (argv if argv is not None else sys.argv[1:])


def relaunch_as_admin(script=None):
    """(ok, note, code). ok=True only when a new elevated process actually started.

    The raw return code travels back because "the user clicked 否" and "Windows
    refused to offer elevation at all" look identical from the window, but they
    mean different things in the log - and the code is the only evidence anyone
    gets after the fact.
    """
    if paths_frozen():
        exe = sys.executable
        params = ELEVATED_FLAG
    else:
        entry = _entry_script(script)
        if not entry:
            return False, "找不到启动文件，无法请求管理员权限", -1
        exe = sys.executable
        params = '"%s" %s' % (entry, ELEVATED_FLAG)
    try:
        # restype must be pointer-sized: ShellExecuteW hands back an HINSTANCE,
        # and the default c_int would chop a 64-bit handle down to 32 bits and
        # turn a real success into a fake failure.
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.ShellExecuteW.restype = ctypes.c_size_t
        shell32.ShellExecuteW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
                                          ctypes.c_wchar_p, ctypes.c_wchar_p,
                                          ctypes.c_wchar_p, ctypes.c_int]
        rc = shell32.ShellExecuteW(
            None, "runas", exe, params, None, SW_SHOWNORMAL)
    except Exception as exc:
        return False, "无法发起权限请求（%s）" % type(exc).__name__, -1
    code = int(rc or 0)
    if code > 32:
        return True, "", code
    if code == 5 and ctypes.get_last_error() == ERROR_CANCELLED:
        return False, "你在权限弹窗里点了“否”，程序继续在普通权限下工作", code
    return False, _MEANING.get(code, "权限请求没有成功（返回 %d）" % code), code


def paths_frozen():
    return bool(getattr(sys, "frozen", False))


def _entry_script(script):
    """In dev the elevated child must be the same app.py the user just ran."""
    for candidate in (script, sys.argv[0]):
        if candidate and os.path.isfile(candidate) and candidate.endswith(".py"):
            return os.path.abspath(candidate)
    return ""
