"""Native, read-only, non-elevated system access.

Everything here was verified working without administrator rights on Windows 11
(10.0.26300). Two findings shaped this module and are worth keeping visible:

* `wmic.exe` no longer ships with this Windows build, so WMI-by-CLI is not an
  option; and direct `wevtapi.dll` calls via ctypes return ERROR_INVALID_PARAMETER
  (87) here, so event logs go through the signed `wevtutil.exe` instead (evtlog.py).
* `OpenServiceW` returns access denied (gle=5) for non-elevated callers even with
  SC_MANAGER_CONNECT + SERVICE_QUERY, so service *running state* is not obtainable
  without elevation. We report only the startup type from the registry.
"""

import ctypes as C
import locale
import os
import subprocess
from ctypes import wintypes as W

U32 = C.c_uint32
kernel32 = C.WinDLL("kernel32.dll", use_last_error=True)
user32 = C.WinDLL("user32.dll", use_last_error=True)

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
CREATE_NO_WINDOW = 0x08000000


# ----------------------------------------------------------------- subprocess

def _decode(raw: bytes) -> str:
    """wevtutil/powercfg emit the OEM codepage (cp936 on zh-CN), not UTF-8."""
    for enc in ("utf-8", "utf-8-sig", locale.getpreferredencoding(False), "gbk", "cp437"):
        if not enc:
            continue
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def run_readonly(argv, timeout=5.0):
    """Run a signed system binary read-only. Never a shell, never a window."""
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must be list[str]")
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW,
        cwd=SYSTEM_ROOT,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return -1, "", "TIMEOUT"
    return proc.returncode, _decode(out), _decode(err)


# ----------------------------------------------------------------- battery

class _SYSTEM_POWER_STATUS(C.Structure):
    _fields_ = [
        ("ACLineStatus", W.BYTE),
        ("BatteryFlag", W.BYTE),
        ("BatteryLifePercent", W.BYTE),
        ("SystemStatus", W.BYTE),
        ("BatteryLifeTime", W.DWORD),
        ("BatteryFullLifeTime", W.DWORD),
    ]


kernel32.GetSystemPowerStatus.argtypes = [C.c_void_p]
kernel32.GetSystemPowerStatus.restype = W.BOOL


def power_status():
    """None on failure; otherwise a dict. BatteryFlag bit 0x80 == no battery."""
    st = _SYSTEM_POWER_STATUS()
    if not kernel32.GetSystemPowerStatus(C.byref(st)):
        return None
    has = not (st.BatteryFlag & 0x80)
    pct = st.BatteryLifePercent
    return {
        "has_battery": has,
        "on_ac": st.ACLineStatus == 1,
        # 255 means "unknown" per the API contract, not "100%".
        "percent": None if pct == 255 else pct,
        "minutes_left": None if st.BatteryLifeTime == 0xFFFFFFFF else st.BatteryLifeTime // 60,
        "minutes_full": None if st.BatteryFullLifeTime == 0xFFFFFFFF else st.BatteryFullLifeTime // 60,
        "flag": st.BatteryFlag,
    }


# ----------------------------------------------------------------- disks

kernel32.GetLogicalDriveStringsW.argtypes = [W.DWORD, W.LPWSTR]
kernel32.GetLogicalDriveStringsW.restype = W.DWORD
kernel32.GetDriveTypeW.argtypes = [W.LPCWSTR]
kernel32.GetDriveTypeW.restype = W.UINT
kernel32.GetDiskFreeSpaceExW.argtypes = [W.LPCWSTR, C.POINTER(C.c_ulonglong),
                                         C.POINTER(C.c_ulonglong), C.POINTER(C.c_ulonglong)]
kernel32.GetDiskFreeSpaceExW.restype = W.BOOL

_DRIVE_TYPE = {2: "可移动磁盘", 3: "本地磁盘", 4: "网络驱动器", 5: "光驱", 6: "内存盘"}


def fixed_drives():
    buf = C.create_unicode_buffer(1024)
    if not kernel32.GetLogicalDriveStringsW(1024, buf):
        return []
    out = []
    for root in [d for d in buf.value.split("\0") if d]:
        dtype = kernel32.GetDriveTypeW(root)
        if dtype != 3:
            continue
        free = C.c_ulonglong(0)
        total = C.c_ulonglong(0)
        tfree = C.c_ulonglong(0)
        if not kernel32.GetDiskFreeSpaceExW(root, C.byref(free), C.byref(total), C.byref(tfree)):
            continue
        if total.value == 0:
            continue
        out.append({
            "root": root,
            "kind": _DRIVE_TYPE.get(dtype, "本地磁盘"),
            "total_gb": total.value / 2 ** 30,
            "free_gb": free.value / 2 ** 30,
            "free_pct": free.value / total.value * 100.0,
            "is_system": root.rstrip("\\").upper() == os.environ.get("SystemDrive", "C:").upper(),
        })
    return out


# ----------------------------------------------------------------- displays

class _DISPLAY_DEVICEW(C.Structure):
    _fields_ = [
        ("cb", W.DWORD),
        ("DeviceName", W.WCHAR * 32),
        ("DeviceString", W.WCHAR * 128),
        ("StateFlags", W.DWORD),
        ("DeviceID", W.WCHAR * 128),
        ("DeviceKey", W.WCHAR * 128),
    ]


EDD_GET_DEVICE_INTERFACE_NAME = 0x00000001


class _DD:
    ACTIVE = 0x00000001
    ATTACHED_TO_DESKTOP = 0x00000002
    PRIMARY_DEVICE = 0x00000004
    MIRRORING_DRIVER = 0x00000008
    VDMOPERATION = 0x00000010
    REMOVED = 0x08000000
    MODESPRUNED = 0x00000040


user32.EnumDisplayDevicesW.argtypes = [W.LPCWSTR, W.DWORD, C.POINTER(_DISPLAY_DEVICEW), W.DWORD]
user32.EnumDisplayDevicesW.restype = W.BOOL


def display_adapters():
    """Adapters with the monitors hanging off them.

    A single physical GPU reports several EnumDisplayDevices entries that share one
    DeviceID (measured: 4 rows for one RTX 4060). Deduping by DeviceID is mandatory,
    otherwise "多显卡冲突" fires on every normal machine.
    """
    raw = []
    i = 0
    while i < 16:
        dd = _DISPLAY_DEVICEW()
        dd.cb = C.sizeof(dd)
        if not user32.EnumDisplayDevicesW(None, i, C.byref(dd), 0):
            break
        monitors = []
        j = 0
        while j < 16:
            md = _DISPLAY_DEVICEW()
            md.cb = C.sizeof(md)
            if not user32.EnumDisplayDevicesW(dd.DeviceName, j, C.byref(md),
                                              EDD_GET_DEVICE_INTERFACE_NAME):
                break
            if md.DeviceString.strip("\0"):
                monitors.append(md.DeviceString.strip("\0"))
            j += 1
        raw.append({
            "name": dd.DeviceString.strip("\0"),
            "device_id": dd.DeviceID.strip("\0"),
            "flags": dd.StateFlags,
            "active": bool(dd.StateFlags & _DD.ACTIVE),
            "primary": bool(dd.StateFlags & _DD.PRIMARY_DEVICE),
            "attached": bool(dd.StateFlags & _DD.ATTACHED_TO_DESKTOP),
            "mirroring": bool(dd.StateFlags & _DD.MIRRORING_DRIVER),
            "removed": bool(dd.StateFlags & _DD.REMOVED),
            "monitors": monitors,
            "index": i,
        })
        i += 1

    merged = {}
    order = []
    for row in raw:
        key = row["device_id"] or "#%d" % row["index"]
        if key not in merged:
            merged[key] = {
                "name": row["name"], "device_id": key, "monitors": [],
                "active": False, "primary": False, "mirroring": False, "copies": 0,
            }
            order.append(key)
        slot = merged[key]
        slot["copies"] += 1
        slot["active"] = slot["active"] or row["active"]
        slot["primary"] = slot["primary"] or row["primary"]
        slot["mirroring"] = slot["mirroring"] or row["mirroring"]
        for m in row["monitors"]:
            if m not in slot["monitors"]:
                slot["monitors"].append(m)
    return [merged[k] for k in order]


# ----------------------------------------------------------------- processes

class _PROCESSENTRY32W(C.Structure):
    _fields_ = [
        ("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD),
        ("th32DefaultHeapID", C.POINTER(C.c_ulonglong)), ("th32ModuleID", W.DWORD),
        ("cntThreads", W.DWORD), ("th32ParentProcessID", W.DWORD),
        ("pcPriClassBase", C.c_long), ("dwFlags", W.DWORD), ("szExeFile", W.WCHAR * 260),
    ]


class _PROCESSENTRY32(C.Structure):
    _fields_ = [
        ("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD),
        ("th32DefaultHeapID", C.POINTER(C.c_ulonglong)), ("th32ModuleID", W.DWORD),
        ("cntThreads", W.DWORD), ("th32ParentProcessID", W.DWORD),
        ("pcPriClassBase", C.c_long), ("dwFlags", W.DWORD), ("szExeFile", W.CHAR * 260),
    ]


TH32CS_SNAPPROCESS = 0x2
_INVALID = C.c_void_p(-1).value

kernel32.CreateToolhelp32Snapshot.restype = C.c_void_p
kernel32.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]
kernel32.Process32First.argtypes = [C.c_void_p, C.c_void_p]
kernel32.Process32First.restype = W.BOOL
kernel32.Process32Next.argtypes = [C.c_void_p, C.c_void_p]
kernel32.Process32Next.restype = W.BOOL
kernel32.CloseHandle.argtypes = [C.c_void_p]
kernel32.OpenProcess.restype = W.HANDLE
kernel32.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
kernel32.QueryFullProcessImageNameW.restype = W.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def processes():
    """Name + pid for every visible process. No memory is ever read from them."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (None, _INVALID):
        return []
    out = []
    try:
        entry = _PROCESSENTRY32()
        entry.dwSize = C.sizeof(entry)
        if kernel32.Process32First(snap, C.byref(entry)):
            while True:
                name = os.fsdecode(entry.szExeFile)
                out.append({"name": name, "pid": int(entry.th32ProcessID),
                            "parent": int(entry.th32ParentProcessID)})
                if not kernel32.Process32Next(snap, C.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snap)
    return out


def image_path(pid):
    """Full exe path of a process; None when the owner denies us (common for
    other users' and protected processes)."""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = C.create_unicode_buffer(1024)
        size = W.DWORD(1024)
        if not kernel32.QueryFullProcessImageNameW(h, 0, buf, C.byref(size)):
            return None
        return buf.value
    finally:
        kernel32.CloseHandle(h)


# ----------------------------------------------------------------- services

import winreg  # noqa: E402  (kept last so the ctypes block above stays readable)

_START_TYPE = {0x1: "自动(开机)", 0x2: "自动(延迟)", 0x3: "手动", 0x4: "已禁用", 0x5: "开机时启动"}


def service_start_type(name):
    """Startup type only. Live state needs elevation (measured gle=5)."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\%s" % name)
    except OSError:
        return None
    try:
        raw = winreg.QueryValueEx(key, "Start")[0]
        return {"code": raw, "text": _START_TYPE.get(raw, "未知(%d)" % raw)}
    except OSError:
        return None
    finally:
        winreg.CloseKey(key)


# ----------------------------------------------------------------- wow64 paths

kernel32.IsWow64Process.argtypes = [W.HANDLE, C.POINTER(W.BOOL)]
kernel32.IsWow64Process.restype = W.BOOL


def is_wow64():
    """Under a 32-bit process, System32 silently redirects to SysWOW64, so the
    64-bit runtime DLLs would appear to be missing. Sysnative is the escape hatch."""
    flag = W.BOOL(False)
    if os.path.isdir(os.path.join(SYSTEM_ROOT, "Sysnative")):
        try:
            h = W.HANDLE(kernel32.GetCurrentProcess()).value
            kernel32.IsWow64Process(h, C.byref(flag))
            return bool(flag.value)
        except Exception:
            return True
    return False


def dir_64bit():
    return os.path.join(SYSTEM_ROOT, "Sysnative" if is_wow64() else "System32")


def dir_32bit():
    return os.path.join(SYSTEM_ROOT, "SysWOW64")
