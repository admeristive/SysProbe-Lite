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

_ENUM_CURRENT_SETTINGS = -1

class _DEVMODEW(C.Structure):
    """The display mode block, laid out by measured offsets, not by trust.

    dmPelsWidth sits at 172 and dmDisplayFrequency at 184; C.sizeof must stay
    220 or every field below dmDeviceName shifts and the readings turn into
    plausible nonsense. The driver writes 188 into dmSize on this machine, so
    the returned size is not a handshake and cannot be used as one.
    """
    _fields_ = [
        ("dmDeviceName", W.WCHAR * 32),
        ("dmSpecVersion", W.WORD), ("dmDriverVersion", W.WORD),
        ("dmSize", W.WORD), ("dmDriverExtra", W.WORD), ("dmFields", W.DWORD),
        ("dmOrientation", W.SHORT), ("dmPaperSize", W.SHORT),
        ("dmPaperLength", W.SHORT), ("dmPaperWidth", W.SHORT),
        ("dmScale", W.SHORT), ("dmCopies", W.SHORT),
        ("dmDefaultSource", W.SHORT), ("dmPrintQuality", W.SHORT),
        ("dmColor", W.SHORT), ("dmDuplex", W.SHORT),
        ("dmYResolution", W.SHORT), ("dmTTOption", W.SHORT),
        ("dmCollate", W.SHORT),
        ("dmFormName", W.WCHAR * 32),
        ("dmLogPixels", W.WORD),
        ("dmBitsPerPel", W.DWORD), ("dmPelsWidth", W.DWORD),
        ("dmPelsHeight", W.DWORD), ("dmDisplayFlags", W.DWORD),
        ("dmDisplayFrequency", W.DWORD), ("dmICMMethod", W.DWORD),
        ("dmICMIntent", W.DWORD), ("dmMediaType", W.DWORD),
        ("dmDitherType", W.DWORD), ("dmReserved1", W.DWORD),
        ("dmReserved2", W.DWORD), ("dmPanningWidth", W.DWORD),
        ("dmPanningHeight", W.DWORD),
    ]


user32.EnumDisplaySettingsW.argtypes = [W.LPCWSTR, C.c_int, C.POINTER(_DEVMODEW)]
user32.EnumDisplaySettingsW.restype = W.BOOL


def _mode_at(device, index):
    """One mode as a dict, or None when the driver declines that index."""
    m = _DEVMODEW()
    if not user32.EnumDisplaySettingsW(device, index, C.byref(m)):
        return None
    return {"width": int(m.dmPelsWidth), "height": int(m.dmPelsHeight),
            "hz": int(m.dmDisplayFrequency), "bpp": int(m.dmBitsPerPel)}


def display_modes():
    """Per attached display: the mode in use, and the fastest mode offered at
    that same size.

    This is what separates "the panel is a 240 Hz panel" from "the panel is
    being driven at 60 Hz", which no other read-only channel on this machine
    answers. Measured here: 1 attached device, 24 size tiers out of 210 mode
    rows, current 2560x1600 at 240 Hz, about 7 ms.

    The DPI trap is worth keeping visible: GetDeviceCaps with HORZRES/VERTRES
    returns 1707x1067 at 150% scaling, while DESKTOPHORZRES/DESKTOPVERTRES
    return the panel's real 2560x1600. Only the desktop pair agrees with what
    this function reports, so the logical device context must never be quoted
    as a resolution.

    Which row to walk also has to be read from the flags, not guessed: the
    adapter rows measure here as 0x00000005 (ACTIVE|PRIMARY) and ATTACHED_TO_DESKTOP
    only appears on the monitor hanging off them, so filtering adapters by that
    bit returns nothing at all - the failure is silent, an empty list, which is
    why the caller reads None as "not measured" rather than "no display".
    """
    if C.sizeof(_DEVMODEW) != 220:
        return None
    devices = []
    i = 0
    while i < 8:
        dd = _DISPLAY_DEVICEW()
        dd.cb = C.sizeof(dd)
        if not user32.EnumDisplayDevicesW(None, i, C.byref(dd), 0):
            break
        flags = dd.StateFlags
        if (flags & _DD.ACTIVE) and not (flags & _DD.MIRRORING_DRIVER):
            devices.append((dd.DeviceName.strip("\0"),
                            dd.DeviceString.strip("\0"),
                            bool(flags & _DD.PRIMARY_DEVICE)))
        i += 1
    out = []
    for device, adapter, primary in devices:
        current = _mode_at(device, _ENUM_CURRENT_SETTINGS)
        if not current:
            continue
        best = {}
        n = 0
        while n < 400:
            row = _mode_at(device, n)
            if not row:
                break
            key = (row["width"], row["height"])
            if row["hz"] > best.get(key, 0):
                best[key] = row["hz"]
            n += 1
        ceiling = best.get((current["width"], current["height"]), current["hz"])
        out.append({
            "device": device, "adapter": adapter, "primary": primary,
            "current": current,
            "ceiling_hz": ceiling,
            "gap": ceiling - current["hz"],
            "tiers": len(best),
            "best_any": max(best.values()) if best else current["hz"],
        })
    return out or None


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


# ------------------------------------------------------- memory vs commit limit

class _MEMORYSTATUSEX(C.Structure):
    _fields_ = [
        ("dwLength", W.DWORD),
        ("dwMemoryLoad", W.DWORD),
        ("ullTotalPhys", C.c_ulonglong),
        ("ullAvailPhys", C.c_ulonglong),
        ("ullTotalPageFile", C.c_ulonglong),
        ("ullAvailPageFile", C.c_ulonglong),
        ("ullTotalVirtual", C.c_ulonglong),
        ("ullAvailVirtual", C.c_ulonglong),
        ("ullAvailExtendedVirtual", C.c_ulonglong),
    ]


kernel32.GlobalMemoryStatusEx.argtypes = [C.POINTER(_MEMORYSTATUSEX)]
kernel32.GlobalMemoryStatusEx.restype = W.BOOL


def memory_commit():
    """Physical RAM against the commit limit.

    The commit limit equals RAM plus every paging file, so the two numbers
    being equal means paging is switched off. dwLength must be set before the
    call or the API refuses and reports success-sized garbage.
    """
    m = _MEMORYSTATUSEX()
    m.dwLength = C.sizeof(_MEMORYSTATUSEX)
    if not kernel32.GlobalMemoryStatusEx(C.byref(m)):
        return None
    return {
        "load_percent": int(m.dwMemoryLoad),
        "total_phys": int(m.ullTotalPhys),
        "avail_phys": int(m.ullAvailPhys),
        "total_commit": int(m.ullTotalPageFile),
        "avail_commit": int(m.ullAvailPageFile),
    }


_MM_KEY = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"


def paging_declaration():
    """What paging the system declares, and what is actually attached.

    PagingFiles is what the user or a script asked for; ExistingPageFiles is
    what Windows attached at start-up. Reading both tells us where the paging
    files live, which the commit-limit totals alone cannot.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _MM_KEY, 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return None
    got = {}
    try:
        for name, out_key in (("PagingFiles", "declared"),
                              ("ExistingPageFiles", "attached")):
            try:
                raw, _kind = winreg.QueryValueEx(key, name)
            except OSError:
                continue
            if isinstance(raw, str):
                raw = [raw]
            got[out_key] = [str(x) for x in raw]
    finally:
        winreg.CloseKey(key)
    return got or None


# ------------------------------------------------- per-process drawing limits

GR_GDIOBJECTS = 0
GR_USEROBJECTS = 1
PROCESS_QUERY_INFORMATION = 0x0400

_ENUM_PROC = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
user32.EnumWindows.argtypes = [_ENUM_PROC, W.LPARAM]
user32.EnumWindows.restype = W.BOOL
user32.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
user32.GetWindowThreadProcessId.restype = W.DWORD
user32.GetGuiResources.argtypes = [W.HANDLE, W.DWORD]
user32.GetGuiResources.restype = W.DWORD


def window_owners(cap=80):
    """[(pid, top_level_window_count)], busiest first.

    Every top-level window counts, not only the visible ones: the program that
    runs out of drawing resources is often sitting in the notification area.
    """
    counts = {}

    @_ENUM_PROC
    def _each(hwnd, _lparam):
        pid = W.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, C.byref(pid))
        if pid.value:
            counts[pid.value] = counts.get(pid.value, 0) + 1
        return True

    try:
        user32.EnumWindows(_each, 0)
    except Exception:
        return []
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:cap]


def draw_usage(pid):
    """(gdi_objects, user_objects) for one pid, or None when we cannot see it.

    Query-only rights, no memory is read, and the handle is always closed.
    A process that owns a window cannot legitimately report zero of both, so
    0/0 is treated as "the owner refused us" rather than as a real measurement.
    """
    for rights in (PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_QUERY_INFORMATION):
        handle = kernel32.OpenProcess(rights, False, pid)
        if not handle:
            continue
        try:
            gdi = int(user32.GetGuiResources(handle, GR_GDIOBJECTS))
            usr = int(user32.GetGuiResources(handle, GR_USEROBJECTS))
        finally:
            kernel32.CloseHandle(handle)
        return (gdi, usr) if (gdi or usr) else None
    return None


# ------------------------------------------------------- registry read helpers

_NO_MORE_ITEMS = 259


def _read_values(handle, names):
    """{name: value} with None for whatever the key does not carry.

    Missing values are the normal case here, not an error: installers write
    wildly different subsets of their own uninstall key.
    """
    got = {}
    for name in names:
        try:
            got[name] = winreg.QueryValueEx(handle, name)[0]
        except OSError:
            got[name] = None
    return got


def _subkey_names(key):
    """Subkey names, or None when the sweep could not be finished.

    [] and None are different answers: [] means this key really holds nothing,
    None means we cannot say. A probe that reads a half-finished list as an
    empty one tells a novice their machine has no programs installed. Enumerating
    past the end raises 259, which is a completed sweep, not a failure - and 259
    is read from winerror, falling back to errno, because a hand-made OSError
    in a test can carry the code in either place.
    """
    try:
        count = winreg.QueryInfoKey(key)[0]
    except OSError:
        return None
    names = []
    for i in range(count):
        try:
            names.append(winreg.EnumKey(key, i))
        except OSError as exc:
            code = getattr(exc, "winerror", None)
            if code is None:
                code = exc.errno
            if code == _NO_MORE_ITEMS:
                break
            return None
    return names


# ------------------------------------------------------------ installed software

_UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_UNINSTALL_VIEWS = (
    ("machine64", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
    ("machine32", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
    ("user", winreg.HKEY_CURRENT_USER, 0),
)
_UNINSTALL_FIELDS = ("DisplayName", "Publisher", "DisplayVersion",
                     "InstallDate", "EstimatedSize", "SystemComponent")


def installed_programs():
    """What "设置 - 应用" itself lists, read from the keys that page is built from.

    Measured here: 200 entries across the three views, 67 left once the rows with
    no display name and the ones the system hides are dropped; 6.2 ms for the
    whole sweep.

    Two value names are refused on purpose. UninstallString and
    QuietUninstallString are the command line that would remove a program, and
    this tool removes nothing. InstallLocation is skipped because it stores
    C:\\Users\\<account> for anything installed per-user, which is exactly the
    text the report must never carry; the subkey name often repeats it, so the
    row below keeps the view ("machine64") instead of the key path.

    The payload carries its own honesty: unreadable counts keys that would not
    open, truncated says a view stopped mid-sweep. A count of programs is only
    safe to judge against a threshold when those two are known.
    """
    rows = []
    unreadable = 0
    truncated = False
    seen = set()
    for scope, hive, view in _UNINSTALL_VIEWS:
        try:
            key = winreg.OpenKey(hive, _UNINSTALL, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        try:
            subs = _subkey_names(key)
            if subs is None:
                truncated = True
                continue
            for sub in subs:
                try:
                    s = winreg.OpenKey(key, sub)
                except OSError:
                    unreadable += 1
                    continue
                try:
                    got = _read_values(s, _UNINSTALL_FIELDS)
                finally:
                    winreg.CloseKey(s)
                name = (got.get("DisplayName") or "").strip()
                if not name or got.get("SystemComponent") == 1:
                    continue
                date = str(got.get("InstallDate") or "")
                size = got.get("EstimatedSize")
                row = {
                    "name": name,
                    "publisher": (got.get("Publisher") or "").strip(),
                    "version": str(got.get("DisplayVersion") or "").strip(),
                    "installed_on": date if len(date) == 8 and date.isdigit() else "",
                    "size_mb": round(size / 1024.0, 1) if isinstance(size, int) else None,
                    "scope": scope,
                }
                mark = (name.lower(), row["version"])
                if mark in seen:
                    continue
                seen.add(mark)
                rows.append(row)
        finally:
            winreg.CloseKey(key)
    if not rows:
        return None
    return {"rows": rows, "unreadable": unreadable, "truncated": truncated}


# ---------------------------------------------------------------- audio endpoints

_MMDEVICES = r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio"
_DEVICE_STATE = {"active": 0x1, "disabled": 0x2,
                 "not_streaming": 0x4, "unplugged": 0x8}


def audio_endpoint_states():
    """Every play and record endpoint with its state word, as the system stores it.

    Measured here: 13 play and 6 record endpoints, all readable without
    elevation, 0.28 ms.

    DeviceState is a bitmask, and the values on a real machine are composites -
    0x22000004 appeared here. Testing it for equality against 1, 2, 4 or 8 is
    how an endpoint that is simply not streaming right now gets misreported as
    broken, so callers must mask. The endpoint's own CLSID is not returned: the
    probe counts devices, and a device that has been renamed after its owner
    would carry that name into a report.
    """
    rows = []
    unreadable = 0
    truncated = False
    for kind, label in (("Render", "play"), ("Capture", "record")):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 "%s\\%s" % (_MMDEVICES, kind))
        except OSError:
            continue
        try:
            subs = _subkey_names(key)
            if subs is None:
                truncated = True
                continue
            for sub in subs:
                try:
                    s = winreg.OpenKey(key, sub)
                except OSError:
                    unreadable += 1
                    continue
                try:
                    raw = _read_values(s, ("DeviceState",))["DeviceState"]
                finally:
                    winreg.CloseKey(s)
                if not isinstance(raw, int):
                    unreadable += 1
                    continue
                row = {"kind": label, "state": int(raw)}
                for name, bit in _DEVICE_STATE.items():
                    row[name] = bool(raw & bit)
                rows.append(row)
        finally:
            winreg.CloseKey(key)
    if not rows:
        return None
    return {"rows": rows, "unreadable": unreadable, "truncated": truncated}


# ------------------------------------------------------------------ net cards

_NIC_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
_NCF = {"virtual": 0x0001, "physical": 0x0004, "hidden": 0x0008,
        "no_service": 0x0010, "not_user_removable": 0x0020, "has_ui": 0x0080}
_NIC_FIELDS = ("DriverDesc", "Characteristics", "*IfType")


def network_adapters():
    """Cards and pseudo-cards, with the hardware ones told from the rest.

    Measured here: 15 numbered subkeys, 0.35 ms, DriverDesc and Characteristics
    present on all 15, 11 of them flagged hidden. The 0x0004 bit split them
    correctly: Intel Wi-Fi 6 AX201 (0x84) and Realtek PCIe GbE (0x04) were the
    only two physical rows, while the remaining thirteen were WAN miniports,
    Wi-Fi Direct, Bluetooth PAN, Kernel Debug and a Wintun tunnel.

    *IfType cannot make that split - five of the thirteen virtual rows report 6,
    the same number as real Ethernet (Bluetooth PAN, Kernel Debug and the three
    WAN miniports that carry IP) - which is why this goes through the bit and not
    the type. No address is read: an IP or a MAC is the
    one reading that names a person's network, and counting adapters is enough
    for the fault this probe is about.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NIC_CLASS, 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return None
    rows = []
    unreadable = 0
    truncated = False
    try:
        subs = _subkey_names(key)
        if subs is None:
            truncated = True
        else:
            for sub in subs:
                if not sub.isdigit():
                    continue
                try:
                    s = winreg.OpenKey(key, sub)
                except OSError:
                    unreadable += 1
                    continue
                try:
                    got = _read_values(s, _NIC_FIELDS)
                finally:
                    winreg.CloseKey(s)
                mask = got.get("Characteristics")
                if not isinstance(mask, int):
                    unreadable += 1
                    continue
                row = {"name": (got.get("DriverDesc") or "").strip(),
                       "characteristics": mask,
                       "if_type": got.get("*IfType")}
                for label, bit in _NCF.items():
                    row[label] = bool(mask & bit)
                rows.append(row)
    finally:
        winreg.CloseKey(key)
    if not rows:
        return None
    return {"rows": rows, "unreadable": unreadable, "truncated": truncated}
