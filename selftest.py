"""Headless harness: run every probe, print timings, prove the sanitizer holds.

This exists because a GUI cannot be reviewed on hardware you do not own. Use:
    py -3 selftest.py            # probes + sanitizer regression, no GUI, no writes
"""

import ast
import json
import os
import sys
import time
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from sysprobe import evtlog, history, native, probes, rules  # noqa: E402
from sysprobe.model import Finding, Status  # noqa: E402
from sysprobe.sanitizer import Sanitizer  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
MARK = {Status.RED: "[需处理]", Status.YELLOW: "[留意] ", Status.GREEN: "[正常] ",
        Status.GRAY: "[未取] "}


def build_ctx():
    return types.SimpleNamespace(
        root=ROOT,
        temp_dir=tempfile.gettempdir(),
        rules=rules.load(ROOT),
        win11=probes.win11(),
        app_codes=set(),
        started=time.time(),
    )


def run_probes(ctx):
    total = []
    print("== 探针耗时（非管理员，本机实测）==")
    for pid, title, fn, needs_admin in probes.PROBES:
        t0 = time.perf_counter()
        try:
            got = fn(ctx)
            err = ""
        except Exception as exc:
            got, err = [], "%s: %s" % (type(exc).__name__, exc)
        ms = (time.perf_counter() - t0) * 1000
        total.extend(got)
        flag = "ADMIN" if needs_admin else "     "
        print("  %-9s %-12s %6.0f ms  findings=%d %s%s"
              % (pid, flag, ms, len(got), "", err if err else ""))
        if err:
            print("     ^^ 探针抛异常，应当被上层兜住并降级为『未获取』")
    return total


def show(findings, san):
    print("\n== 结论（已过脱敏闸）==")
    order = [Status.RED, Status.YELLOW, Status.GREEN, Status.GRAY]
    for f in sorted(findings, key=lambda x: order.index(x.status)):
        if f.skip:
            continue
        print("%s %s" % (MARK[f.status], san.text(f.headline)))
        if f.plain:
            print("        %s" % san.text(f.plain)[:120])
        if f.native:
            print("        native=%s" % str(san.deep(f.native))[:160])
    skipped = [f for f in findings if f.skip]
    print("\n== 折叠项（skip，只进报告不进看板）%d 条 ==" % len(skipped))
    for f in skipped:
        print("   %s" % san.text(f.headline))


def encoding_check():
    """wevtutil writes the OEM codepage; prove Chinese survives the round trip."""
    print("\n== wevtutil 输出编码实测 ==")
    san = Sanitizer()
    rows = evtlog.query("System", evtlog.build("EventID=7036", days=3), max_records=3)
    for row in rows[:3]:
        computer = row["computer"]
        masked = san.text("on " + computer)
        print("   provider=%s 原样含中文=%s 脱敏后变化=%s"
              % (row["provider"],
                 any("\u4e00" <= c <= "\u9fff" for c in computer),
                 computer.lower() not in masked.lower()))
    if rows and ("\ufffd" in rows[0]["computer"]):
        print("   !! 解码失败：需要调整 native._decode 的编码顺序")


def live_identity_check(findings):
    """The only regression that matters: this machine's own names must not survive."""
    print("\n== 本机身份实跑校验 ==")
    san = Sanitizer()
    live = [v for v, _ in san._live]
    parts = []
    for f in findings:
        parts.extend([f.headline, f.plain, f.why, f.copy_cmd])
        parts.extend(f.steps)
        parts.append(str(san.deep(f.native)))
    blob = " \n ".join(san.text(p) for p in parts if p)
    leaked = [len(v) for v in live if v.lower() in blob.lower()]
    print("   参与校验的本机身份值: %d 只（最短 %s 字）"
          % (len(live), min([len(v) for v in live], default="-")))
    print("   实跑结论里残留的本机身份: %s" % ("有，长度=%s" % leaked if leaked else "无"))
    return not leaked


LEAK_CORPUS = [
    "C:\\Users\\zhangsan\\AppData\\Roaming\\foo\\bar.exe",
    "S-1-5-21-1234567890-1234567890-1234567890-1001",
    "192.168.10.23:7897",
    "00-1A-2B-3C-4D-5E",
    "ProxyServer=http://alice:SuperSecret1@10.0.0.9:7890",
    "dGhpcyBpcyBBIFRoaXMgaXMgVGhlVG9rZW4xMjM0",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abcDEF123",
    "fe80::1234:5678:9abc:def0%12",
    "token: hunter2secret",
]

MUST_SURVIVE = [
    # evidence the report needs; a lazy sanitizer eats these
    "0xc0000005",
    "{12345678-1234-1234-1234-123456789abc}",
    "224.0.0.0",
    "127.0.0.1",
]


def sanitizer_check():
    print("\n== 脱敏闸回归 ==")
    san = Sanitizer(seed_extra=("zhangsan", "alice", "SuperSecret1", "hunter2secret"))
    for line in LEAK_CORPUS:
        out = san.text(line)
        print("   IN : %s" % line)
        print("   OUT: %s" % out)
    joined = " \n ".join(san.text(x) for x in LEAK_CORPUS)
    banned = ["zhangsan", "alice", "SuperSecret1", "hunter2secret", "1234567890",
              "192.168.10.23", "00-1A-2B-3C-4D-5E",
              "dGhpcyBpcyBBIFRoaXMgaXMgVGhlVG9rZW4xMjM0"]
    leaked = [b for b in banned if b.lower() in joined.lower()]
    print("   泄露项: %s" % (leaked or "无"))
    keep_ok = []
    for token in MUST_SURVIVE:
        if token in san.text("异常代码 %s 位于 %s 网卡 224.0.0.0 与 127.0.0.1" % (token, token)):
            keep_ok.append(token)
    print("   证据保留: %s / %s" % (len(keep_ok), len(MUST_SURVIVE)))
    print("   %s" % san.summary())
    return not leaked


# ------------------------------------------------ collection-layer regressions

import ctypes as C                                              # noqa: E402
import winreg as RealWinReg                                     # noqa: E402

REAL_WINREG = native.winreg
REAL_USER32 = native.user32


class FakeWinReg:
    """A winreg that can refuse at any chosen step of a sweep.

    Every degradation below has to be reproducible without finding a machine
    that happens to deny us, so the stand-in answers for the handful of entry
    points native.py actually calls, and nothing else. count exists apart from
    the real list length so "枚举到底(259)" can be told from "被砍断".
    """
    HKEY_LOCAL_MACHINE = 1
    HKEY_CURRENT_USER = 2
    KEY_READ = 8
    KEY_WOW64_64KEY = 0x100
    KEY_WOW64_32KEY = 0x200

    def __init__(self, deny=(), subkeys=(), values=(), break_at=None, count=None):
        self.deny = set(deny)
        self.subkeys = list(subkeys)
        self.values = dict(values)
        self.break_at = break_at
        self.count = count
        self.closed = 0

    def OpenKey(self, hive, path, *rest):
        if path in self.deny:
            raise PermissionError(5, "access denied")
        return path

    def CloseKey(self, handle):
        self.closed += 1

    def QueryInfoKey(self, handle):
        return (len(self.subkeys) if self.count is None else self.count, 0, 0, 0)

    def EnumKey(self, handle, index):
        if self.break_at is not None and index == self.break_at:
            raise self._winerr(10054, "sweep cut")
        if index < len(self.subkeys):
            return self.subkeys[index]
        raise self._winerr(259, "no more items")

    @staticmethod
    def _winerr(winerror, text):
        """A registry error carries its Windows code in winerror, and native.py
        reads that to tell "到底了" from "被砍断" - the stand-in has to be shaped
        the same way or the case proves nothing about the real API.
        """
        exc = OSError(winerror, text)
        exc.winerror = winerror
        return exc

    def QueryValueEx(self, handle, name):
        if name in self.values:
            return (self.values[name], 4)
        raise FileNotFoundError(2, "no such value")


class FakeUser32:
    """user32 stand-in: one fake adapter, and either API can be made to refuse.

    The device row has to be filled in, not merely allowed: filtering happens
    on its state bits, so an empty row would make the mode-reading case pass
    for the wrong reason.
    """

    def __init__(self, devices=True, modes=True):
        self.devices, self.modes = devices, modes

    def EnumDisplayDevicesW(self, device, index, out, flags):
        if not self.devices or index > 0:
            return 0
        row = out._obj
        row.DeviceName = "\\\\.\\DISPLAY1"
        row.DeviceString = "Fake Adapter"
        row.StateFlags = 0x00000005
        return 1

    def EnumDisplaySettingsW(self, device, index, out):
        return 1 if self.modes else 0


def swap(winreg_obj=None, user32_obj=None):
    if winreg_obj is not None:
        native.winreg = winreg_obj
    if user32_obj is not None:
        native.user32 = user32_obj


def restore():
    native.winreg = REAL_WINREG
    native.user32 = REAL_USER32


def case(label, ok, extra=""):
    print("   %s %s%s" % ("[成立]" if ok else "[不成立]", label,
                          ("  |  %s" % extra) if extra else ""))
    return bool(ok)


PROGRAM_KEYS = {"name", "publisher", "version", "installed_on", "size_mb", "scope"}


def stub_check():
    """Degradation only: nothing here reads the machine."""
    print("\n== 采集层故障桩 ==")
    ok = []

    swap(winreg_obj=FakeWinReg(deny=[native._UNINSTALL]))
    ok.append(case("软件列表整条位置都拒绝 -> 取不到，不返回空名单",
                   native.installed_programs() is None))
    swap(winreg_obj=FakeWinReg(deny=[native._MMDEVICES + "\\Render",
                                     native._MMDEVICES + "\\Capture"]))
    ok.append(case("音频放音与录音两个位置都拒绝 -> 取不到",
                   native.audio_endpoint_states() is None))
    swap(winreg_obj=FakeWinReg(deny=[native._NIC_CLASS]))
    ok.append(case("网卡位置拒绝 -> 取不到", native.network_adapters() is None))

    swap(winreg_obj=FakeWinReg(subkeys=["0000", "0001"], break_at=1,
                               values={"DisplayName": "甲", "DeviceState": 1,
                                       "Characteristics": 0x0004, "DriverDesc": "甲"}))
    ok.append(case("枚举到一半被砍断 -> 软件名单取不到（不许把半份当成到底）",
                   native.installed_programs() is None))
    ok.append(case("枚举到一半被砍断 -> 网卡取不到", native.network_adapters() is None))
    ok.append(case("枚举到一半被砍断 -> 音频取不到",
                   native.audio_endpoint_states() is None))
    swap(winreg_obj=FakeWinReg(subkeys=["0000"], count=2,
                               values={"DisplayName": "只有这一条",
                                       "Characteristics": 0x0001, "DriverDesc": "只有这一条",
                                       "DeviceState": 1}))
    got = native.installed_programs()
    nics = native.network_adapters()
    ok.append(case("报「到底了」(259) 算读完：照常出名单，且不标记读不全",
                   got is not None and len(got["rows"]) == 1 and not got["truncated"],
                   str(got)))
    ok.append(case("同一位置对网卡也一样：259 之后照常出行，不标记读不全",
                   nics is not None and len(nics["rows"]) == 1 and not nics["truncated"],
                   str(nics)))

    swap(winreg_obj=FakeWinReg(subkeys=["0000", "0001"], deny=["0001"],
                               values={"DisplayName": "能读的那条", "EstimatedSize": 2048}))
    got = native.installed_programs()
    ok.append(case("单个条目拒绝 -> 能读到的照常给出，读不了的要被记账",
                   got is not None and len(got["rows"]) == 1
                   and got["unreadable"] >= 1 and not got["truncated"],
                   "unreadable=%s（三个视图各记一次）" % (got or {}).get("unreadable")))

    swap(winreg_obj=FakeWinReg(subkeys=["0000"],
                               values={"SystemComponent": 1, "DisplayName": "系统组件"}))
    ok.append(case("只登记为系统组件 -> 不进软件名单", native.installed_programs() is None))
    swap(winreg_obj=FakeWinReg(subkeys=["0000"], values={"Publisher": "没人写名字"}))
    ok.append(case("没有显示名 -> 不进软件名单", native.installed_programs() is None))
    swap(winreg_obj=FakeWinReg(subkeys=["0000"],
                               values={"DisplayName": "同名同版本", "DisplayVersion": "1.0"}))
    got = native.installed_programs()
    ok.append(case("三个视图都登记同一条同名同版本 -> 只算一次",
                   got is not None and len(got["rows"]) == 1, str(got)))

    swap(winreg_obj=FakeWinReg(subkeys=["{A}", "Link"]))
    ok.append(case("网卡位置里非编号的子键不参与统计", native.network_adapters() is None))
    swap(winreg_obj=FakeWinReg(subkeys=["0001"], values={"DriverDesc": "无特征位的一行"}))
    ok.append(case("网卡缺特征位 -> 说不清，不许猜成物理或虚拟",
                   native.network_adapters() is None))

    swap(winreg_obj=FakeWinReg(subkeys=["{A}", "{B}"], values={"DeviceState": 0x22000004}))
    rows = (native.audio_endpoint_states() or {}).get("rows", [])
    play = [r for r in rows if r["kind"] == "play"]
    ok.append(case("复合状态值按位拆解，不等于任何单一状态",
                   len(play) == 2 and len(rows) == 4
                   and all(r["active"] is False and r["disabled"] is False
                           and r["not_streaming"] is True and r["unplugged"] is False
                           for r in rows),
                   "%d 行（放音 %d）｜第一行 %s" % (len(rows), len(play), rows[:1])))
    swap(winreg_obj=FakeWinReg(subkeys=["{A}"]))
    ok.append(case("端点读不到状态 -> 计入读不了，不当成可用",
                   native.audio_endpoint_states() is None))

    swap(user32_obj=FakeUser32(devices=False))
    ok.append(case("一个显示设备都枚举不到 -> 取不到（不是「没有屏幕」）",
                   native.display_modes() is None))
    swap(user32_obj=FakeUser32(modes=False))
    ok.append(case("设备在、当前模式读不到 -> 取不到，不报 0x0@0Hz",
                   native.display_modes() is None))
    restore()
    return all(ok)


def live_check():
    """What this machine really answers, including the cross-checks."""
    print("\n== 采集层本机实测 ==")
    ok = []

    size = C.sizeof(native._DEVMODEW)
    off_w = native._DEVMODEW.dmPelsWidth.offset
    off_hz = native._DEVMODEW.dmDisplayFrequency.offset
    ok.append(case("显示模式结构体尺寸与偏移锁死（挪字段必先过这条）",
                   size == 220 and off_w == 172 and off_hz == 184,
                   "尺寸=%d 宽@%d 刷新率@%d" % (size, off_w, off_hz)))

    timings = {}
    for name in ("display_modes", "installed_programs",
                 "audio_endpoint_states", "network_adapters"):
        t0 = time.perf_counter()
        try:
            timings[name] = getattr(native, name)()
        except Exception as exc:
            timings[name] = "异常 %s" % type(exc).__name__
        timings[name + "_ms"] = (time.perf_counter() - t0) * 1000

    modes = timings["display_modes"]
    print("   显示模式 %.2f ms -> %s" % (timings["display_modes_ms"],
                                        "取不到" if not modes else
                                        "%d 个设备" % len(modes)))
    if modes:
        gdi = C.WinDLL("gdi32.dll", use_last_error=True)
        u32 = C.WinDLL("user32.dll", use_last_error=True)
        gdi.GetDeviceCaps.argtypes = [C.c_void_p, C.c_int]
        gdi.GetDeviceCaps.restype = C.c_int
        u32.GetDC.argtypes = [C.c_void_p]
        u32.GetDC.restype = C.c_void_p
        u32.ReleaseDC.argtypes = [C.c_void_p, C.c_void_p]
        hdc = u32.GetDC(None)
        caps = (gdi.GetDeviceCaps(hdc, 118), gdi.GetDeviceCaps(hdc, 117),
                gdi.GetDeviceCaps(hdc, 116), gdi.GetDeviceCaps(hdc, 12))
        u32.ReleaseDC(None, hdc)
        main_dev = [d for d in modes if d["primary"]] or modes
        cur = main_dev[0]["current"]
        seen = (cur["width"], cur["height"], cur["hz"], cur["bpp"])
        ok.append(case("另一条通道（显示能力查询）与结构体读数四项全等",
                       caps == seen, "另一路=%s 本路=%s" % (caps, seen)))
        ok.append(case("同分辨率上限不低于当前刷新率（差值只会是「被压住」或 0）",
                       main_dev[0]["ceiling_hz"] >= cur["hz"],
                       "当前 %d Hz / 上限 %d Hz / 差 %d"
                       % (cur["hz"], main_dev[0]["ceiling_hz"], main_dev[0]["gap"])))
        print("   分辨率档 %d 个｜全机最高 %d Hz" % (main_dev[0]["tiers"],
                                                  main_dev[0]["best_any"]))

    progs = timings["installed_programs"]
    rows = (progs or {}).get("rows", [])
    print("   已装软件 %.2f ms -> %d 条（读不了 %s，截断 %s）"
          % (timings["installed_programs_ms"], len(rows),
             (progs or {}).get("unreadable"), (progs or {}).get("truncated")))
    ok.append(case("软件名单至少取到 1 条（一条都没有就是没读到）",
                   len(rows) >= 1, "%d 条" % len(rows)))
    shape = set().union(*[set(r) for r in rows]) if rows else set()
    ok.append(case("每条只有那六个字段（不含卸载命令与安装路径）",
                   shape == PROGRAM_KEYS, str(sorted(shape - PROGRAM_KEYS))))
    who = os.environ.get("USERNAME", "")
    dirty = [r["name"] for r in rows
             if any("\\" in (r[k] or "") for k in ("name", "publisher", "version"))
             or (who and who.lower() in (r["name"] + r["publisher"]).lower())]
    ok.append(case("名单里没有账户名，也没有带路径的条目", not dirty,
                   "%d 条可疑" % len(dirty)))

    audio = timings["audio_endpoint_states"]
    arows = (audio or {}).get("rows", [])
    play = [r for r in arows if r["kind"] == "play"]
    rec = [r for r in arows if r["kind"] == "record"]
    comp = sum(1 for r in arows if r["state"] > 0xFF)
    print("   音频端点 %.2f ms -> 放音 %d / 录音 %d（复合状态 %d 个）"
          % (timings["audio_endpoint_states_ms"], len(play), len(rec), comp))
    ok.append(case("至少读到一路放音端点", bool(play), "%d 路" % len(play)))
    ok.append(case("状态拆解与原始位一致（判据只能走位，不能走相等）",
                   all(r["active"] is bool(r["state"] & 1) for r in arows)))

    nics = timings["network_adapters"]
    nrows = (nics or {}).get("rows", [])
    phys = [r for r in nrows if r["physical"]]
    virt = [r for r in nrows if r["virtual"]]
    both = [r for r in nrows if r["physical"] and r["virtual"]]
    six = [r for r in virt if r["if_type"] == 6]
    print("   网卡 %.2f ms -> 共 %d 行｜物理 %d｜虚拟 %d｜隐藏 %d｜读不了 %s"
          % (timings["network_adapters_ms"], len(nrows), len(phys), len(virt),
             sum(1 for r in nrows if r["hidden"]), (nics or {}).get("unreadable")))
    ok.append(case("至少认出一张物理网卡", len(phys) >= 1, "%d 张" % len(phys)))
    ok.append(case("物理与虚拟不打架（同一行不会两者都真）", not both,
                   "%d 行冲突" % len(both)))
    print("   本机读数：虚拟行里报以太网编号 6 的有 %d 行——类型号分不出真假，"
          "判据只能走特征位" % len(six))

    spent = sum(timings[k + "_ms"] for k in ("display_modes", "installed_programs",
                                             "audio_endpoint_states", "network_adapters"))
    ok.append(case("四路合计低于 60 ms（采集层不该成为瓶颈）", spent < 60.0,
                   "合计 %.2f ms" % spent))
    return all(ok)


def collectors_check():
    return stub_check() and live_check()


def _suppress_sites(text, where):
    """Split skip-flagged Finding calls into proven-red/yellow and unreadable."""
    bad, unclear = [], []
    for node in ast.walk(ast.parse(text)):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name != "Finding":
            continue
        kw = {k.arg: k.value for k in node.keywords}
        if "skip" not in kw or ast.unparse(kw["skip"]) == "False":
            continue
        status = ast.unparse(kw["status"]).replace("\n", "") if "status" in kw else ""
        if "RED" in status or "YELLOW" in status:
            bad.append("%s:%d %s" % (where, node.lineno, status.split("=")[-1]))
        elif "Status." not in status:
            unclear.append("%s:%d" % (where, node.lineno))
    return bad, unclear


CONTROL_SUPPRESS = '''
out.append(Finding(module="a", status=Status.RED, skip=True))
out.append(Finding(module="b", status=Status.YELLOW, skip=True))
out.append(Finding(module="c", status=Status.GREEN, skip=True))
'''


def skip_invariant_check():
    """A red or yellow conclusion must never be born already suppressed.

    This is read from the source, not from a live run, on purpose: this machine
    has no nearly-full secondary drive, so scanning cannot produce the case that
    broke - only reading every Finding call can.
    """
    print("\n== 抑制位不变量（红黄结论不许一出生就不占卡）==")
    ok = []
    control, _ = _suppress_sites(CONTROL_SUPPRESS, "<control>")
    ok.append(case("探针自检：故意写 3 处，命中 2 处（绿的那处不算）",
                   len(control) == 2, "、".join(control)))

    hits, unclear, files = [], [], 0
    for name in ("probes.py", "limits.py"):
        path = os.path.join(ROOT, "sysprobe", name)
        with open(path, "r", encoding="utf-8") as handle:
            bad, grey = _suppress_sites(handle.read(), "sysprobe/" + name)
        files += 1
        hits += bad
        unclear += grey
    ok.append(case("源码里没有一处红黄结论带着抑制位出生", not hits,
                   "、".join(hits) if hits else "已读 %d 个文件" % files))
    print("   判不出状态的抑制位 %d 处（状态是变量，需人工看）：%s"
          % (len(unclear), "、".join(unclear) if unclear else "无"))
    return all(ok)


def F(module, kind, status):
    return Finding(module=module, kind=kind, status=status, headline="占位标题")


HIST_SETS = {
    "same": [F("network", "proxy", Status.GREEN), F("storage", "space", Status.GREEN)],
    "worse": [F("network", "proxy", Status.YELLOW),
              F("storage", "space", Status.GREEN)],
    "seen": [F("network", "proxy", Status.YELLOW), F("storage", "space", Status.GREEN),
             F("audio", "device", Status.GREEN)],
    "blind": [F("network", "proxy", Status.YELLOW), F("storage", "space", Status.GREEN),
              F("audio", "device", Status.GRAY)],
}


def history_check():
    """The compare layer, checked where a live scan cannot reach it.

    A smoke run only ever sees this machine's one branch. Here the shapes are
    invented, including the two that must never be reported as health: a
    reading that only became visible, and a previous scan taken under another
    version or another permission level. Written entirely into a temporary
    folder - the program's own history file is not touched by a test.
    """
    print("\n== 历史对比（同机器不重跑也能验的几档）==")
    ok = []
    same_a = history.build(HIST_SETS["same"], "1.1.0", "r1", False)
    same_b = history.build(HIST_SETS["same"], "1.1.0", "r1", False)
    full, short = history.describe(same_a, same_b)
    ok.append(case("结论没变时只说“没变化”，不编出数字",
                   full == "结论和上次一条没变。" and short == "没变化", full))

    worse = history.build(HIST_SETS["worse"], "1.1.0", "r1", False)
    full, short = history.describe(same_a, worse)
    ok.append(case("一项转黄：短句报数、长句点名是哪项",
                   short == "建议留意多 1 项" and "网络上网" in full,
                   "%s ｜ %s" % (short, full)))

    blind = history.build(HIST_SETS["blind"], "1.1.0", "r1", False)
    seen = history.build(HIST_SETS["seen"], "1.1.0", "r1", False)
    full, _s = history.describe(blind, seen)
    ok.append(case("看不到的项变能看到，不算变好也不算变坏",
                   "比上次好" not in full and "比上次差" not in full
                   and "这次能看到了" in full, full))

    moved = history.describe(same_a, history.build(HIST_SETS["same"],
                                                  "9.9.9", "r1", False))
    prev, why = history.pick([dict(same_a, ver="9.9.9")], same_b)
    ok.append(case("版本对不上时不比较", prev is None and why == "nomatch",
                   str(moved[1])))
    prev, why = history.pick([dict(same_a, admin=True)], same_b)
    ok.append(case("权限对不上时也不比较", prev is None and why == "nomatch"))

    tmp = os.path.join(tempfile.mkdtemp(prefix="sysprobe_hist_"), history.NAME)
    rec = same_b
    for _i in range(14):
        history.save(tmp, rec, history.load(tmp)[0] if os.path.isfile(tmp) else [])
    scans, state = history.load(tmp)
    text = open(tmp, "rb").read()
    ok.append(case("记录只留 %d 次（灌了 14 次）" % history.KEEP,
                   state == "ok" and len(scans) == history.KEEP,
                   "%d 条 / %d 字节" % (len(scans), len(text))))
    ok.append(case("这份文件里没有一句人话（零隐私靠形状，不靠替换）",
                   max(text) < 0x80 and "占位" not in text.decode("utf-8", "replace"),
                   "%d 字节，纯 ASCII" % len(text)))

    data = json.loads(text.decode("utf-8"))
    data["scans"][0]["worst"]["network"] = "purple"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False)
    scans, state = history.load(tmp)
    ok.append(case("手改脏的记录被丢掉，其余照常能用",
                   state == "ok" and len(scans) == history.KEEP - 1,
                   "可用 %d 条" % len(scans)))
    data["schema"] = 99
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False)
    scans, state = history.load(tmp)
    ok.append(case("看不懂的模式号就当没有记录，不瞎比",
                   state == "schema" and not scans, str(state)))
    return all(ok)


def main():
    ctx = build_ctx()
    print("SysProbe-Lite selftest  |  python %s  |  %s  |  win11=%s"
          % (sys.version.split()[0], probes.os_label(), ctx.win11))
    if ctx.rules.load_error:
        print("规则库回退内置：%s" % ctx.rules.load_error)
    print("规则库版本 %s（%s 校订）" % (ctx.rules.version, ctx.rules.reviewed))
    ps = native.power_status()
    print("电池断言: %r" % (ps,))

    findings = run_probes(ctx)
    san = Sanitizer()
    encoding_check()
    show(findings, san)
    ok = (sanitizer_check() and live_identity_check(findings)
          and collectors_check() and skip_invariant_check()
          and history_check())
    print("\n合计 %d 条结论，脱敏 %d 处，回归%s"
          % (len(findings), sum(san.stats.values()), "通过" if ok else "失败"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
