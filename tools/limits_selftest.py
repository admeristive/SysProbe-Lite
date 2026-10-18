"""Offline self-test for sysprobe/limits.py.

Nothing here touches the real system except the last timing section: every
failure mode is simulated by swapping the two objects the module talks to
(`native` and `winreg`), so a missing key, a refused key, a boundary number and
a raising API call are all reproducible. The point being proven is the fail-soft
promise: no input shape may make a probe raise.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# The wording checks borrow the release gate's own patterns instead of typing
# them out again: writing "reg delete" here to prove it is absent is itself a
# hit in that gate, and a gate you have to weaken to test is not a gate.
from check_no_network import BANNED_STRINGS as GATE_BANNED_STRINGS    # noqa: E402

from sysprobe import limits                                     # noqa: E402
from sysprobe.model import Status                               # noqa: E402

FAILS = []
TOTAL = 0


def case(name, cond, detail=""):
    global TOTAL
    TOTAL += 1
    print("  [%s] %s%s" % ("通过" if cond else "不通过", name,
                           "" if cond or not detail else "  <- %s" % detail))
    if not cond:
        FAILS.append(name)


def no_more():
    """The exact exception real winreg raises once the index runs past the end.

    Measured on this machine (Windows 11, 10.0.26300) for both EnumKey and
    EnumValue: OSError with winerror=259, errno=22, strerror
    '没有可用的数据了。'. errno alone is 22 for several unrelated failures, so the
    number that distinguishes "end of list" from "refused" is winerror - a fake
    that gets this wrong hides the very bug the module is written to catch.
    """
    exc = OSError(22, "没有可用的数据了。")
    exc.winerror = 259
    return exc


def refused():
    """A mid-list refusal: same exception type, different winerror."""
    exc = OSError(5, "拒绝访问。")
    exc.winerror = 5
    return exc


class FakeWinReg(object):
    """Stands in for the winreg module: HKEY constants and scripted keys."""

    HKEY_LOCAL_MACHINE = 1
    HKEY_CURRENT_USER = 2
    HKEY_CLASSES_ROOT = 3
    KEY_READ = 8
    KEY_WOW64_64KEY = 256
    KEY_WOW64_32KEY = 512

    def __init__(self, error=None, keys=None, values=None, break_at=None,
                 defaults=None, keys32=None):
        self.error = error
        self.keys = keys or []
        self.values = values or []
        self.break_at = break_at
        self.defaults = defaults or {}
        self.keys32 = keys32

    def OpenKey(self, hive, path, reserved=0, access=0):
        if self.error is not None:
            raise self.error
        return ("key", path)

    def EnumKey(self, key, index):
        if self.break_at is not None and index == self.break_at:
            raise refused()
        if self.keys32 is not None and key[1] == limits._REG_OVERLAY_32:
            return self._at(self.keys32, index)
        return self._at(self.keys, index)

    def EnumValue(self, key, index):
        if self.break_at is not None and index == self.break_at:
            raise refused()
        return self._at(self.values, index)

    def QueryValueEx(self, key, name):
        table = self.defaults.get(key[1]) or self.defaults.get("*") or {}
        if name not in table:
            raise no_more()
        return table[name], 1

    @staticmethod
    def _at(seq, index):
        try:
            return seq[index]
        except IndexError:
            raise no_more()

    def CloseKey(self, key):
        pass


class FakeNative(object):
    def __init__(self, memory=None, owners=None, usage=None, path=None,
                 paging=None, modes=None, apps=None, audio=None, nic=None,
                 raise_where=()):
        self.memory = memory
        self.owners = owners if owners is not None else []
        self.usage = usage or {}
        self.path = path or {}
        self.paging = paging
        self.modes = modes
        self.apps = apps
        self.audio = audio
        self.nic = nic
        self.raise_where = set(raise_where)

    def memory_commit(self):
        if "memory" in self.raise_where:
            raise RuntimeError("simulated API blow-up")
        return self.memory

    def paging_declaration(self):
        if "paging" in self.raise_where:
            raise RuntimeError("simulated registry blow-up")
        return self.paging

    def window_owners(self, cap=80):
        if "owners" in self.raise_where:
            raise RuntimeError("simulated enumeration blow-up")
        return self.owners

    def draw_usage(self, pid):
        if pid in self.raise_where:
            raise RuntimeError("simulated handle blow-up")
        return self.usage.get(pid)

    def image_path(self, pid):
        return self.path.get(pid)

    def display_modes(self):
        if "modes" in self.raise_where:
            raise RuntimeError("simulated display blow-up")
        return self.modes

    def installed_programs(self):
        if "apps" in self.raise_where:
            raise RuntimeError("simulated uninstall sweep blow-up")
        return self.apps

    def audio_endpoint_states(self):
        if "audio" in self.raise_where:
            raise RuntimeError("simulated endpoint sweep blow-up")
        return self.audio

    def network_adapters(self):
        if "nic" in self.raise_where:
            raise RuntimeError("simulated class key blow-up")
        return self.nic


REAL_NATIVE = limits.native
MB = 1024 ** 3


# The four device probes read payload shapes the real collector builds, so the
# fakes below build the same shapes and recompute the same derived booleans. A
# fake that got the mask wrong would let a probe pass by testing nothing.
def MODE(hz, top, w=2560, h=1600, primary=True, adapter="Test GPU", tiers=24):
    return {"device": "\\\\.\\DISPLAY1", "adapter": adapter, "primary": primary,
            "current": {"width": w, "height": h, "hz": hz, "bpp": 32},
            "ceiling_hz": top, "gap": top - hz, "tiers": tiers,
            "best_any": max(top, hz)}


def APP(name, date="", publisher="A Vendor", version="1.0", scope="machine64",
        size_mb=100.0):
    return {"name": name, "publisher": publisher, "version": version,
            "installed_on": date, "size_mb": size_mb, "scope": scope}


def BOOK(rows, unreadable=0, truncated=False):
    """The collector returns its own honesty fields; a fake without them would
    never prove the probe reads them."""
    return {"rows": rows, "unreadable": unreadable, "truncated": truncated}


def EP(kind, state):
    row = {"kind": kind, "state": state}
    for label, bit in (("active", 0x1), ("disabled", 0x2),
                       ("not_streaming", 0x4), ("unplugged", 0x8)):
        row[label] = bool(state & bit)
    return row


def NIC(name, mask, if_type=6):
    row = {"name": name, "characteristics": mask, "if_type": if_type}
    for label, bit in (("virtual", 0x0001), ("physical", 0x0004),
                       ("hidden", 0x0008), ("no_service", 0x0010),
                       ("not_user_removable", 0x0020), ("has_ui", 0x0080)):
        row[label] = bool(mask & bit)
    return row


class FakeRules(object):
    """A probe only ever calls match_bad, so that is the whole contract here."""

    def __init__(self, entries=()):
        self.entries = list(entries)

    def match_bad(self, item):
        for entry in self.entries:
            if entry.get("name") and entry["name"] == item.get("name"):
                return entry
        return None


class Ctx(object):
    def __init__(self, entries=()):
        self.rules = FakeRules(entries)


def swap(winreg_obj=None, native_obj=None):
    if winreg_obj is not None:
        limits.winreg = winreg_obj
    if native_obj is not None:
        limits.native = native_obj


def restore():
    limits.winreg = RealWinReg
    limits.native = REAL_NATIVE


import winreg as RealWinReg                                     # noqa: E402


def one(got):
    return got[0] if got else None


# ---------------------------------------------------------------- A: badges

print("== A 图标角标槽位 ==")
swap(winreg_obj=FakeWinReg(error=FileNotFoundError(2, "no key")))
got = limits.probe_badges(None)
case("位置不存在 -> 正常且不弹出底层细节",
     one(got).status == Status.GREEN and one(got).skip)

swap(winreg_obj=FakeWinReg(error=PermissionError(5, "denied")))
got = limits.probe_badges(None)
case("没有权限 -> 降级为未获取", one(got).status == Status.GRAY)

twelve = ["\t\tOneDrive1", " OneDrive2", "MEGA3", " Dropbox1", " 坚果云",
          "BaiduSync1", "{472083B0-878C-11D0-840B-0000E8900C33}",
          "SharePoint7", "YandexDisc", "IDM Shell Extension",
          "BoxShellExt Overlay Handler", "TencentWeiyun"]
swap(winreg_obj=FakeWinReg(keys=twelve))
got = limits.probe_badges(None)
f = one(got)
case("12 个占位 -> 建议留意", f.status == Status.YELLOW, str(f.status))
case("超出时给出可照做的步骤（>=3 步）", len(f.steps) >= 3)
case("native 里记下了真实计数", f.native.get("count") == 12, str(f.native))
case("看不出差别的编号名不混进文案", "{472083" not in f.plain)
case("超出那一行不折叠", not f.skip)

swap(winreg_obj=FakeWinReg(keys=twelve[:11]))
case("11 个（边界值）-> 仍算正常",
     one(limits.probe_badges(None)).status == Status.GREEN)

swap(winreg_obj=FakeWinReg(keys=["\tReal", " Normal", "Plain"]))
f = one(limits.probe_badges(None))
case("没超总数但有人在抢前排 -> 正常行不折叠，并如实写明",
     f.status == Status.GREEN and not f.skip and "2 个" in f.plain, f.plain)

swap(winreg_obj=FakeWinReg(keys=["{A1B2C3D4-E5F6-4A7B-9C8D-1E2F3A4B5C6D}",
                                 "{00000000-0000-0000-0000-000000000000}"]))
f = one(limits.probe_badges(None))
case("全是编号名也不会算错", f.native.get("count") == 2 and f.native.get("readable") == [],
     str(f.native))

tab = "\t\t\tIDM Shell Extension"
clsid = "{CDC95B92-E27C-4745-A8C5-64A52A78855D}"
dll = "C:\\Program Files (x86)\\Internet Download Manager\\IDMShellExt64.dll"
swap(winreg_obj=FakeWinReg(
    keys=[tab, "Plain"],
    defaults={limits._path(limits._REG_OVERLAY, tab): {"": clsid},
              limits._path("SOFTWARE", "Classes", "CLSID", clsid,
                           "InprocServer32"): {"": dll}}))
f = one(limits.probe_badges(None))
case("抢前排的那个能认到是谁家的程序",
     f.native.get("owners", {}).get(tab.strip()) == "IDMShellExt64.dll",
     str(f.native.get("owners")))
case("认归属用的路径不会漏进对外文案",
     "Internet Download Manager" not in f.plain + f.headline + "".join(f.steps))

swap(winreg_obj=FakeWinReg(keys=["a", "b"], keys32=[
    "z", "y", "x", "w", "v", "u", "t", "s", "r", "q", "p", "o", "n", "m"]))
f = one(limits.probe_badges(None))
case("只登记在另一套视图里的 14 项不算进争抢总数",
     f.status == Status.GREEN and f.native.get("count") == 2
     and f.native.get("registered_32bit") == 14, str(f.native))

swap(winreg_obj=FakeWinReg(keys=["a", "b", "c"], break_at=1))
case("读到一半被拒绝 -> 不许当成「到底了」少报",
     one(limits.probe_badges(None)).status == Status.GRAY)

# --------------------------------------------------------------- B: paging

print("\n== B 虚拟内存 ==")
swap(native_obj=FakeNative(raise_where=("memory",)))
case("读取函数炸了 -> 降级为未获取",
     one(limits.probe_paging(None)).status == Status.GRAY)

swap(native_obj=FakeNative(memory=None))
case("接口返回空 -> 降级为未获取",
     one(limits.probe_paging(None)).status == Status.GRAY)

swap(native_obj=FakeNative(memory={"total_phys": 16 * MB, "total_commit": 16 * MB,
                                   "avail_commit": 4 * MB, "load_percent": 40}))
f = one(limits.probe_paging(None))
case("分页完全关闭 -> 建议留意", f.status == Status.YELLOW)
case("给出图解步骤而非术语",
     len(f.steps) >= 4 and "设置" in "".join(f.steps))

swap(native_obj=FakeNative(memory={"total_phys": 16 * MB,
                                   "total_commit": int(16 * MB * 1.04),
                                   "avail_commit": 4 * MB, "load_percent": 40}))
case("略高于物理内存（边界）-> 仍算异常",
     one(limits.probe_paging(None)).status == Status.YELLOW)

swap(native_obj=FakeNative(memory={"total_phys": 16 * MB,
                                   "total_commit": int(16 * MB * 1.06),
                                   "avail_commit": 4 * MB, "load_percent": 40}))
case("正常分页（边界外一点）-> 正常并折叠",
     one(limits.probe_paging(None)).status == Status.GREEN)

R16 = {"total_phys": 16 * MB, "total_commit": 40 * MB,
       "avail_commit": 20 * MB, "load_percent": 30}
swap(native_obj=FakeNative(memory=R16,
                           paging={"declared": ["c:\\pagefile.sys 24576 32768"],
                                   "attached": ["\\??\\C:\\pagefile.sys"]}))
f = one(limits.probe_paging(None))
case("声明并挂载在 C 盘 -> 正常，并写明在哪个盘",
     f.status == Status.GREEN and "C 盘" in f.plain, f.plain)

swap(native_obj=FakeNative(memory=R16,
                           paging={"declared": ["d:\\pagefile.sys 8192 16384"],
                                   "attached": ["\\??\\D:\\pagefile.sys"]}))
f = one(limits.probe_paging(None))
case("分页文件放在非系统盘也算正常（多驱动器判据）",
     f.status == Status.GREEN and "D 盘" in f.plain, f.plain)

swap(native_obj=FakeNative(memory=R16, paging={"declared": ["*:AUTO"],
                                               "attached": []}))
f = one(limits.probe_paging(None))
case("声明自动管理但一个都没挂上 -> 建议留意",
     f.status == Status.YELLOW and f.kind == "paging_off", "%s/%s" % (f.kind, f.status))

swap(native_obj=FakeNative(memory=R16,
                           paging={"declared": ["*:AUTO"]}))
case("只读得到声明、读不到挂载 -> 按声明判定，不误报关闭",
     one(limits.probe_paging(None)).status == Status.GREEN)

swap(native_obj=FakeNative(memory=R16, paging=None,
                           raise_where=("paging",)))
case("声明位置整个炸了 -> 退回比值判据，不崩溃",
     one(limits.probe_paging(None)).status == Status.GREEN)

swap(native_obj=FakeNative(memory={"total_phys": 16 * MB,
                                   "total_commit": int(16 * MB * 1.04),
                                   "avail_commit": 4 * MB, "load_percent": 40,},
                           paging={"declared": ["c:\\pagefile.sys 512 512"],
                                   "attached": ["\\??\\C:\\pagefile.sys"]}))
f = one(limits.probe_paging(None))
case("分页挂着但只给一点点 -> 建议留意（不是「已关闭」）",
     f.status == Status.YELLOW and f.kind == "paging_tiny",
     "%s/%s" % (f.kind, f.status))
case("这种情况不许写成「等于没给」",
     "等于没给" not in f.headline, f.headline)

# ------------------------------------------------------------- C: tool locks

print("\n== C 系统工具锁定 ==")
DWORD = 4  # 真 winreg 的 EnumValue 恒返回（名字, 数值, 类型）三元组，
           # 假货必须照抄这个形状，否则探针解包失败会把每条用例都伪装成降级。
swap(winreg_obj=FakeWinReg(values=[("DisableTaskMgr", 1, DWORD),
                                   ("EnableLUA", 1, DWORD)]))
got = limits.probe_locks(None)
f = one(got)
case("数值 1 -> 需处理", f.status == Status.RED, str(f.status))
case("抓出了是哪个工具被锁", "任务管理器" in f.headline)
case("报告里带着位置和开关名",
     f.native.get("value") == "DisableTaskMgr" and f.native.get("site"))
case("解锁动作交给人、不由本程序执行",
     any("不会替你改动" in x for x in f.steps))

swap(winreg_obj=FakeWinReg(values=[("DisableRegistryTools", "1", 2)]))
case("文本形式的 1 也认（脚本书写差异）",
     one(limits.probe_locks(None)).status == Status.RED)

swap(winreg_obj=FakeWinReg(values=[("DisableCMD", 0, DWORD),
                                   ("DisableCMD2", 1, DWORD)]))
f = one(limits.probe_locks(None))
case("数值 0 不算锁定", f.status == Status.GREEN and f.skip)

swap(winreg_obj=FakeWinReg(values=[("disabletaskmgr", 1, DWORD)]))
f = one(limits.probe_locks(None))
case("开关名大小写乱写也认（第三方脚本常这样）", f.status == Status.RED, str(f.status))
case("锁定那一行不折叠，必须让人看见", not f.skip)

swap(winreg_obj=FakeWinReg(values=[("DisableTaskMgr", 1, DWORD)], break_at=1))
case("值列表读到一半被拒绝 -> 未获取，不许当成「只有这些值」",
     one(limits.probe_locks(None)).status == Status.GRAY)

swap(winreg_obj=FakeWinReg(values=[("DisableTaskMgr", 1, DWORD)]))
f = one(limits.probe_locks(None))
glued = "".join(f.steps)
case("给了组策略路线", "组策略" in glued and "未配置" in glued)
case("给了家庭版能走的路线", "regedit" in glued and "家庭版" in glued)
case("写清楚选「未配置」而不是「已启用」", "而不是「已启用」" in glued)
case("全程没有可复制的注册表写入命令",
     not [p for p, _why in GATE_BANNED_STRINGS if re.search(p, glued, re.I)],
     glued[:60])
case("步骤条数对得起「图解级」这三个字", len(f.steps) >= 6, "%d 步" % len(f.steps))

swap(winreg_obj=FakeWinReg(error=PermissionError(5, "denied")))
case("全部位置无权限 -> 未获取，不谎报正常",
     one(limits.probe_locks(None)).status == Status.GRAY)

swap(winreg_obj=FakeWinReg(error=FileNotFoundError(2, "no key")))
case("全部位置不存在 -> 正常且折叠",
     one(limits.probe_locks(None)).status == Status.GREEN)

swap(winreg_obj=FakeWinReg(keys=[], values=[("DisableTaskMgr", 1, DWORD)]))
sites = limits._POLICY_SITES
limits._POLICY_SITES = sites * 2
got = limits.probe_locks(None)
case("同一工具被两处重复锁定 -> 只报一条", len(got) == 1 and got[0].status == Status.RED,
     "%d 条 / %s" % (len(got), got[0].status))
limits._POLICY_SITES = sites
restore()

# ----------------------------------------------------------- D: draw budget

print("\n== D 软件界面资源 ==")
swap(native_obj=FakeNative(owners=[]))
case("一个窗口属主都找不到 -> 未获取",
     one(limits.probe_draw(None)).status == Status.GRAY)

swap(native_obj=FakeNative(owners=[(11, 3), (22, 1)], usage={}))
case("全部拒绝查看 -> 未获取，不谎报正常",
     one(limits.probe_draw(None)).status == Status.GRAY)

swap(native_obj=FakeNative(owners=[(11, 3), (22, 1)],
                           usage={11: (8001, 900), 22: (400, 120)},
                           path={11: "C:\\Games\\demo\\leaky.exe"}))
f = one(limits.probe_draw(None))
case("超过警戒线 -> 需处理", f.status == Status.RED, str(f.status))
case("点名是哪个软件", "leaky.exe" in f.headline, f.headline)
case("给了立刻能做的处置",
     any("关掉" in s and "打开" in s for s in f.steps), "".join(f.steps))

swap(native_obj=FakeNative(owners=[(11, 3)], usage={11: (8000, 900)}))
case("正好卡在上限数字（边界）-> 不算需处理",
     one(limits.probe_draw(None)).status == Status.GREEN)

swap(native_obj=FakeNative(owners=[(11, 3), (22, 1), (33, 2)],
                           usage={11: (120, 30), 33: (900, 400)},
                           path={}))
f = one(limits.probe_draw(None))
case("个别进程读不到不影响整体结论",
     f.status == Status.GREEN and f.native.get("measured") == 2)
case("安全水位时记下最高占用", f.native.get("peak_gdi") == 900, str(f.native))
case("附注里能看出总共看过几个属主",
     f.native.get("seen_owners") == 3, str(f.native))

swap(native_obj=FakeNative(owners=[(11, 3), (22, 1)],
                           usage={22: (700, 50)}, raise_where={11}))
case("单进程调用抛异常 -> 被吞掉，整条仍能出结论",
     one(limits.probe_draw(None)).status == Status.GREEN)

restore()

# ------------------------------------------------------- E: refresh ceiling

print("\n== E 屏幕刷新率 ==")
swap(native_obj=FakeNative(raise_where=("modes",)))
case("读取函数炸了 -> 未获取",
     one(limits.probe_refresh(None)).status == Status.GRAY)

swap(native_obj=FakeNative(modes=None))
case("一块屏幕都报不上来 -> 未获取，不许当成「没有屏幕」",
     one(limits.probe_refresh(None)).status == Status.GRAY)

swap(native_obj=FakeNative(modes=[MODE(0, 0)]))
f = one(limits.probe_refresh(None))
case("驱动上报 0 Hz -> 未获取，不许写成「跑在 0 Hz」",
     f.status == Status.GRAY and "0 Hz" not in f.headline, f.headline)

swap(native_obj=FakeNative(modes=[MODE(60, 240)]))
f = one(limits.probe_refresh(None))
case("高刷屏被按 60 Hz 跑着 -> 建议留意", f.status == Status.YELLOW, str(f.status))
case("标题里现在与最高两个数字都给", "60 Hz" in f.headline and "240 Hz" in f.headline,
     f.headline)
case("步骤里直接写着要选哪一档", any("240 Hz" in s for s in f.steps))
case("留了「画面黑了别乱按键」这一条",
     any("什么键都不用按" in s for s in f.steps), "".join(f.steps))
case("改砸了自己能退回、且不动驱动这一点写明了",
     any("只动显示设置" in s for s in f.steps), "".join(f.steps))
case("这一行不许折叠", not f.skip)
case("条数对得起图解级", len(f.steps) >= 6, "%d 步" % len(f.steps))
case("附注留下分辨率与两档数字",
     f.native.get("now_hz") == 60 and f.native.get("ceiling_hz") == 240
     and "2560" in str(f.native.get("size")), str(f.native))

swap(native_obj=FakeNative(modes=[MODE(60, 75)]))
f = one(limits.probe_refresh(None))
case("只差一档（60 对 75）-> 不许惊动新手", f.status == Status.GREEN and f.skip,
     str(f.status))

swap(native_obj=FakeNative(modes=[MODE(60, 90)]))
case("差 30 Hz（边界值）-> 建议留意",
     one(limits.probe_refresh(None)).status == Status.YELLOW)

swap(native_obj=FakeNative(modes=[MODE(240, 240)]))
case("已在最高档 -> 正常且折叠",
     one(limits.probe_refresh(None)).status == Status.GREEN)

swap(native_obj=FakeNative(modes=[MODE(60, 240),
                                  MODE(144, 144, w=3840, h=2160, primary=False)]))
got = limits.probe_refresh(None)
case("两块屏只点出问题那一块", len(got) == 1 and got[0].status == Status.YELLOW,
     "%d 条" % len(got))
case("点名时说清是主屏", "主屏" in got[0].headline, got[0].headline)

swap(native_obj=FakeNative(modes=[MODE(240, 240),
                                  MODE(60, 165, w=1920, h=1080, primary=False)]))
got = limits.probe_refresh(None)
case("出问题的若是副屏，写成「第 2 块屏幕」",
     len(got) == 1 and "第 2 块屏幕" in got[0].headline, got[0].headline)

swap(native_obj=FakeNative(modes=[MODE(60, 240), MODE(0, 0)]))
got = limits.probe_refresh(None)
case("有一块屏说不清不影响另一块下结论",
     len(got) == 1 and got[0].status == Status.YELLOW, str(got))
restore()

# --------------------------------------------------- F: installed software

print("\n== F 已装软件 ==")
swap(native_obj=FakeNative(raise_where=("apps",)))
case("清单整个读不到 -> 未获取", one(limits.probe_apps(None)).status == Status.GRAY)

swap(native_obj=FakeNative(apps=BOOK([])))
case("读到但一条记录都没有 -> 未获取，不许报「一个软件都没装」",
     one(limits.probe_apps(None)).status == Status.GRAY)

BAD_ENTRY = {"name": "某推广组件", "exe": "junk.exe",
             "plain": "这一条写在规则库的名单里，用来弹广告",
             "why": "名单点过名的才处理",
             "steps": ["在「设置 → 应用 → 已安装的应用」里卸载它"]}
swap(native_obj=FakeNative(apps=BOOK([APP("某推广组件"), APP("浏览器")])))
got = limits.probe_apps(Ctx([BAD_ENTRY]))
f = got[0]
case("名单命中 -> 需处理", f.status == Status.RED, str(f.status))
case("红标的文案取自规则库那一条，不是程序自己编的",
     f.plain == BAD_ENTRY["plain"] and f.steps == BAD_ENTRY["steps"], f.plain)
case("命中时另起一条折叠行交代其余",
     len(got) == 2 and got[1].skip and got[1].status == Status.GREEN, "%d 条" % len(got))
case("其余那些不许被说成「安全」", "安全" not in got[1].plain + got[1].headline,
     got[1].plain)
case("红行不借用「官方地址」栏塞命令", not f.copy_cmd)

swap(native_obj=FakeNative(apps=BOOK([APP("浏览器"), APP("输入法")])))
f = one(limits.probe_apps(Ctx([{"name": "某个没装的组件", "exe": "x.exe"}])))
case("名单里的名字本机没装着 -> 一条红标都不许凭空造",
     f.status == Status.GREEN and f.skip, str(f.status))
case("绿行交代了判据的边界（整名比对、不靠猜）",
     "整名" in f.why and "宁可漏" in f.why, f.why)

f = one(limits.probe_apps(None))
case("没有规则库时也不许崩（探针被单独调用就是这种情况）",
     f.status == Status.GREEN)

TODAY = time.strftime("%Y%m%d")
LONG_AGO = time.strftime("%Y%m%d", time.localtime(time.time() - 400 * 86400))
swap(native_obj=FakeNative(apps=BOOK([APP("新装的浏览器", date=TODAY),
                                      APP("老软件", date=LONG_AGO),
                                      APP("日期写错到将来的", date="20380119"),
                                      APP("没写日期的")])))
f = one(limits.probe_apps(None))
case("近三个月只数真在那三个月里的", f.native.get("recent_total") == 1, str(f.native))
case("将来日期不算「刚装的」", "将来" not in str(f.native.get("last_90d")),
     str(f.native.get("last_90d")))
case("最近装的那几个名字是印得出的一行，不是一条被丢掉的列表",
     isinstance(f.native.get("last_90d"), str) and "新装的浏览器" in f.native["last_90d"],
     str(f.native.get("last_90d")))

swap(native_obj=FakeNative(apps=BOOK([APP("甲", scope="user"), APP("乙"),
                                      APP("丙", scope="user")])))
f = one(limits.probe_apps(None))
case("只装在当前用户名下的数量单独说", "其中 2 个只装在当前" in f.plain, f.plain)

swap(native_obj=FakeNative(apps=BOOK([APP("甲")], truncated=True)))
f = one(limits.probe_apps(None))
case("有一处没读完 -> 文案承认清单可能偏少",
     "可能偏少" in f.plain and f.native.get("incomplete"), f.plain)

swap(native_obj=FakeNative(apps=BOOK([APP("甲")], unreadable=7)))
f = one(limits.probe_apps(None))
case("有 7 处打不开 -> 写进文案，不许装作读全了",
     "7 处" in f.plain and f.native.get("unreadable") == 7, f.plain)
restore()

# -------------------------------------------------------- G: sound endpoints

print("\n== G 声音设备 ==")
swap(native_obj=FakeNative(raise_where=("audio",)))
case("读取函数炸了 -> 未获取", one(limits.probe_audio(None)).status == Status.GRAY)

swap(native_obj=FakeNative(audio=BOOK([])))
case("登记处一个端点都没有 -> 未获取",
     one(limits.probe_audio(None)).status == Status.GRAY)

swap(native_obj=FakeNative(audio=BOOK([EP("play", 0x2), EP("play", 0x22000002)])))
got = [x for x in limits.probe_audio(None) if x.kind == "audio_disabled"]
f = got[0]
case("播放设备全被停用 -> 需处理", f.status == Status.RED, str(f.status))
case("带高位的复合停用值也认（判据是掩码不是相等）", f.native.get("disabled") == 2,
     str(f.native))
case("标题说的是「全部被停用」这种可核对的话", "全部被停用" in f.headline, f.headline)
case("一路写到要勾「显示禁用的设备」那一层",
     any("显示禁用的设备" in s for s in f.steps), "".join(f.steps))
case("说清只做启用与设为默认这两下",
     any("只做启用与设为默认" in s for s in f.steps))
case("上面这层找不到时给了设备管理器那条",
     any("设备管理器" in s for s in f.steps))
case("停用这一行不许折叠", not f.skip)
case("条数对得起图解级", len(f.steps) >= 6, "%d 步" % len(f.steps))

swap(native_obj=FakeNative(audio=BOOK([EP("record", 0x2), EP("record", 0x2)])))
got = [x for x in limits.probe_audio(None) if x.kind == "audio_disabled"]
case("麦克风全停用只标黄：这台可能根本不用麦克风",
     len(got) == 1 and got[0].status == Status.YELLOW,
     str(got and got[0].status))
case("这条黄行允许人放着不动",
     "放着不动" in got[0].plain, got[0].plain)

swap(native_obj=FakeNative(audio=BOOK([EP("play", 0x22000004), EP("play", 0x4),
                                       EP("play", 0x1), EP("record", 0x8)])))
got = limits.probe_audio(None)
case("空闲与没插都不算停用：不许报成故障",
     len(got) == 2 and all(x.status == Status.GREEN for x in got),
     str([x.status for x in got]))
play = [x for x in got if x.native.get("count") == 3][0]
rec = [x for x in got if x.native.get("count") == 1][0]
case("有设备在活动就照实在活动那一头写",
     "活动状态" in play.plain, play.plain)
case("一个都没报活动时下另一句，不谎称在用",
     "没有一个报活动" in rec.plain and "在用" not in rec.headline, rec.plain)
case("没插东西的那个如实写成插拔状态", "插拔状态" in rec.plain, rec.plain)

swap(native_obj=FakeNative(audio=BOOK([EP("play", 0x1), EP("play", 0x2),
                                       EP("play", 0x2)])))
f = one(limits.probe_audio(None))
case("部分停用 -> 正常行里如实写出数量与去处",
     f.status == Status.GREEN and "另有 2 个当前是停用状态" in f.plain, f.plain)

swap(native_obj=FakeNative(audio=BOOK([EP("play", 0x22000000), EP("play", 0x100)])))
f = one(limits.probe_audio(None))
case("四个位都不沾的状态词 -> 未获取，不许猜是好是坏",
     f.status == Status.GRAY, str(f.status))
case("这种读不懂要留下一句解释", "不认识" in f.plain, f.plain)
restore()

# ---------------------------------------------------------------- H: nic

print("\n== H 网卡 ==")
swap(native_obj=FakeNative(raise_where=("nic",)))
case("读取函数炸了 -> 未获取", one(limits.probe_nic(None)).status == Status.GRAY)

swap(native_obj=FakeNative(nic=BOOK([])))
case("登记处整个读不到 -> 未获取", one(limits.probe_nic(None)).status == Status.GRAY)

PHYS = [NIC("Intel(R) Wi-Fi 6 AX201", 0x84, 71), NIC("Realtek PCIe GbE", 0x04, 6),
        NIC("WAN Miniport (IP)", 0x290029, 6),
        NIC("Wintun Userspace Tunnel", 0x10001, 6),
        NIC("Kernel Debug Network Adapter", 0x90009, 6)]
swap(native_obj=FakeNative(nic=BOOK(PHYS)))
f = one(limits.probe_nic(None))
case("有实体网卡 -> 正常且折叠", f.status == Status.GREEN and f.skip)
case("实体与虚拟各数各的",
     "Intel(R) Wi-Fi 6 AX201" in f.native.get("physical", "")
     and "Realtek PCIe GbE" in f.native.get("physical", "")
     and f.native.get("virtual") == 3, str(f.native))
case("报 6 号的虚拟卡不许算成实体（类型号做不了判据）",
     "WAN Miniport" not in f.native.get("physical", ""), str(f.native))
case("虚拟卡的名字留给帮忙的人看（也是一行标量）",
     "WAN Miniport (IP)" in f.native.get("virtual_names", "")
     and isinstance(f.native.get("virtual_names"), str), str(f.native.get("virtual_names")))
case("绿行先把「虚拟网卡多不是病」说在前面", "不是病" in f.plain, f.plain)

swap(native_obj=FakeNative(nic=BOOK(PHYS[2:])))
f = one(limits.probe_nic(None))
case("一块实体卡都没有 -> 建议留意，不是需处理", f.status == Status.YELLOW,
     str(f.status))
case("标题只说读到的那件事", "没有一个被标记为实体网卡" in f.headline, f.headline)
case("没有实体卡时附注写「无」，不留一条会被丢掉的空列表",
     f.native.get("physical") == "无", str(f.native.get("physical")))
case("虚拟机这种无辜解释写在人话里", "虚拟机" in f.plain, f.plain)
case("缺驱动与被禁用分成两条路给",
     "启用设备" in "".join(f.steps) and "驱动" in "".join(f.steps))
case("不暗示本程序会去下载安装", "不会替你下载" in "".join(f.steps))
case("不劝第三方驱动站", "驱动站" in "".join(f.steps))
case("这一行不许折叠", not f.skip)
case("文案里没有任何地址形状的数字",
     not re.search(r"(?:\d{1,3}\.){3}\d{1,3}", f.headline + f.plain + "".join(f.steps)))
case("不借用「官方地址」栏塞命令", not f.copy_cmd)

swap(native_obj=FakeNative(nic=BOOK([NIC("Realtek GbE", 0x04)], unreadable=2,
                                    truncated=True)))
f = one(limits.probe_nic(None))
case("有位置没读全 -> 附注与文案都承认",
     bool(f.native.get("incomplete")) and "未计入" in f.plain, str(f.native))

swap(native_obj=FakeNative(nic=BOOK([NIC("两个位都挂的卡", 0x15)])))
f = one(limits.probe_nic(None))
case("实体位在就按实体算，哪怕同时挂着虚拟位",
     f.status == Status.GREEN and f.native.get("physical") == "两个位都挂的卡"
     and f.native.get("virtual") == 1, str(f.native))
restore()

# ------------------------------------------------------- wording guarantee

print("\n== 小白文案闸（八项的全部对外文字）==")
# The word list is the release gate's own, shared with gui_smoke and
# tools/wording_check.py so a branch this machine never triggers cannot hide a
# word one of the three forgot about.
from wording_check import BANNED_WORDS as BANNED                 # noqa: E402
sample = []
swap(winreg_obj=FakeWinReg(keys=twelve))
sample += limits.probe_badges(None)
swap(winreg_obj=FakeWinReg(error=PermissionError(5, "x")))
sample += limits.probe_badges(None)
swap(native_obj=FakeNative(memory={"total_phys": 16 * MB, "total_commit": 16 * MB,
                                   "avail_commit": 1 * MB, "load_percent": 90}))
sample += limits.probe_paging(None)
swap(native_obj=FakeNative(memory={"total_phys": 16 * MB,
                                   "total_commit": 40 * MB,
                                   "avail_commit": 30 * MB, "load_percent": 20}))
sample += limits.probe_paging(None)
swap(winreg_obj=FakeWinReg(values=[("DisableTaskMgr", 1, DWORD)]))
sample += limits.probe_locks(None)
restore()
sample += limits.probe_draw(None)
swap(native_obj=FakeNative(owners=[(7777, 3)],
                           usage={7777: (9999, 9999)},
                           path={7777: "C:\\Tools\\leaky.exe"}))
sample += limits.probe_draw(None)
restore()
swap(native_obj=FakeNative(modes=[MODE(60, 240), MODE(0, 0, primary=False)]))
sample += limits.probe_refresh(None)
swap(native_obj=FakeNative(modes=[MODE(240, 240)]))
sample += limits.probe_refresh(None)
swap(native_obj=FakeNative(apps=BOOK([APP("某推广组件"), APP("浏览器"),
                                      APP("输入法", scope="user")], unreadable=3)))
sample += limits.probe_apps(Ctx([BAD_ENTRY]))
sample += limits.probe_audio(None)
swap(native_obj=FakeNative(audio=BOOK([EP("play", 0x2), EP("record", 0x2),
                                       EP("record", 0x22000002)])))
sample += limits.probe_audio(None)
swap(native_obj=FakeNative(audio=BOOK([EP("play", 0x4), EP("play", 0x8)])))
sample += limits.probe_audio(None)
sample += limits.probe_nic(None)
swap(native_obj=FakeNative(nic=BOOK(PHYS[2:])))
sample += limits.probe_nic(None)
swap(native_obj=FakeNative(nic=BOOK(PHYS)))
sample += limits.probe_nic(None)
restore()

case("文案闸的样本回答覆盖了八项，不是只重跑老四项",
     {f.module for f in sample} == {"badges", "paging", "toollocks", "drawlimits",
                                    "refresh", "applist", "audio", "nic"},
     str(sorted({f.module for f in sample})))
case("取样条数对得起八项（>=16 条）", len(sample) >= 16, "%d 条" % len(sample))

texts = []
for f in sample:
    texts += [f.headline, f.plain, f.why] + list(f.steps)
dirty = sorted({w for w in BANNED for t in texts if w.lower() in t.lower()})
case("对外文字零底层词汇", not dirty, str(dirty))
alltext = "".join(texts)
gate_hits = sorted({p for p, _why in GATE_BANNED_STRINGS
                    if re.search(p, alltext, re.I)})
case("对外文字按发布闸口的禁词表重扫 -> 零命中", not gate_hits, str(gate_hits))
case("八项都不借用\"官方地址\"栏塞命令",
     all(not f.copy_cmd for f in sample))

# ------------------------------------------------- the annex a helper reads
# The report's last column is deliberately raw so a helper can check numbers,
# but the three columns before it are read by the person holding the machine -
# they must not carry internal codenames. And the "去网页版最下面那一栏找位置"
# instruction only holds if the location actually renders there.
from sysprobe.report import html as _html                        # noqa: E402

annex = _html._tech_table(sample)
human = re.sub(r'<span class="tech">.*?</span>', "", annex, flags=re.S)
bad = sorted({w for w in BANNED if w.lower() in human.lower()})
case("附注前三栏零内部代号", not bad, str(bad))
case("附注不再单列内部线索代号", "线索类型" not in annex)
lock = [f for f in sample if f.module == "toollocks" and f.status == Status.RED]
raw = _html._tech_table(lock)
case("被锁那一行的位置与开关名确实印在最后一栏",
     bool(lock) and "DisableTaskMgr" in raw and "Policies" in raw)
case("附注说明了最后一栏可以跳过", "可以直接跳过" in annex)
case("解锁指引指向新手真能翻到的地方",
     any("网页版报告最下面那一栏" in s for f in lock for s in f.steps))

# The last column keeps scalars and throws away anything list-shaped (see
# html._tech_table). A clue written as a list is a clue the helper never sees, so
# the new four are checked against what actually renders, not against the dict
# they were built from.
NEW = ("refresh", "applist", "audio", "nic")
listing = [f for f in sample if f.module in NEW]
sloppy = [f.kind for f in listing if any(isinstance(v, (list, dict))
                                         for v in f.native.values())]
case("新四项取样条数对得起（>=8 条）", len(listing) >= 8, "%d 条" % len(listing))
case("新四项没把线索写成会被丢掉的列表", not sloppy, str(sloppy))
raw = _html._tech_table(listing)
case("附注里印得出刷新率的现在与最高两个数字",
     "now_hz=60" in raw and "ceiling_hz=240" in raw, raw[:180])
case("附注里印得出声音设备的停用数", "disabled=1" in raw or "disabled=2" in raw,
     raw[-200:])

swap(native_obj=FakeNative(apps=BOOK([APP("新装的浏览器", date=TODAY),
                                      APP("老软件", date=LONG_AGO)])))
printed = _html._tech_table(limits.probe_apps(None))
restore()
case("最近装的两个名字真能印在最后一栏", "新装的浏览器" in printed,
     re.sub(r"<[^>]+>", " ", printed)[:160])

swap(native_obj=FakeNative(nic=BOOK(PHYS)))
printed2 = _html._tech_table(limits.probe_nic(None))
restore()
case("实体与虚拟网卡的名字都真能印在最后一栏",
     "AX201" in printed2 and "WAN Miniport" in printed2,
     re.sub(r"<[^>]+>", " ", printed2)[:160])

old_lists = sorted({f.module for f in sample if f.module not in NEW
                    and any(isinstance(v, (list, dict)) for v in f.native.values())})
if old_lists:
    print("  已知遗留：%s 的附注里有列表型线索，最后一栏本来就印不出来（本批未动）"
          % "、".join(old_lists))

# ------------------------------------------------ privacy annex passthrough
# The new probes put file paths into the technical annex. Those paths can carry
# the account name (a per-user shell extension lives under the profile), so the
# annex must go through the same scrubbing the visible text does. The needles
# come from the environment at run time and nothing here prints an identity.
from sysprobe.sanitizer import Sanitizer                          # noqa: E402
from sysprobe.model import Finding as _F                          # noqa: E402

san = Sanitizer()
home = os.path.expanduser("~")
probe = _F(module="badges", status=Status.YELLOW, headline="h",
           native={"owner_path": home + r"\App\OneDriveSyncShell64.dll",
                   "pagefile": home + "\\pagefile.sys"})
clean = _F.from_dict(san.deep(probe.to_dict()))
case("技术附注里的路径也过脱敏闸（本机用户目录不再出现）",
     home not in str(clean.native))
# The installed-list annex carries display names and publishers, and a per-user
# install is registered under the profile: the same gate has to cover it.
appl = _F(module="applist", status=Status.RED, headline="h",
          native={"name": home, "publisher": home + r"\tools\junk",
                  "scope": "user"})
clean2 = _F.from_dict(san.deep(appl.to_dict()))
case("已装软件那一行的附注也过脱敏闸", home not in str(clean2.native),
     str(clean2.native)[:80])
case("脱敏计数确实动了（不是空跑）",
     san.summary() != "本次未发现需要隐藏的个人信息", san.summary())

# ------------------------------------------------------- real machine costs

print("\n== 本机实跑（只读）==")
from types import SimpleNamespace                                  # noqa: E402
from sysprobe import rules as _rules                               # noqa: E402
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ctx = SimpleNamespace(rules=_rules.load(ROOT))
t0 = time.perf_counter()
live = []
for pid, title, fn, _admin in limits.PROBES:
    s = time.perf_counter()
    rows = fn(ctx)
    live.extend(rows)
    print("  %-11s %s %6.2f ms  结论 %d 条 %s" % (
        pid, title, (time.perf_counter() - s) * 1000, len(rows),
        rows[0].status.value if rows else "-"))
cost = (time.perf_counter() - t0) * 1000
print("  八项合计 %.2f ms（预算 50 ms）" % cost)
case("八项合计在 50 ms 预算内", cost < 50.0, "%.2f ms" % cost)
case("本机实跑没有任何一项抛异常逃逸", all(live))
case("八项都真跑到了（本机各出一行以上）",
     len({f.module for f in live}) == 8, str(sorted({f.module for f in live})))
case("本机实跑的新四项附注也全是标量（印得出才算线索）",
     all(not isinstance(v, (list, dict)) for f in live if f.module in NEW
         for v in f.native.values()))
for f in live:
    if f.status in (Status.GRAY,) and f.kind == "probe_failed":
        print("  注意：%s 这一项本机降级为未获取（%s）" % (f.module, f.headline))

# A green light from a suite that asserted nothing is worse than a red one.
case("断言数量对得起这份自检（>=120 项）", TOTAL >= 120, "%d 项" % TOTAL)

if not FAILS:
    print("\n全部通过（%d 项断言）" % TOTAL)
    print("自检结论：八项探针在任何模拟故障下都没有把异常抛出去，全部降级为未获取。")
else:
    print("\n不通过 %d/%d 项：%s" % (len(FAILS), TOTAL, "、".join(FAILS)))
    sys.exit(1)
