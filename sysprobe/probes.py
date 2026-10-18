"""Read-only probes. Each returns a list of Finding and never raises.

Every channel used here was verified working without administrator rights on this
machine, except where a finding is explicitly marked needs_admin.
"""

import os
import re
import time
import winreg

from . import evtlog
from . import limits
from . import native
from .model import Finding, Status

# --------------------------------------------------------------------- helpers

_APPCODE = {
    "c000007b": ("软件版本不匹配（32 位与 64 位运行库混装）", "常见于游戏和老软件，补装微软运行库即可"),
    "c0000135": ("软件缺少运行库文件", "打不开时提示缺少某个程序文件，就是这一类"),
    "c0000139": ("软件的启动文件版本对不上", "多为运行库被覆盖，重装运行库可解"),
    "c0000142": ("软件启动时初始化失败", "常见于运行库或软件自身文件被改动"),
    "c0000005": ("软件读写了不该读的内存", "多数是软件/MOD/外挂自身的问题，不代表内存条坏了"),
    "c0000374": ("软件内存管理出错", "通常是某个软件自身缺陷，看它是哪个软件反复出现"),
    "c0000409": ("软件触发了安全保护而自行停止", "属于软件自身缺陷"),
    "c0000094": ("软件计算时除以了零", "属于软件自身缺陷"),
    "c0000022": ("软件没有权限访问某个文件", "可尝试放到不用管理员权限的文件夹，或右键以管理员运行"),
    "8007000e": ("软件申请内存时电脑已没有多余内存", "关闭其他大程序后再试"),
}

_BUGCHECK = {
    0x000000D1: ("驱动访问了不该访问的内存", "常见于网卡/显卡驱动过旧，或装了修改内核的软件"),
    0x00000050: ("内存读写越界", "常见于驱动问题；反复出现时再考虑内存条接触"),
    0x000000EF: ("系统关键进程被终止", "常见于软件冲突或系统文件被改动"),
    0x0000007E: ("系统服务出现异常", "常见于驱动兼容问题"),
    0x0000003B: ("系统服务出现异常", "常见于驱动兼容问题"),
    0x000000F4: ("系统关键对象被终止", "常见于存储链路（数据线/硬盘）或驱动问题"),
    0x0000009F: ("睡眠或唤醒时驱动未能正确响应", "建议到笔记本官网更新芯片组与显卡驱动"),
    0x0000007A: ("内核数据访问失败", "常见于磁盘或驱动问题"),
    0xC000021A: ("Windows 子系统异常", "常见于深度优化/美化类软件改动系统"),
    0x000000BE: ("驱动收到了不合法的请求", "常见于刚安装的驱动或硬件管理软件"),
    0x00000139: ("系统内部检查失败", "常见于驱动问题"),
    0x00000133: ("系统响应超时", "常见于驱动或存储设备响应过慢"),
}

_SOFT_BUGCHECK = {0x0000009F, 0x000000EF}

_IGPU = re.compile(r"(?i)\b(intel|uhd|iris|hd graphics|vga compatible|radeon graphics"
                   r"|amd radeon\(tm\) graphics)\b")
_DGPU = re.compile(r"(?i)\b(nvidia|geforce|rtx|gtx|quadro|radeon rx|rx \d|rtx a)\b")

_VCRUNTIME = ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")
_DIRECTX = ("d3dx9_43.dll", "XAudio2_7.dll", "xinput1_3.dll", "d3dcompiler_47.dll")
_VC_REDIST = "https://learn.microsoft.com/windows/cpp/windows/latest-supported-vc-redist"
_DX_ENDUSER = "https://www.microsoft.com/en-us/download/details.aspx?id=35"

_AUDIO_SVC = (("Audiosrv", "音频服务"), ("AudioEndpointBuilder", "音频设备管理服务"))
_NET_SVC = (("Dnscache", "DNS 解析服务"), ("Dhcp", "自动获取IP服务"))


def win11():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    except OSError:
        return False
    try:
        build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
        return int(build) >= 22000
    except (OSError, ValueError):
        return False
    finally:
        winreg.CloseKey(key)


def os_label():
    """ProductName is not trustworthy - on this machine it reads "Windows 10 Home"
    while CurrentBuildNumber is 26300. Derive the family from the build."""
    build, ubr = 0, 0
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        try:
            build = int(winreg.QueryValueEx(key, "CurrentBuildNumber")[0])
            try:
                ubr = int(winreg.QueryValueEx(key, "UBR")[0])
            except OSError:
                pass
        finally:
            winreg.CloseKey(key)
    except (OSError, ValueError):
        pass
    if not build:
        return "Windows"
    family = "Windows 11" if build >= 22000 else ("Windows 10" if build >= 10240 else "Windows")
    return "%s（内部版本 %s%s）" % (family, build, ".%d" % ubr if ubr else "")


def _first_int(row, *keys):
    for k in keys:
        v = row["data"].get(k, "")
        if v:
            return v
    return ""


def _is_desktop():
    ps = native.power_status()
    if ps is None:
        return None
    return not ps["has_battery"]


# ---------------------------------------------------------------- module A

def probe_stability(ctx):
    out = []
    rows = evtlog.query(*evtlog.XPATH["crash"], max_records=20)
    seen_bugcheck = set()

    for row in rows:
        if row["event_id"] == "1001" and row["provider"].startswith("Microsoft-Windows-WER"):
            code = _bugcheck_code(row)
            mod = _faulting_module(row)
            seen_bugcheck.add(row["time"][:13])
            known = _BUGCHECK.get(code)
            out.append(Finding(
                module="stability", status=Status.RED, kind="bsod",
                headline="电脑出现过蓝屏自动重启（共 %d 次记录）" % 1,
                plain=known[0] if known else "系统底层出现过一次异常停机",
                why=known[1] if known else "",
                steps=ctx.rules.steps("bsod", default=_BSOD_STEPS),
                copy_cmd="",
                native={"code": "0x%08x" % code if code is not None else "?",
                        "module": mod, "time": row["time"]},
            ))
        elif row["event_id"] == "41":
            if any(t.startswith(row["time"][:13]) for t in seen_bugcheck):
                continue
            out.append(Finding(
                module="stability", status=Status.YELLOW, kind="hardreset",
                headline="电脑出现过没有蓝屏记录的异常停机",
                plain="多为直接断电、长按电源键关机，或整机彻底卡死（卡死到来不及记录）",
                why="如果只出现过一两次且当时确实在强关机，可以不必处理",
                steps=_POWER_STEPS,
            ))
        elif row["event_id"] == "6008":
            out.append(Finding(
                module="stability", status=Status.GRAY, kind="unexpected_shutdown",
                headline="系统记录到一次非正常关机",
                plain="这与上面的蓝屏/断电是同一次事件时属于重复记录，无需重复处理",
                skip=True,
            ))

    if not any(f.kind in ("bsod", "hardreset") for f in out):
        out.append(Finding(
            module="stability", status=Status.GREEN, kind="no_crash",
            headline="近 30 天未发现意外重启记录",
            plain="没有蓝屏、也没有说不清的突然关机",
        ))

    whea_rows = evtlog.query(*evtlog.XPATH["whea"], max_records=20)
    fatal = [r for r in whea_rows if r["event_id"] in ctx.rules.whea_uncorrected]
    fixed = [r for r in whea_rows if r["event_id"] in ctx.rules.whea_corrected]
    other = [r for r in whea_rows if r["event_id"] not in ctx.rules.whea_uncorrected
             and r["event_id"] not in ctx.rules.whea_corrected]
    for r in fatal:
        out.append(Finding(
            module="stability", status=Status.RED, kind="whea_fatal",
            headline="底层硬件报出了无法自动修复的错误",
            plain="这类记录通常对应死机、自动重启或数据损坏",
            why="硬件本身问题的可能性较高",
            steps=["请先备份重要文件（复制到U盘或网盘）",
                  "如果最近加装过内存、固态硬盘或散热改装，先恢复原样再观察",
                  "备份完成后联系售后或维修点，把这份报告给对方看"],
            native={"time": r["time"], "id": r["event_id"]},
        ))
    if fixed:
        out.append(Finding(
            module="stability", status=Status.GREEN, kind="whea_corrected",
            headline="底层硬件通信轻微抖动（已自动修复，无需担心）",
            plain="主板把这类错误当场纠正过来了，共记录 %d 次，%s"
                  % (len(fixed), "属于长期存在的小毛病" if len(fixed) >= 10 else "偶尔几次可忽略"),
            why="多与总线信号噪声、内存轻微校验失败有关，不等于硬件已经坏",
            native={"count": len(fixed), "ids": sorted({r["event_id"] for r in fixed})},
        ))
    if other:
        out.append(Finding(
            module="stability", status=Status.YELLOW, kind="whea_unknown",
            headline="底层硬件记录到无法自动分类的错误（%d 条）" % len(other),
            plain="本机的错误分类规则还不能确定这些记录的严重程度，先不当成故障",
            steps=["观察是否伴随死机或自动重启；如果有，按上面的意外重启项目处理"],
            native={"ids": sorted({r["event_id"] for r in other})},
        ))
    if not whea_rows:
        out.append(Finding(
            module="stability", status=Status.GRAY, kind="whea_none",
            headline="硬件错误日志核对",
            plain="未发现硬件错误记录。要提醒的是：真正严重的硬件故障常常直接死机、来不及写日志，"
                  "所以\"没记录\"不等于\"一定没问题\"（这是诚实的限制，不是客套话）",
            skip=True,
        ))
    return out


def _bugcheck_code(row):
    data = row["data"]
    for key in sorted(data, key=lambda k: (not k.isdigit(), k)):
        value = data[key]
        if not value or key == "_names":
            continue
        token = value.strip().lstrip("0") or "0"
        if re.fullmatch(r"[0-9a-fA-F]{1,16}", token):
            try:
                code = int(value.strip(), 16)
            except ValueError:
                continue
            if code in _BUGCHECK:
                return code
    for value in data.values():
        m = re.search(r"[0-9a-fA-F]{8}", value or "")
        if m:
            try:
                return int(m.group(0), 16)
            except ValueError:
                pass
    return None


def _faulting_module(row):
    blob = " ".join(v for v in row["data"].values() if isinstance(v, str))
    m = re.search(r"([A-Za-z0-9_.-]{2,64}\.sys)", blob)
    return m.group(1) if m else ""


_BSOD_STEPS = [
    "记住报告里给出的原因和文件名，这是最有用的线索",
    "到笔记本/主板官网（不要用第三方驱动站）更新显卡、网卡、芯片组驱动",
    "卸载最近新装的驱动类、杀毒类、游戏修改类软件，观察一到两周",
    "如果反复出现同一个原因，把它交给维修点或售后，比描述\"电脑老重启\"有用得多",
]
_POWER_STEPS = [
    "确认不是拔电源、电池耗尽或长按电源键造成的",
    "检查插座与电源线是否松动；台式机可换一根电源线试试",
    "如果是散热导致的自动保护，会伴随风扇狂转、机身发烫，需要清灰或检查风扇",
]


# ---------------------------------------------------------------- module B

_DLL_CODES = {"c000007b", "c0000135", "c0000139", "c0000142"}


def probe_runtime_dlls(ctx):
    out = []
    dirs = {"64 位系统目录": native.dir_64bit(), "32 位程序目录": native.dir_32bit()}
    missing_vc, missing_dx = [], []
    for label, path in dirs.items():
        if not os.path.isdir(path):
            continue
        for name in _VCRUNTIME:
            if not os.path.exists(os.path.join(path, name)):
                missing_vc.append("%s（%s）" % (name, label))
        for name in _DIRECTX:
            if not os.path.exists(os.path.join(path, name)):
                missing_dx.append("%s（%s）" % (name, label))

    # A missing file is only a *problem* when something actually tripped over it.
    # Measured on this machine: vcruntime140_1.dll is absent from SysWOW64 while
    # every 32-bit program on it runs fine. Reporting that as 需处理 would train the
    # user to ignore the red marks that do matter.
    tripped = sorted(_DLL_CODES & set(getattr(ctx, "app_codes", set())))

    if (missing_vc or missing_dx) and tripped:
        out.append(Finding(
            module="display", status=Status.RED, kind="vc_missing",
            headline="缺少运行库文件，并且已经导致软件打不开（%d 个文件）" % (len(missing_vc) + len(missing_dx)),
            plain="近 7 天有软件报过\"某个程序文件找不到\"类的错误，这正是缺少运行库的典型表现",
            why="运行库不是病毒，是微软的公共基础组件，装上就能好",
            steps=_REDIST_STEPS,
            copy_cmd=_VC_REDIST,
            native={"missing": missing_vc + missing_dx, "codes": tripped},
        ))
    elif missing_vc or missing_dx:
        merged = missing_vc + missing_dx
        out.append(Finding(
            module="display", status=Status.GRAY, kind="runtime_absent",
            headline="有 %d 个常见运行库文件不在，但近 7 天没有任何软件因此报错" % len(merged),
            plain="这不影响使用，不需要处理。只有当某个软件打不开、并且提示缺少某个程序"
                  "文件的时候才需要补装",
            skip=True,
            native={"missing": merged},
        ))
    else:
        out.append(Finding(
            module="display", status=Status.GREEN, kind="runtime_ok",
            headline="常用运行库文件齐全",
            plain="7 类常见\"缺少程序文件\"的成因都检查过了，本机都存在",
        ))
    return out


_REDIST_STEPS = [
    "到微软官方页面下载 \"Visual C++ Redistributed\"，x64 和 x86 两个版本都装（很多软件是 32 位的）",
    "下载地址：%s" % _VC_REDIST,
    "老游戏缺 DirectX 老组件时，下载 \"DirectX End-User Runtime\"：%s" % _DX_ENDUSER,
    "装完重启那个软件即可，不需要重装系统，也不要从第三方\"单独下载某个程序文件\"的站点取文件",
]


def probe_display(ctx):
    out = []
    adapters = native.display_adapters()
    physical = [a for a in adapters if not a["mirroring"] and a["copies"] >= 1]
    active = [a for a in physical if a["active"] and a["monitors"]]
    primary = [a for a in physical if a["primary"]]
    dgpus = [a for a in physical if _DGPU.search(a["name"])]
    igpus = [a for a in physical if _IGPU.search(a["name"]) and not _DGPU.search(a["name"])]

    basic = [a for a in physical if re.search(r"(?i)basic display|microsoft 基本", a["name"])]
    if basic:
        out.append(Finding(
            module="display", status=Status.YELLOW, kind="no_gpu_driver",
            headline="显卡正在使用 Windows 的基本驱动",
            plain="这通常意味着显卡驱动没装或装坏了，画面会明显变卡、游戏帧数很低",
            steps=["到显卡官网（NVIDIA / AMD / Intel 之一）下载对应型号驱动并安装",
                   "笔记本请优先用笔记本品牌官网提供的驱动"],
        ))

    if not active and not primary:
        out.append(Finding(
            module="display", status=Status.GRAY, kind="display_unknown",
            headline="显示适配器检查",
            plain="未能确认当前哪块显卡在输出画面，不作为故障结论",
            native={"adapters": [a["name"] for a in physical]},
        ))
        return out

    desktop = _is_desktop()
    on_igpu = bool(primary and _IGPU.search(primary[0]["name"]) and not _DGPU.search(primary[0]["name"]))

    if dgpus and igpus:
        if desktop and on_igpu:
            out.append(Finding(
                module="display", status=Status.YELLOW, kind="wrong_port",
                headline="显示器接在了主板的显示口上，独立显卡没有参与工作",
                plain="表现是游戏帧数低、画面卡顿，硬件本身没有损坏",
                why="台式机显示器线要插到独立显卡的接口（机箱背面横着的那一排），"
                    "不要插到主板的显示接口（竖着靠近 USB 那一排）",
                steps=["关机后，把显示器线从主板上的接口拔下",
                       "插到下面那块横向的独立显卡接口上",
                       "开机后重新运行本程序，这一条应变为正常"],
            ))
        elif desktop and not on_igpu:
            out.append(Finding(
                module="display", status=Status.GREEN, kind="dgpu_ok",
                headline="独立显卡正在输出画面",
                plain="接法正确，游戏不会被集显拖慢",
                native={"primary": primary[0]["name"] if primary else ""},
            ))
        else:
            out.append(Finding(
                module="display", status=Status.GRAY, kind="laptop_hybrid",
                headline="笔记本的显卡工作方式：无法从系统判断，且大概率不是问题",
                plain="绝大多数笔记本的屏幕本来就由核显输出，独显在后台算完再把画面交出去，"
                      "这是设计如此，不是插错线",
                why="少数游戏本有\"独显直连\"开关，位置在品牌自带的控制中心或开机设置里，"
                    "想要更高帧数可以打开它，但会增加耗电",
                skip=True,
            ))
    elif dgpus and not igpus:
        out.append(Finding(
            module="display", status=Status.GREEN, kind="single_gpu",
            headline="只有一块显卡在工作，不存在显卡之间的冲突",
            native={"names": [a["name"] for a in physical]},
        ))

    names = [a["name"] for a in physical if a["name"]]
    if len(set(names)) >= 3:
        out.append(Finding(
            module="display", status=Status.YELLOW, kind="many_adapters",
            headline="系统里存在 %d 种不同的显示适配器" % len(set(names)),
            plain="多块显卡或虚拟显示设备混用，偶尔会造成画面卡顿、外接屏不亮",
            steps=["如果你没有主动装过多显卡或采集卡，这一项通常是虚拟显示设备（远程、投屏类软件）带来的",
                   "可先回忆近期是否装过投屏/远程/录屏类软件"],
            native={"names": sorted(set(names))},
        ))
    return out


def probe_tdr(ctx):
    rows = evtlog.query(*evtlog.XPATH["tdr"], max_records=20)
    if not rows:
        return [Finding(module="display", status=Status.GREEN, kind="tdr_ok",
                        headline="近 30 天没有出现显卡驱动卡死后恢复的情况",
                        plain="游戏画面突然冻结一两秒再回来，就是这类现象，本机没有记录")]
    recovered = [r for r in rows if r["event_id"] == "4101"]
    failed = [r for r in rows if r["event_id"] in ("4102", "4103")]
    out = []
    if recovered:
        out.append(Finding(
            module="display", status=Status.YELLOW, kind="tdr",
            headline="显卡驱动短暂卡死后恢复（近 30 天 %d 次）" % len(recovered),
            plain="表现为画面突然定格一两秒又能动，偶尔几次不算硬件损坏",
            why="常见诱因：驱动版本与游戏不匹配、超频或散热不足、显存占用过高、"
                "或帧数无限制导致瞬时负载过高",
            steps=["到显卡官网重装一次驱动，安装时选择\"清洁安装\"",
                   "如果游戏开了无上限帧数，限制在 60 或 144 试试",
                   "机箱/笔记本散热清灰，观察是否还出现"],
            native={"count": len(recovered), "first": recovered[-1]["time"], "last": recovered[0]["time"]},
        ))
    if failed:
        out.append(Finding(
            module="display", status=Status.RED, kind="tdr_fail",
            headline="显卡驱动卡死后没能恢复（%d 次）" % len(failed),
            plain="这类会直接黑屏、游戏崩溃甚至系统重启，比上面的定格更需要处理",
            steps=["优先重装显卡驱动（官网，清洁安装）",
                   "如果刚超频或换过显卡，先恢复默认设置"],
            native={"count": len(failed)},
        ))
    return out


def probe_appcrash(ctx):
    rows = evtlog.query(*evtlog.XPATH["appcrash"], max_records=20)
    codes = getattr(ctx, "app_codes", None)
    if codes is None:
        codes = set()
        ctx.app_codes = codes
    counts = {}
    for row in rows:
        if row["event_id"] != "1000":
            continue
        data = row["data"]
        app = data.get("0", "")
        code = (data.get("6", "") or "").lower().replace("0x", "")
        if code:
            codes.add(code)
        if not app:
            continue
        key = (app.lower(), code)
        counts.setdefault(key, {"app": app, "code": code, "n": 0,
                               "module": data.get("3", ""), "path": data.get("2", "")})
        counts[key]["n"] += 1

    out = []
    repeated = [(k, v) for k, v in counts.items() if v["n"] >= 2]
    for _, info in sorted(repeated, key=lambda kv: -kv[1]["n"])[:6]:
        code = info["code"]
        known = _APPCODE.get(code)
        out.append(Finding(
            module="display", status=Status.YELLOW, kind="app_crash",
            headline="软件\"%s\"近 7 天闪退 %d 次" % (info["app"], info["n"]),
            plain=known[0] if known else "软件自身出现过崩溃",
            why=("%s（软件内部原因居多，不能据此说内存条坏了）" % known[1]) if known else "",
            steps=["重装或更新这个软件本身",
                   "如果是游戏：先关掉覆盖层、帧数显示、汉化补丁与 MOD",
                   "如果某个软件打不开、提示缺少某个程序文件，按本报告\"运行库\"那一条处理",
                   "以上无效再考虑软件自带的反馈渠道"],
            native={"app": info["app"], "code": "0x%s" % code if code else "?",
                    "faulting_module": info["module"], "path": info["path"]},
        ))
    if not out:
        return [Finding(module="display", status=Status.GREEN, kind="app_ok",
                        headline="近 7 天没有软件反复闪退的记录",
                        plain="偶尔一次崩溃属于正常，报告只列出反复出现两次以上的软件")]
    return out


# ---------------------------------------------------------------- module C

def probe_proxy(ctx):
    out = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    except OSError as exc:
        return [Finding(module="network", status=Status.GRAY, headline="代理设置未能读取",
                        plain="这一项没取到数据，不影响其他检查项", native={"error": str(exc)})]
    try:
        enable = _reg_int(key, "ProxyEnable")
        server = _reg_str(key, "ProxyServer")
        pac = _reg_str(key, "AutoConfigURL")
    finally:
        winreg.CloseKey(key)

    per_user = None
    try:
        mk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings")
        try:
            per_user = _reg_int(mk, "ProxySettingsPerUser")
            machine_server = _reg_str(mk, "ProxyServer")
        finally:
            winreg.CloseKey(mk)
    except OSError:
        machine_server = ""

    if enable == 1 and server:
        loopback = bool(re.match(r"^\s*(127\.0\.0\.1|localhost)", server))
        out.append(Finding(
            module="network", status=Status.YELLOW, kind="proxy_on",
            headline="系统代理是开着的",
            plain="如果微信能上、网页打不开，八成就是它：代理指向的软件已经不运行了，但开关还开着",
            why=("代理地址指向本机某个软件（加速器/翻译/公司网络工具）。这个软件没在运行时，网页就会全打不开"
                 if loopback else "代理地址不是本机地址，通常来自公司网络或代理类软件"),
            steps=_PROXY_STEPS,
            copy_cmd="",
            native={"ProxyEnable": enable, "ProxyServer": server, "AutoConfigURL": pac},
        ))
    elif enable != 1 and server:
        out.append(Finding(
            module="network", status=Status.GREEN, kind="proxy_residue",
            headline="代理已关闭，只留下一个不再使用的地址",
            plain="这不影响上网，也不需要处理",
            why="卸载加速器/代理软件后经常会留这一条，属于正常残留",
            native={"ProxyServer": server},
        ))
    if pac:
        out.append(Finding(
            module="network", status=Status.YELLOW, kind="proxy_pac",
            headline="网页被设置为按一个自动脚本地址来上网",
            plain="如果这个脚本已经打不开，所有网页都会报错，而 QQ、微信仍然能用",
            steps=_PROXY_STEPS,
            native={"AutoConfigURL": pac},
        ))
    if per_user == 0 and machine_server:
        out.append(Finding(
            module="network", status=Status.YELLOW, kind="proxy_machine",
            headline="这台电脑由管理员统一设置了代理",
            plain="你自己的设置页里改了也没用，需要管理员改机器级设置",
            steps=["如果这是公司电脑，请联系 IT；本机程序不会替你修改任何设置"],
            native={"ProxySettingsPerUser": per_user},
        ))
    if not out:
        out.append(Finding(module="network", status=Status.GREEN, kind="proxy_ok",
                           headline="没有代理残留", plain="网页打不开的原因不在代理设置"))
    return out


_PROXY_STEPS = [
    "按键盘上的 Win 键 + I 键，打开\"设置\"",
    "点\"网络和 Internet\"，再点最下面的\"代理\"（Win10 是：点\"状态\"→底部\"网络\"→\"代理\"）",
    "把\"使用代理服务器\"的开关关掉（灰色是关闭状态）",
    "同一页面把\"自动检测设置\"打开，然后重新打开浏览器试试",
    "如果一关掉又自己变成开着，说明是某个软件在反复改它，回想最近装过什么",
]


def probe_hosts(ctx):
    path = os.path.join(native.SYSTEM_ROOT, "System32", "drivers", "etc", "hosts")
    try:
        raw = open(path, "rb").read()
    except OSError as exc:
        return [Finding(module="network", status=Status.GRAY, headline="hosts 文件未能读取",
                        native={"error": str(exc)})]
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    text = text.lstrip("\ufeff")
    lines = [ln.strip() for ln in text.splitlines()]
    active = [ln for ln in lines if ln and not ln.startswith("#")]
    if not active:
        return [Finding(module="network", status=Status.GREEN, kind="hosts_ok",
                        headline="hosts 文件没有被改动过",
                        plain="这是流氓软件劫持网页最常用的地方，本机干净")]
    blocked = [ln for ln in active if re.match(r"^\s*(127\.0\.0\.1|0\.0\.0\.0)", ln)]
    if len(blocked) >= 3:
        return [Finding(
            module="network", status=Status.YELLOW, kind="hosts_tampered",
            headline="hosts 文件里有 %d 条指向本机的拦截记录" % len(blocked),
            plain="某些网站会打不开并显示无法访问，但 QQ、微信正常——这就是它造成的",
            why="常见于\"系统优化软件\"、杀毒软件的广告拦截，或手动照教程改过",
            steps=["按 Win 键 + R，输入 notepad C:\\Windows\\System32\\drivers\\etc\\hosts 后回车",
                   "只看不改：把开头不是 # 的行记下来，交给懂的人或回原软件里关掉拦截",
                   "不确定就不要保存，改错这一行会让所有网页都打不开"],
            native={"active_lines": len(active), "sample": blocked[:3]},
        )]
    return [Finding(module="network", status=Status.GREEN, kind="hosts_minor",
                   headline="hosts 有少量自定义条目，未见批量拦截特征",
                   native={"active_lines": len(active)})]


def probe_services(ctx):
    out = []
    checked = []
    for name, label in list(_AUDIO_SVC) + list(_NET_SVC):
        info = native.service_start_type(name)
        if info is None:
            continue
        checked.append((label, info))
        if info["code"] == 0x4:
            out.append(Finding(
                module="network", status=Status.YELLOW, kind="svc_disabled",
                headline="%s被设置为\"已禁用\"" % label,
                plain="如果对应功能不工作（没声音、网页打不开、IP 获取失败），多半就是它",
                why="系统不会自己禁用它，通常是优化软件或照教程操作时改的",
                steps=["按键盘 Win 键 + R，输入 services.msc 后回车",
                       "在列表里找到 \"%s\"，双击打开" % name,
                       "把\"启动类型\"改为\"自动\"，点\"启动\"，再点确定",
                       "重启电脑确认"],
                copy_cmd="",
                native={"service": name, "start": info["text"]},
            ))
    if not out:
        detail = "、".join("%s:%s" % (l, i["text"]) for l, i in checked)
        out.append(Finding(
            module="network", status=Status.GREEN, kind="svc_ok",
            headline="关键系统服务没有被禁用",
            plain="音频与网络相关的服务启动方式都正常（%s）" % detail if detail else
                   "音频与网络相关的服务启动方式都正常",
        ))
    out.append(Finding(
        module="network", status=Status.GRAY, needs_admin=True, kind="svc_state",
        headline="服务\"当前是否正在运行\"没有检查",
        plain="这一项需要授权后才能看；未授权时程序宁可留空，也不猜一个结果给你看",
        skip=True,
    ))
    return out


def probe_usb(ctx):
    """Per-device \"allow the computer to turn off this device\" is only reachable
    through the power-management WMI class, which denies non-elevated callers, and
    parsing powercfg's localized text into a red/yellow verdict would be a guess.
    So this probe reports guidance, not a fake measurement."""
    return [Finding(
        module="network", status=Status.GRAY, kind="usb_advice", needs_admin=True,
        headline="USB 设备的省电设置：只提供检查方法，不自动判断",
        plain="如果 U 盘、鼠标、耳机时不时断一下又回来，这个设置是常见原因之一",
        why="本程序宁可告诉你怎么看，也不根据语言本地化的命令行文字猜一个结论",
        steps=["按键盘 Win 键 + X，点\"设备管理器\"",
                "展开\"通用串行总线控制器\"，双击 \"USB Root Hub\"（可能有多个，逐个看）",
                "点\"电源管理\"标签页，把\"允许计算机关闭此设备以节约电源\"的勾去掉，点确定",
                "这一页除了这个勾，别的按钮都不用点；改完立刻生效，无需重启"],
        skip=True,
    )]


# ---------------------------------------------------------------- module D

def probe_disk(ctx):
    out = []
    drives = native.fixed_drives()
    if not drives:
        return [Finding(module="storage", status=Status.GRAY, headline="磁盘剩余空间未能读取")]
    for d in drives:
        free, total = d["free_gb"], d["total_gb"]
        if d["is_system"]:
            if free < 5:
                status, why = Status.RED, "Windows 更新、软件安装和虚拟内存都会因此失败，属于需要马上处理的问题"
            elif free < 15:
                status, why = Status.YELLOW, "剩得不多了，Windows 大版本更新可能失败"
            elif free < 30:
                status, why = Status.GREEN, "空间够用，暂时不用清理"
            else:
                out.append(Finding(module="storage", status=Status.GREEN, kind="disk_ok",
                                  headline="系统盘空间充足（剩 %.0f GB）" % free,
                                  plain="没有因为空间不足引发的问题", skip=True))
                continue
            out.append(Finding(
                module="storage", status=status, kind="disk_space",
                headline="系统盘剩余空间 %.0f GB（共 %.0f GB）" % (free, total),
                plain=why,
                why="空间紧张时常见的表现：更新失败、软件打不开、越用越卡",
                steps=["按 Win 键 + I 打开设置，点\"系统\"→\"存储\"（Win10：系统→存储感知）",
                       "点\"临时文件\"，勾选后删除（不会删掉你的文档和照片）",
                       "在同一页可以打开\"存储感知\"，让它自动清理",
                       "把不常用的大文件移动到别的盘，比清理更能解决问题"],
                native={"free_gb": round(free, 1), "total_gb": round(total, 1),
                        "drive": d["root"]},
            ))
        elif free < 5 and total > 50:
            out.append(Finding(
                module="storage", status=Status.YELLOW, kind="disk_space_other",
                headline="%s 盘剩余空间只有 %.0f GB" % (d["root"][0], free),
                plain="不影响系统运行，但存不进去东西",
                steps=["清理这个盘里的大文件，或把文件移动到空间充足的盘"],
                skip=True,
            ))
    return out


def _reg_values(key):
    out = []
    index = 0
    while True:
        try:
            name, value, kind = winreg.EnumValue(key, index)
        except OSError:
            break
        out.append((name, value, kind))
        index += 1
    return out


def _reg_str(key, name):
    try:
        raw = winreg.QueryValueEx(key, name)[0]
    except OSError:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw) if raw is not None else ""


def _reg_int(key, name):
    try:
        return int(winreg.QueryValueEx(key, name)[0])
    except (OSError, ValueError, TypeError):
        return None


_RUN_SITES = (
    ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "当前用户"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "本机所有用户"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "本机(32位程序)"),
    ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "当前用户(一次性)"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "本机(一次性)"),
)


def probe_startup(ctx):
    entries = []
    for _, hive, sub, label in _RUN_SITES:
        try:
            key = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        try:
            for name, value, _ in _reg_values(key):
                path = _extract_path(str(value))
                entries.append({"name": name, "command": str(value), "path": path,
                                "site": label})
        finally:
            winreg.CloseKey(key)

    for startup_dir in (_startup_dirs()):
        try:
            for fn in os.listdir(startup_dir):
                if fn.lower().endswith((".lnk", ".exe", ".bat")):
                    entries.append({"name": fn, "command": os.path.join(startup_dir, fn),
                                    "path": os.path.join(startup_dir, fn), "site": "启动文件夹"})
        except OSError:
            pass

    bad, orphan, normal = [], [], []
    for item in entries:
        hit = ctx.rules.match_bad(item)
        if hit:
            bad.append((item, hit))
        elif item["path"] and not _path_exists(item["path"]):
            orphan.append(item)
        elif not item["path"]:
            normal.append(item)
        else:
            normal.append(item)

    out = []
    for item, hit in bad:
        out.append(Finding(
            module="startup", status=Status.RED, kind="known_bad",
            headline="发现需要处理的自启动项：%s" % item["name"],
            plain=hit.get("plain", "这一项在已知的流氓捆绑名单里"),
            why=hit.get("why", ""),
            steps=hit.get("steps", ["先在\"设置→应用→已安装的应用\"里卸载它对应的软件"]),
            native={"name": item["name"], "command": item["command"], "site": item["site"]},
        ))
    for item in orphan[:8]:
        out.append(Finding(
            module="startup", status=Status.YELLOW, kind="orphan_run",
            headline="有个开机自启项指向已经不存在的文件：%s" % item["name"],
            plain="这是卸载留下的残留，不会拖慢电脑，也不会危害安全，看着碍眼而已",
            why="删掉它之前，值得确认它不是某个软件的\"延迟安装\"任务",
            steps=["按 Win 键 + R，输入 msconfig 后回车，点\"启动\"选项卡",
                   "更稳妥的做法：在任务管理器（Win+X 后选任务管理器）的\"启动\"页里禁用它",
                   "不确定的话，这一条可以完全不管"],
            native={"command": item["command"], "site": item["site"]},
        ))
    if not bad and not orphan:
        out.append(Finding(
            module="startup", status=Status.GREEN, kind="startup_ok",
            headline="自启动项里没有已知流氓软件，也没有卸载残留",
            plain="共检查 %d 个自启项。Steam、微信、声卡驱动这类正常软件的自启不算问题，"
                  "本程序不会因为\"没被微软签名\"就给它们打红标" % len(entries),
            native={"count": len(entries),
                    "items": [{"name": n["name"], "site": n["site"]} for n in normal]},
        ))
    else:
        out.append(Finding(
            module="startup", status=Status.GREEN, kind="startup_list",
            headline="其余 %d 个自启动项属于正常软件" % len(normal),
            plain="完整清单在报告下方折叠区，不需要逐个处理",
            skip=True,
            native={"items": [{"name": n["name"], "site": n["site"], "command": n["command"]}
                              for n in normal]},
        ))
    return out


def _extract_path(command):
    """Pull the executable out of a Run-key command line.

    Returns "" whenever the target cannot be resolved to an absolute path. Empty
    means "say nothing" - claiming a startup entry points at a missing file when
    our own parsing failed is precisely how a tool like this manufactures false
    positives (that is what the first version did to OneDrive and Chrome here).
    """
    text = (command or "").strip()
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        cand = text[1:end] if end > 1 else text[1:]
    else:
        cand = text
        for marker in (" -", " /"):
            cut = cand.find(marker)
            if cut > 2:
                cand = cand[:cut]
                break
    cand = _expand_env(cand).strip().strip('"')
    if not re.match(r"^(?:[A-Za-z]:[\\/]|\\\\)", cand):
        return ""
    if not cand.lower().endswith((".exe", ".dll", ".bat", ".cmd", ".vbs", ".msc", ".lnk")):
        if not os.path.sep.strip("\\") or not re.search(r"\.\w{2,4}$", cand):
            return ""
    return cand


def _expand_env(text):
    missing = []

    def repl(match):
        value = os.environ.get(match.group(1), "")
        if not value:
            missing.append(match.group(1))
        return value

    out = re.sub(r"%([A-Za-z_][A-Za-z0-9_]*)%", repl, text, flags=re.I)
    return "" if missing else out


def _path_exists(path):
    try:
        return os.path.exists(path)
    except (OSError, ValueError):
        return True


def _startup_dirs():
    dirs = []
    for env_key, sub in (("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
                         ("ProgramData", r"Microsoft\Windows\Start Menu\Programs\Startup")):
        base = os.environ.get(env_key, "")
        if base:
            dirs.append(os.path.join(base, sub))
    return dirs


# ---------------------------------------------------------------- module E

def probe_battery(ctx):
    ps = native.power_status()
    if ps is None:
        return [Finding(module="power", status=Status.GRAY, headline="电源状态未能读取")]
    if not ps["has_battery"]:
        return [Finding(
            module="power", status=Status.GRAY, kind="no_battery",
            headline="台式机无电池，跳过",
            plain="这一项只适用于笔记本和带电池的机器",
            skip=True,
        )]

    out = [Finding(
        module="power", status=Status.GREEN if (ps["percent"] or 0) > 0 else Status.GRAY,
        kind="battery_now",
        headline="电池当前剩余 %s%%，%s" % (
            ps["percent"] if ps["percent"] is not None else "?",
            "接着电源" if ps["on_ac"] else "正在用电池"),
        plain="剩余 %s%%，按当前用量大约还能用 %s 分钟" % (
            ps["percent"], ps["minutes_left"] if ps["minutes_left"] else "不确定"),
        native=dict(ps),
    )]
    if ps["percent"] is not None and ps["percent"] < 20 and not ps["on_ac"]:
        out[0].status = Status.YELLOW
        out[0].plain = "电量偏低且没接电源，突然断电会造成未保存内容丢失"
        out[0].headline = "电池剩余 %d%%，建议接上电源" % ps["percent"]

    wear = _battery_wear(ctx)
    if wear is None:
        return out
    out.append(wear)
    return out


def _battery_wear(ctx):
    tmp = os.path.join(ctx.temp_dir, "sysprobe_batt_%d.html" % os.getpid())
    try:
        rc, out_text, err = native.run_readonly(
            ["powercfg", "/batteryreport", "/output", tmp, "/duration", "14"], timeout=45.0)
        if rc != 0 or not os.path.isfile(tmp):
            return Finding(
                module="power", status=Status.GRAY, kind="wear_unavailable",
                headline="电池损耗：本机的系统工具没能给出报告，跳过",
                plain="这不代表电池有问题，只是这项信息这次取不到",
                skip=True)
        try:
            raw = open(tmp, "rb").read()
        except OSError:
            return None
        text = raw.decode("utf-8", "replace")
        # The two capacities are read from the report's own label cells. Those
        # labels stay English even on a Chinese Windows ("DESIGN CAPACITY"),
        # while every other string in the file is localised - so this is the
        # only reading here that does not depend on the system language.
        # The previous version guessed "the two largest mWh numbers in the
        # file", which on this machine picked two equal samples out of the 61
        # discharge rows and reported a brand-new-looking 0% wear on a battery
        # that is really at 8%.
        caps = {}
        for label, value in re.findall(
                r'class="label">\s*([A-Z][A-Z ]{3,40}?)\s*</span></td>'
                r'<td>\s*([\d,]{2,15})\s*m?Wh', text, re.I):
            if label.upper() in ("DESIGN CAPACITY", "FULL CHARGE CAPACITY"):
                caps.setdefault(label.upper(), int(value.replace(",", "")))
        design = caps.get("DESIGN CAPACITY", 0)
        full = caps.get("FULL CHARGE CAPACITY", 0)
        if design <= 0 or full <= 0:
            return Finding(
                module="power", status=Status.GRAY, kind="wear_unparsed",
                headline="电池损耗：报告已生成，但无法从本机语言版本的表格里可靠读出容量",
                plain="本程序不做\"猜一个损耗率\"这件事；想知道具体数值，可以把报告文件交给维修人员看",
                skip=True)
        wear = max(0.0, 100.0 - (full * 100.0 / design))
        status = Status.GREEN if wear < 20 else (Status.YELLOW if wear < 40 else Status.RED)
        return Finding(
            module="power", status=status, kind="wear",
            headline="电池损耗约 %.0f%%" % wear,
            plain="电池现在大约只能存住出厂容量的 %.0f%%（出厂 %s，现在充满 %s）"
                  % (100 - wear, format(design, ","), format(full, ",")),
            why="损耗是自然老化；超过 40% 会明显感觉续航变短，属于换电池的信号，不是电脑坏了",
            steps=["笔记本厂商售后或正规渠道更换电池即可，不需要换整机"] if wear >= 40 else [],
            native={"design_mWh": design, "full_mWh": full})
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------- registry

PROBES = [
    ("stability", "系统崩溃与硬件错误", probe_stability, False),
    ("appcrash", "软件闪退", probe_appcrash, False),
    ("display", "显卡、驱动与软件闪退", probe_display, False),
    ("tdr", "显卡驱动卡死", probe_tdr, False),
    # after appcrash: it correlates the missing-dll report with real crash codes
    ("runtime", "运行库文件", probe_runtime_dlls, False),
    ("network", "网络与代理", probe_proxy, False),
    ("hosts", "hosts 文件", probe_hosts, False),
    ("services", "系统服务", probe_services, False),
    ("usb", "USB 省电设置", probe_usb, True),
    ("storage", "磁盘剩余空间", probe_disk, False),
    ("startup", "开机自启动", probe_startup, False),
    ("power", "电池", probe_battery, False),
    # the invisible-limit set lives in limits.py and shares this pipeline
] + limits.PROBES
