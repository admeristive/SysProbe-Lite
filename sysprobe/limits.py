"""Probes for faults that never reach the system log.

Nothing here leaves an error record, yet the machine stops behaving: the
desktop flickers because too many programs fight for the icon badge slots, big
games die silently because paging was switched off by some "optimisation
guide", Task Manager says it has been disabled by the administrator, a program
slowly spends its whole drawing budget and then freezes with a black taskbar and
square-character text - and, in the same family, a 240 Hz panel quietly driven
at 60, an output device somebody disabled years ago, a missing network card
driver, a piece of software that sits on the rule list.

Measured on Windows 11 (10.0.26300) without administrator rights: the first four
together cost about 1 ms, the four that read devices and settings about 14.5 ms
(screen 7.2 ms, installed list 6.8 ms, sound 0.3 ms, network cards 0.3 ms) - eight
together 15.7 ms against the 50 ms the self-test budgets. Every failing path
degrades to a gray row.
"""

import re
import time
import winreg

from . import native
from .model import Finding, Status, failed

# The shell honours only a small number of icon badge handlers and keeps a few
# slots for itself, so the practical room left for third-party programs is
# around eleven. We can count the list but cannot read the shell's real cap, so
# this is a caution threshold, not a hard limit.
SLOT_LIMIT = 11

# Windows gives each program on the order of ten thousand drawing objects;
# past roughly eighty per cent of that, failures start showing up everywhere.
DRAW_CAUTION = 8000

_GUID = re.compile(r"^\{?[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?$", re.I)
_SUFFIX = ("shell extension", "overlay handler", "overlay identifier",
           "shell overlay", "icon overlay")

_B = chr(92)


def _path(*parts):
    return _B.join(parts)


_REG_OVERLAY = _path("SOFTWARE", "Microsoft", "Windows", "CurrentVersion",
                     "Explorer", "ShellIconOverlayIdentifiers")
# The 32-bit list. A 64-bit shell never loads these, but a 32-bit shell would,
# so they belong in the annex rather than in the contention count.
_REG_OVERLAY_32 = _path("SOFTWARE", "Wow6432Node", "Microsoft", "Windows",
                        "CurrentVersion", "Explorer",
                        "ShellIconOverlayIdentifiers")

_POLICY_SITES = (
    (winreg.HKEY_CURRENT_USER,
     _path("Software", "Microsoft", "Windows", "CurrentVersion",
           "Policies", "System"), "当前用户"),
    (winreg.HKEY_CURRENT_USER,
     _path("Software", "Policies", "Microsoft", "Windows", "System"),
     "当前用户（组策略下发）"),
    (winreg.HKEY_LOCAL_MACHINE,
     _path("SOFTWARE", "Microsoft", "Windows", "CurrentVersion",
           "Policies", "System"), "这台电脑"),
    (winreg.HKEY_LOCAL_MACHINE,
     _path("SOFTWARE", "Policies", "Microsoft", "Windows", "System"),
     "这台电脑（组策略下发）"),
)

_LOCKS = (("DisableTaskMgr", "任务管理器"),
          ("DisableRegistryTools", "系统设置查看工具"),
          ("DisableCMD", "命令提示符窗口"))


class _StopScan(Exception):
    """Raised when enumeration fails for a reason other than reaching the end."""


def _step_error(exc):
    """True only when winreg said 'no more items' (measured winerror 259).

    A bare `except OSError` here would turn a mid-list access refusal into a
    short count, and a short count reads as "normal" on screen.
    """
    return getattr(exc, "winerror", None) == 259


def _reg_names(key):
    out, index = [], 0
    while True:
        try:
            out.append(winreg.EnumKey(key, index))
        except OSError as exc:
            if not _step_error(exc):
                raise _StopScan("读取被中断")
            return out
        index += 1


def _reg_values(key):
    out, index = [], 0
    while True:
        try:
            name, value, _kind = winreg.EnumValue(key, index)
        except OSError as exc:
            if not _step_error(exc):
                raise _StopScan("读取被中断")
            return out
        out.append((name, value))
        index += 1


# ------------------------------------------------------- A: icon badge slots

def _badge_label(raw):
    """A readable name for one entry, or None when the entry is unlabelled."""
    stripped = raw.strip()
    if _GUID.match(stripped):
        return None
    for suffix in _SUFFIX:
        if stripped.lower().endswith(suffix):
            stripped = stripped[: -len(suffix)].strip()
            break
    return stripped or None


def _badge_owner(raw):
    """Which program put one badge entry here, read from the handler it points at.

    The entry's default value is a class id; that class points at the dll the
    shell loads. The dll's file name is the honest attribution - we never claim
    the product name, only what the system would actually load.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             _path(_REG_OVERLAY, raw), 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return ""
    try:
        clsid = str(winreg.QueryValueEx(key, "")[0]).strip()
    except OSError:
        clsid = ""
    finally:
        winreg.CloseKey(key)
    if not clsid:
        return ""
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CLASSES_ROOT):
        try:
            handler = winreg.OpenKey(hive, _path("SOFTWARE", "Classes", "CLSID",
                                                 clsid, "InprocServer32"), 0,
                                     winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            continue
        try:
            dll = str(winreg.QueryValueEx(handler, "")[0]).strip()
        except OSError:
            dll = ""
        finally:
            winreg.CloseKey(handler)
        if dll:
            return dll.replace("/", _B).rsplit(_B, 1)[-1]
    return ""


def _count_badges_32():
    """Entries registered in the 32-bit list. The 64-bit shell does not load
    these, so they are context for a helper, never part of the contention
    count."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _REG_OVERLAY_32, 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_32KEY)
    except OSError:
        return -1
    try:
        return len(_reg_names(key))
    except Exception:
        return -1
    finally:
        winreg.CloseKey(key)


def _collect_badges():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _REG_OVERLAY, 0,
                             winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except FileNotFoundError:
        return "missing", []
    except OSError:
        return "denied", []
    try:
        return "ok", _reg_names(key)
    finally:
        winreg.CloseKey(key)


def probe_badges(ctx):
    try:
        state, names = _collect_badges()
    except Exception:
        return [failed("badges", "角标占用情况这一项没能读到")]

    if state == "denied":
        return [failed("badges", "角标占用情况这一项没能读到")]
    if state == "missing" or not names:
        return [Finding(module="badges", status=Status.GREEN, kind="badge_none",
                        headline="桌面图标角标没有被很多软件争抢",
                        plain="这台电脑上没有一堆软件在抢图标角标的位置。",
                        skip=True)]

    grabbed = [n for n in names if n[:1] in (" ", "\t", "\u3000")]
    readable = [x for x in (_badge_label(n) for n in names) if x]
    count = len(names)
    racers = "、".join([x for x in ((_badge_label(n) or "") for n in grabbed) if x][:3])

    # Attribution costs two key opens per entry, so only the entries that
    # matter get it: whoever is racing for the front, then the rest as far as
    # the cap goes.
    owners = {}
    for raw in (grabbed + names)[: 2 * SLOT_LIMIT + 4]:
        got = _badge_owner(raw)
        if got:
            owners[raw.strip() or raw] = got
    try:
        count32 = _count_badges_32()
    except Exception:
        count32 = -1

    # The annex prints scalars only (html._tech_table drops lists and dicts) and
    # cuts the whole line at 400 characters, so the six names and six program
    # files below are joined and capped before they get there.
    notes = {"count": count, "leading_blank_names": len(grabbed),
             "readable": "、".join(readable[:6]),
             "racers": racers,
             "owner_dlls": "、".join(sorted(set(owners.values()))[:6]),
             "registered_32bit": count32,
             "unlabelled": count - len(readable)}

    if count > SLOT_LIMIT:
        return [Finding(
            module="badges", status=Status.YELLOW, kind="badge_overflow",
            headline="有 %d 个软件在抢桌面图标的小角标（建议别超过 %d 个）"
                     % (count, SLOT_LIMIT),
            plain="图标一闪一闪、或者网盘的同步角标时有时无，多半是这个原因："
                  "排队顺序一变，系统就要反复重画桌面上的图标。",
            why="这些小角标是网盘和同步软件用来显示\"已同步／未同步\"的标记。系统只留了"
                "很少的位置，并且按名字的先后顺序来取，所以不少软件会把名字前面加上空格"
                "或制表符来抢排最前——抢位置的软件越多，越容易超出总数。",
            steps=["先不用卸载软件：少几个角标不影响文件同步",
                   "在右下角托盘里找到网盘类软件（比如 OneDrive、百度网盘、坚果云、夸克网盘）",
                   "进它的设置，把\"在桌面显示同步状态\"\"桌面放置同步文件夹\"\"显示角标\""
                   "这类开关关掉一到两个",
                   "改完注销一次或者重启，桌面图标才会按新的顺序重新排队"],
            native=notes,
        )]

    note = ""
    if grabbed:
        note = "其中有 %d 个软件把名字排在最前来抢位置，目前总数还没超。" % len(grabbed)
    return [Finding(
        module="badges", status=Status.GREEN, kind="badge_ok",
        headline="桌面图标角标占用正常（%d 个）" % count,
        plain=note or "占用位置不多，图标闪烁不太可能是这里引起的。",
        native=notes,
        skip=not grabbed,
    )]


# ------------------------------------------------------------- B: paging

_GB = 1024.0 ** 3

# With paging genuinely on, the commit limit sits far above physical memory;
# anything barely over it means the paging file is nominal at best.
_COMMIT_CAUTION = 1.05


def _drives(items):
    """Drive letters holding a paging file, from Windows' own path spelling."""
    out = []
    for raw in items or []:
        text = str(raw).replace("/", _B)
        for piece in text.split(_B):
            if len(piece) == 2 and piece[1] == ":" and piece[0].isalpha():
                letter = piece[0].upper()
                if letter not in out:
                    out.append(letter)
    return out


def _paging_state(decl):
    """'off', 'on' or None from what the registry declares and has attached.

    An attached list that is present but empty is a real reading, not a failure:
    it means nothing was attached at start-up. Only a missing key means we could
    not look, and then the caller must fall back to the commit-limit ratio.
    """
    if not decl:
        return None
    attached = decl.get("attached")
    if attached is not None:
        return "on" if attached else "off"
    declared = decl.get("declared")
    if declared is None:
        return None
    items = [str(x).strip() for x in declared if str(x).strip()]
    return "on" if items else "off"


def probe_paging(ctx):
    try:
        info = native.memory_commit()
    except Exception:
        info = None
    if not info:
        return [failed("paging", "内存与虚拟内存的数值没能读到")]

    phys = info["total_phys"] / _GB
    commit = info["total_commit"] / _GB
    try:
        decl = native.paging_declaration()
    except Exception:
        decl = None
    state = _paging_state(decl)
    drives = _drives((decl or {}).get("attached")) or _drives((decl or {}).get("declared"))
    where = "".join("%s 盘" % d for d in drives[:3]) if drives else ""
    tech = {"total_phys_gb": round(phys, 2),
            "total_commit_gb": round(commit, 2),
            "avail_commit_gb": round(info["avail_commit"] / _GB, 2),
            "load_percent": info["load_percent"],
            "declared": (decl or {}).get("declared", ""),
            "attached": (decl or {}).get("attached", ""),
            "paging_seen": state or "ratio_only"}

    # Paging off by declaration beats every other test.
    if state == "off":
        return [Finding(
            module="paging", status=Status.YELLOW, kind="paging_off",
            headline="虚拟内存被关掉了（可分配总量 %.1f GB，和物理内存 %.1f GB 一样）"
                     % (commit, phys),
            plain="内存条再大也可能出问题：Windows 能答应给软件的总量是\"物理内存＋分页文件\"，"
                  "分页文件关掉以后，这个总数就只剩内存条本身。满了之后大型游戏和不少"
                  "生产力软件会直接消失，而且常常什么错误记录都不留。",
            why="这一步多半是照着某个\"系统优化教程\"关掉的，目的是省磁盘空间。省下的空间"
                "不划算：出问题的表现是闪退、无提示，很难让人联想到这里。",
            steps=["按 Win + I 打开设置，在顶部搜索框输入\"高级系统设置\"并点开",
                   "在弹出窗口选\"高级\"标签，点\"性能\"下面的\"设置\"按钮",
                   "再选\"高级\"标签，点\"虚拟内存\"下面的\"更改\"按钮",
                   "勾上最上面的\"自动管理所有驱动器的分页文件大小\"，一路点确定",
                   "重启电脑生效"],
            native=tech,
        )]

    # Declared on but so small the headroom is meaningless - or the registry
    # would not tell us and the totals are the only evidence left.
    tight = commit <= phys * _COMMIT_CAUTION
    if tight:
        room = commit - phys
        return [Finding(
            module="paging", status=Status.YELLOW, kind="paging_tiny",
            headline=("虚拟内存几乎没有余量（可分配总量 %.1f GB，物理内存 %.1f GB）"
                      % (commit, phys) if room <= 0 else
                      "分页文件只多给了 %.1f GB，起不了缓冲作用（物理内存 %.1f GB）"
                      % (room, phys)),
            plain="Windows 能答应给软件的总量是\"物理内存＋分页文件\"。分页文件只开到这个"
                  "程度的话，大型游戏和吃内存的软件还是会在用满那一刻直接消失，而且"
                  "常常什么错误记录都不留。",
            why="这通常是手动设了一个固定值、或者把分页文件从系统盘挪走之后没配对。"
                "移动到其他盘本身没问题，问题是那边给的量太小。",
            steps=["按 Win + I 打开设置，在顶部搜索框输入\"高级系统设置\"并点开",
                   "在弹出窗口选\"高级\"标签，点\"性能\"下面的\"设置\"按钮",
                   "再选\"高级\"标签，点\"虚拟内存\"下面的\"更改\"按钮",
                   "勾上最上面的\"自动管理所有驱动器的分页文件大小\"，一路点确定",
                   "如果你确实是手动设在别的盘：保留那个盘，把大小改成\"系统管理大小\""
                   "或至少和内存一样多，再重启"],
            native=tech,
        )]

    return [Finding(
        module="paging", status=Status.GREEN, kind="paging_ok",
        headline="虚拟内存开启正常（可分配总量 %.1f GB）" % commit,
        plain="物理内存 %.1f GB，可分配总量 %.1f GB，缓冲够用%s。"
              % (phys, commit, ("，分页文件在 %s" % where) if where else ""),
        native=tech,
        skip=True,
    )]


# ------------------------------------------------------------ C: tool locks

def _locked(value):
    """A number 1 and the text "1" both lock the tool in practice."""
    if value == 1:
        return True
    return isinstance(value, str) and value.strip() == "1"


def _collect_locks():
    hits, denied = [], 0
    for hive, site, scope in _POLICY_SITES:
        try:
            key = winreg.OpenKey(hive, site, 0,
                                 winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            continue
        except OSError:
            denied += 1
            continue
        try:
            values = _reg_values(key)
        finally:
            winreg.CloseKey(key)
        for name, label in _LOCKS:
            for found, value in values:
                if found.lower() == name.lower() and _locked(value):
                    hits.append((label, scope, site, found, value))
    return hits, denied


def probe_locks(ctx):
    try:
        hits, denied = _collect_locks()
    except Exception:
        return [failed("toollocks", "系统工具锁定情况没能读到")]

    out, seen = [], set()
    for label, scope, site, found, value in hits:
        if label in seen:
            continue
        seen.add(label)
        out.append(Finding(
            module="toollocks", status=Status.RED, kind="tool_locked",
            headline="%s 被一条遗留的限制打不开了" % label,
            plain="按快捷键也没用，会提示\"已被系统管理员停用\"。如果这台电脑是你自己在用，"
                  "你并没有设置过这种限制——它通常是流氓软件或者某个\"激活／优化脚本\"留下的。",
            why="这是一条写进系统策略位置的开关，意思是\"只允许管理员取消\"。它和普通软件"
                "设置不在同一个地方，所以在常规设置里找不到，也关不掉。",
            steps=["本程序只做检查，不会替你改动任何设置，下面两条路都由你自己点",
                   "路线一（有组策略的电脑）：开始菜单搜「组策略」并打开，左侧依次展开"
                   "「用户配置」→「管理模板」→「系统」，在右侧列表里找到和本工具同名的那一条"
                   "（比如写着禁用任务管理器的），双击它，选最左边的「未配置」，点确定",
                   "选「未配置」而不是「已启用」：未配置才是把这个限制彻底取消",
                   "改完不用重启，按一下快捷键就能验证；还不行再注销一次或重启",
                   "路线二（家庭版没有组策略，走这条）：按 Win + R，在框里输入 regedit 回车，"
                   "弹出确认时点是。左侧树一层层展开到网页版报告最下面那一栏里写的那个位置",
                   "在右侧找到那个开关名，右键它选「删除」，只删这一条，别的都不要碰，"
                   "然后重新开机",
                   "被锁的是命令窗口时更要用这条：那种情况下命令行本身也打不开",
                   "两条路都只动这一个开关，不会影响系统的其他设置；不敢自己点就把报告"
                   "发给你信任的人，位置和开关名都写在里面"],
            native={"tool": label, "scope": scope, "site": site,
                    "value": found, "data": str(value)},
        ))
    if out:
        return out
    if denied:
        return [failed("toollocks", "有一处限制位置没有权限查看")]
    return [Finding(
        module="toollocks", status=Status.GREEN, kind="tool_open",
        headline="任务管理器等系统工具没有被锁定",
        plain="几处限制位置都看过，没有发现异常锁定项。",
        skip=True,
    )]


# ------------------------------------------------------ D: drawing budget

def _exe_name(pid):
    try:
        path = native.image_path(pid)
    except Exception:
        return ""
    if not path:
        return ""
    return path.replace("/", _B).rsplit(_B, 1)[-1]


def probe_draw(ctx):
    try:
        owners = native.window_owners()
    except Exception:
        return [failed("drawlimits", "软件界面资源占用情况没能读到")]
    if not owners:
        return [failed("drawlimits", "软件界面资源占用情况没能读到")]

    out, worst, measured = [], None, 0
    for pid, windows in owners:
        try:
            usage = native.draw_usage(pid)
        except Exception:
            usage = None
        if not usage:
            continue
        measured += 1
        gdi, user = usage
        if worst is None or gdi > worst[0]:
            worst = (gdi, user, pid, windows)
        if gdi <= DRAW_CAUTION:
            continue
        name = _exe_name(pid)
        out.append(Finding(
            module="drawlimits", status=Status.RED, kind="draw_exhausting",
            headline="「%s」的界面资源快用完了（已用约 %d，额度大约一万个）"
                     % (name or "某个软件", gdi),
            plain="出问题的往往不是这一个软件卡住，而是整台电脑的画面对付不过来："
                  "文字变成方块、任务栏变黑、右键菜单一片空白，然后软件静默卡死。",
            why="系统给每个软件一份界面绘制额度。用完之后它再申请就申请不到，画面只能"
                "画出半个。正常软件用不到上限，用到上限说明这个软件在反复申请却不归还，"
                "属于它自身的缺陷。",
            steps=["先保存手头的东西，把这个软件关掉再重新打开"
                   "（这是唯一能马上把额度还回来的办法）",
                   "如果用一段时间又变成这样，去这个软件的官网更新到最新版本",
                   "更新也解决不了就把这份报告反馈给软件方，他们能凭这组数字定位问题",
                   "临时办法：重启电脑会把所有软件的额度重新清零"],
            native={"process": name or "unknown", "pid": pid,
                    "gdi_objects": gdi, "user_objects": user, "windows": windows},
        ))

    if out:
        return out
    if not measured:
        return [failed("drawlimits", "软件界面资源占用情况没能读到")]
    return [Finding(
        module="drawlimits", status=Status.GREEN, kind="draw_ok",
        headline="正在使用的软件界面资源都在安全水位",
        plain="看了 %d 个有界面的软件，用得最多的一个占了 %d 份（额度大约一万个）。"
              % (measured, worst[0]),
        native={"measured": measured, "peak_gdi": worst[0], "peak_user": worst[1],
                "seen_owners": len(owners)},
        skip=True,
    )]


# ------------------------------------------------------- E: refresh ceiling

# A panel that offers 75 Hz where the system sits at 60 is not worth interrupting
# anybody for. The class worth a row is the other one: a 120/144/165/240 Hz panel
# left on its slowest step by an update, a docking station or by nobody ever
# having opened that page.
REFRESH_STEP_CAUTION = 30


def _live_modes(modes):
    """(index, row, current, hz, ceiling) for every screen that said its rate.

    Some drivers answer 0 for the refresh figure - variable-refresh panels
    mostly. A zero read as "running at 0 Hz" would be an invented fault, so those
    screens are set aside and the caller says 未获取 if nothing else is left.
    """
    live = []
    for i, row in enumerate(modes):
        cur = row.get("current") or {}
        hz = int(cur.get("hz") or 0)
        if hz <= 0:
            continue
        live.append((i, row, cur, hz, int(row.get("ceiling_hz") or 0)))
    return live


def _size(cur):
    return "%d×%d" % (int(cur.get("width") or 0), int(cur.get("height") or 0))


def probe_refresh(ctx):
    try:
        modes = native.display_modes()
    except Exception:
        return [failed("refresh", "屏幕刷新率的数值没能读到")]
    if not modes:
        return [failed("refresh", "屏幕刷新率的数值没能读到")]

    live = _live_modes(modes)
    if not live:
        return [failed("refresh", "显示器没有上报当前刷新率")]

    out = []
    for i, row, cur, hz, top in live:
        if top - hz < REFRESH_STEP_CAUTION:
            continue
        which = "主屏" if row.get("primary") else "第 %d 块屏幕" % (i + 1)
        out.append(Finding(
            module="refresh", status=Status.YELLOW, kind="refresh_low",
            headline="%s现在跑在 %d Hz，同一分辨率下它其实能给到 %d Hz"
                     % (which, hz, top),
            plain="拖动窗口不跟手、滚动时字发虚、游戏画面有撕裂感，多半出在这一处。"
                  "看视频和办公感觉不出来，所以从装机那天起没人动过它，也就一直按最慢"
                  "那一档在跑。",
            why="分辨率和刷新率是两个各自独立的选择：分辨率选低了人立刻看得见，刷新率选低"
                  "了系统一声不吭。这个 %d Hz 不是估的，是显示器自己报上来的同一分辨率"
                  "最高一档。" % top,
            steps=["按 Win + I 打开设置，点「系统」，再点「屏幕」",
                   "页面最上面是显示器的方框，先点一下要改的那一块，标几就是第几块",
                   "往下翻到「高级显示器设置」，点开它",
                   "在「选择刷新率」里选到 %d Hz 那一档，选完画面当场生效" % top,
                   "屏幕会黑一下再亮，随后弹出「是否保留这些更改」，点「保留更改」",
                   "万一选完画面黑了、连提示都看不见：什么键都不用按，等十几秒系统自己退回",
                   "下拉里找不到那一档：外接显示器多半是线只送到 60（老 HDMI 线常见），"
                   "换一根支持高刷的线再看；内置屏则是驱动没报这一档，不是这里能改出来的",
                   "这一处只动显示设置，不碰文件也不碰驱动，改回来随时可以"],
            native={"where": which, "size": _size(cur), "now_hz": hz,
                    "ceiling_hz": top, "tiers": row.get("tiers", 0),
                    "adapter": row.get("adapter", "")},
        ))
    if out:
        return out

    first = live[0]
    extra = ""
    if len(live) > 1:
        extra = "另外 %d 块也各自核对过，都在自己那一档的最高处。" % (len(live) - 1)
    # The annex prints scalars only (html._tech_table drops lists and dicts), so
    # per-screen evidence has to arrive as one readable line, not as a table.
    each = "; ".join("%s 现 %d 顶 %d%s" % (_size(r[2]), r[3], r[4],
                                           "（主屏）" if r[1].get("primary") else "")
                     for r in live[:4])
    return [Finding(
        module="refresh", status=Status.GREEN, kind="refresh_ok",
        headline="屏幕刷新率已在这一分辨率能给的最高一档（%d Hz）" % first[3],
        plain="当前 %s、%d Hz，同一分辨率下最高也是 %d Hz。%s"
              % (_size(first[2]), first[3], first[4], extra),
        native={"screens": len(modes), "said_rate": len(live), "each": each},
        skip=True,
    )]


# ---------------------------------------------------- F: installed software

# InstallDate is a bare yyyymmdd string out of the registry, so comparing those
# eight characters is a date comparison: no parsing, no locale, no clock guesses.
# A date in the future is some installer's nonsense and gets dropped rather than
# counted as brand new.
_RECENT_DAYS = 90


def _recent(rows, limit=0):
    floor = time.strftime("%Y%m%d", time.localtime(time.time() - _RECENT_DAYS * 86400))
    today = time.strftime("%Y%m%d")
    dated = sorted((r for r in rows
                    if floor <= (r.get("installed_on") or "") <= today),
                   key=lambda r: r["installed_on"], reverse=True)
    return dated if limit <= 0 else dated[:limit]


def probe_apps(ctx):
    """Inventory plus the rule list - and only the rule list can make it red.

    The comparison hands match_bad a name and nothing else, on purpose. Two of
    its three ways to match want a command line and an install path, and those
    are exactly the two values this channel refuses to read (they carry
    C:\\Users\\<account> for per-user installs). So a hit here means the library
    was written against display names - the documented contract - never a
    keyword that happens to look suspicious.
    """
    try:
        book = native.installed_programs()
    except Exception:
        book = None
    if not book or not book.get("rows"):
        return [failed("applist", "已装软件清单没能读到")]

    rows = book["rows"]
    rules = getattr(ctx, "rules", None)
    recent = _recent(rows)
    per_user = sum(1 for r in rows if r.get("scope") == "user")
    # One readable line, not a list: the annex renderer keeps scalars and drops
    # anything list-shaped, and a clue that never prints is worse than none.
    tech = {"count": len(rows),
            "last_90d": "、".join(r["name"] for r in recent[:6])[:220] or "无",
            "recent_total": len(recent),
            "per_user": per_user,
            "unreadable": book.get("unreadable", 0),
            "incomplete": bool(book.get("truncated"))}

    hits = []
    if rules is not None:
        for row in rows:
            got = rules.match_bad({"name": row["name"], "command": "", "path": ""})
            if not got:
                continue
            hits.append(Finding(
                module="applist", status=Status.RED, kind="known_bad_app",
                headline="已装软件里有一条要处理：%s" % row["name"],
                plain=got.get("plain", "这一条写在规则库的名单里"),
                why=got.get("why", ""),
                steps=got.get("steps", ["在「设置 → 应用 → 已安装的应用」里找到它，"
                                        "确认自己不再需要了再卸载"]),
                native={"name": row["name"], "publisher": row["publisher"],
                        "version": row["version"], "scope": row["scope"]},
            ))
    if hits:
        rest = dict(tech)
        rest["count"] = len(rows) - len(hits)
        hits.append(Finding(
            module="applist", status=Status.GREEN, kind="app_list_rest",
            headline="其余 %d 个软件与名单无关" % rest["count"],
            plain="这一条不评价好坏，只说明剩下这些没被名单命中。",
            native=rest, skip=True,
        ))
        return hits

    gap = ""
    if book.get("truncated"):
        gap = "有几处位置没读完，这份清单可能偏少。"
    elif book.get("unreadable"):
        gap = "有 %d 处位置打不开，未计入清单。" % book["unreadable"]
    return [Finding(
        module="applist", status=Status.GREEN, kind="app_none_bad",
        headline="已装软件 %d 个，逐条比过规则库名单，没有命中" % len(rows),
        plain="其中 %d 个只装在当前登录的用户名下，这一类卸载不需要管理员权限。"
              "近三个月装了 %d 个，名字写在最后一栏，帮你装系统的人常问这个。%s"
              % (per_user, len(recent), gap),
        why="这一条只按名单整名比对，不靠名字像不像来猜。名单里没写的软件，"
            "本程序不判它好、也不判它坏——宁可漏，也不肯冤枉正常软件。",
        native=tech,
        skip=True,
    )]

# -------------------------------------------------------- G: sound endpoints

# DeviceState's low bits carry the meaning and real machines stack undocumented
# high bits on top (0x22000004 measured here), so every test masks. Only the
# disabled bit is a decision somebody made; not_streaming and unplugged are
# states a healthy device passes through whenever nothing is playing.
_SOUND_SPECS = (
    ("play", "播放设备", Status.RED,
     "不是坏了，是被人手动关掉的。这种状态下系统不弹窗、不记错，只是安静地没有声音。",
     ["点一下任务栏右下角的喇叭图标，看输出设备那一行有没有可以点的选择",
      "没有可选项，或者点了仍然没声：按 Win + I 打开设置，点「系统」，再点「声音」",
      "在「输出」下面点开「所有声音设备」（有的版本写作「更多声音设置」）",
      "在弹出的老窗口里，于设备列表的空白处点右键，勾上「显示禁用的设备」",
      "把要用的那一项（扬声器或耳机）右键点开，选「启用」；再右键选「设为默认设备」",
      "全程只做启用与设为默认这两下，不动别的设置；做完放一段视频或音乐确认",
      "老窗口里连这一项都找不到：按 Win + X 选「设备管理器」，展开"
      "「声音、游戏和视频控制器」，带向下箭头的图标要在这一层启用"],
     ),
    ("record", "录音设备", Status.YELLOW,
     "开会、录音、语音聊天都会收不到声音；如果这台机器从来不用麦克风，这一条可以放着不动。",
     ["按 Win + I 打开设置，点「系统」，再点「声音」",
      "往下找到「输入」，点开「所有声音设备」（有的版本写作「更多声音设置」）",
      "在弹出的老窗口里切到「录制」标签，在空白处点右键，勾上「显示禁用的设备」",
      "把麦克风右键点开，选「启用」，再右键选「设为默认设备」",
      "启用之后在「输入」那页对着说话，看音量条有没有跳动，跳了就是通了",
      "这一层找不到麦克风：按 Win + X 选「设备管理器」，在「音频输入或输出」里"
      "看有没有带向下箭头的图标"],
     ),
)


def _sound_group(rows, kind):
    pool = [r for r in rows if r.get("kind") == kind]
    disabled = [r for r in pool if r.get("disabled")]
    readable = [r for r in pool if r.get("active") or r.get("disabled")
                or r.get("not_streaming") or r.get("unplugged")]
    unplugged = [r for r in pool if r.get("unplugged")]
    return pool, disabled, readable, unplugged


def probe_audio(ctx):
    try:
        book = native.audio_endpoint_states()
    except Exception:
        book = None
    if not book or not book.get("rows"):
        return [failed("audio", "声音设备的情况没能读到")]

    out = []
    for kind, cn, level, plain, steps in _SOUND_SPECS:
        pool, disabled, readable, unplugged = _sound_group(book["rows"], kind)
        if not pool:
            continue
        tech = {"count": len(pool), "disabled": len(disabled),
                "unplugged": len(unplugged),
                "active": sum(1 for r in pool if r.get("active")),
                "incomplete": bool(book.get("truncated"))}
        if not readable:
            out.append(Finding(
                module="audio", status=Status.GRAY, kind="audio_unknown",
                headline="%s的状态词没能读懂" % cn,
                plain="系统报上来的这一串数字本程序不认识，不敢替你猜它是好是坏。",
                why="驱动写法各不相同，读不懂的判据宁可退回未获取，也不编一个结论出来。",
                native=tech, skip=True))
            continue
        if len(disabled) == len(pool):
            out.append(Finding(
                module="audio", status=level, kind="audio_disabled",
                headline="%s全部被停用（%d 个里没有一个启用）" % (cn, len(pool)),
                plain=plain,
                why="停用是要人一个一个手动按的开关，日常使用不会自己变成这样。常见于"
                    "照着某个调教声音的帖子改过，或者清理类软件顺手禁用了一整排。",
                steps=steps,
                native=tech,
            ))
            continue
        note = ""
        if disabled:
            note = "另有 %d 个当前是停用状态，想用哪个就在声音设置里把它设为默认。" % len(disabled)
        elif unplugged:
            note = "有 %d 个此刻显示没插东西，这是插拔状态，不算故障。" % len(unplugged)
        head = ("%s没有被停用（共 %d 个）" % (cn, len(pool)) if not disabled
                else "%s大体正常（%d 个里停用 %d 个）" % (cn, len(pool), len(disabled)))
        if tech["active"]:
            body = "%d 个里 %d 个此刻在活动状态，其余显示空闲——空闲是指这一会儿没有" \
                   "音频在走，不是坏了。" % (len(pool), tech["active"])
        else:
            body = "%d 个里没有一个被停用，也没有一个报活动：这种写法通常是此刻没有" \
                   "音频在走。" % len(pool)
        out.append(Finding(
            module="audio", status=Status.GREEN, kind="audio_ok",
            headline=head,
            plain=body + note,
            native=tech, skip=True,
        ))
    return out or [failed("audio", "声音设备的情况没能读到")]


# -------------------------------------------------------------- H: net cards

def probe_nic(ctx):
    """Physical against virtual, read off the flag the installer itself sets.

    The type field cannot make this split: five of the thirteen virtual rows on
    this machine report the same number real Ethernet uses (WAN miniports,
    Bluetooth PAN, kernel debug). The characteristics bit can, and it split
    cleanly. No address is read and none is needed - the fault here is "the
    system cannot see a card at all", which is a count, not an IP.
    """
    try:
        book = native.network_adapters()
    except Exception:
        book = None
    if not book or not book.get("rows"):
        return [failed("nic", "网卡登记情况没能读到")]

    rows = book["rows"]
    phys = [r for r in rows if r.get("physical")]
    virt = [r for r in rows if r.get("virtual")]
    hidden = sum(1 for r in rows if r.get("hidden"))
    nosvc = sum(1 for r in rows if r.get("no_service"))
    # Scalars again, because the annex drops anything list-shaped: the names a
    # helper needs are joined here, and the virtual list is capped hard since a
    # row of text past four hundred characters gets cut off by the renderer.
    tech = {"registered": len(rows),
            "physical": "、".join(r["name"] for r in phys[:4])[:160] or "无",
            "virtual": len(virt),
            "virtual_names": ("、".join((r["name"] or "?")[:28] for r in virt[:5])[:190]
                              or "无"),
            "hidden": hidden, "no_service": nosvc,
            "unreadable": book.get("unreadable", 0),
            "incomplete": bool(book.get("truncated"))}

    if not phys:
        return [Finding(
            module="nic", status=Status.YELLOW, kind="nic_no_physical",
            headline="登记在案的 %d 个网卡里，没有一个被标记为实体网卡" % len(rows),
            plain="上不了网时先看这一条。如果这台是虚拟机或者云桌面，本来就没有实体网卡，"
                  "可以放着不管；如果是摆在面前的笔记本或台式机，多半是网卡驱动没装好，"
                  "或者网卡被禁用了。",
            why="系统在登记网卡时写明这一块是实体还是虚拟，这里只读那一句标记。"
                "本程序不联网、也不读任何地址，所以看不出通不通，只看得出有没有。",
            steps=["先确认这是不是虚拟机：虚拟机里没有实体网卡是正常情况，这一条可以跳过",
                   "按 Win + X，选「设备管理器」",
                   "展开「网络适配器」，逐条看有没有带黄色感叹号或者向下箭头的图标",
                   "带向下箭头的是被禁用：右键它选「启用设备」",
                   "带黄色感叹号、或者列表里找不到任何写着 Wi-Fi、Ethernet、GbE 字样的"
                   "那一块：缺的是驱动，不是设置。把这份报告交给帮你装系统或卖电脑的人",
                   "本程序不会替你下载或安装任何东西，也不建议去第三方驱动站下所谓的"
                   "驱动合集，装机用的驱动只认笔记本、主板官网那一个来源"],
            native=tech,
        )]

    names = "、".join(r["name"] for r in phys[:2] if r["name"])
    tail = "有几处位置打不开，未计入。" if book.get("unreadable") else ""
    return [Finding(
        module="nic", status=Status.GREEN, kind="nic_ok",
        headline="实体网卡 %d 块%s，虚拟网卡 %d 个"
                 % (len(phys), ("（%s）" % names) if names else "", len(virt)),
        plain="虚拟网卡多不是病：虚拟机、代理与加速器类软件都会往里加，正常机器上这一摞"
              "数字本来就比实体网卡大得多。%s" % tail,
        native=tech,
        skip=True,
    )]


PROBES = [
    ("badges", "桌面图标角标", probe_badges, False),
    ("paging", "虚拟内存", probe_paging, False),
    ("toollocks", "系统工具锁定", probe_locks, False),
    ("drawlimits", "软件界面资源", probe_draw, False),
    ("refresh", "屏幕刷新率", probe_refresh, False),
    ("applist", "已装软件", probe_apps, False),
    ("audio", "声音设备", probe_audio, False),
    ("nic", "网卡", probe_nic, False),
]
