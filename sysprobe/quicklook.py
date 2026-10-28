"""One glance at the numbers a novice reads wrong.

The board judges faults. This is different: four plain quantities, measured in
well under a second, shown so that "我电脑卡" has a number next to it before
anything is concluded - memory left, video memory fitted, temp files waiting,
recycle bin waiting.

Nothing here is a rule and nothing is a verdict. A machine with 8 GB of video
memory is not broken; the sentence only says what the machine has, so the
person can compare it against what the game or the software asked for.

Costs measured on this machine (2026-10-28), all at ordinary privilege:

* memory: one call, no walk;
* video memory: reading the display adapter's own registration, ~0.01 s, and
  it returns the fitted size only - live usage would need a graphics API we
  deliberately do not ship, because a resident monitor is exactly what this
  program promised never to be;
* temp folder: 550 folders, 0.04 s;
* recycle bin: one shell call.

A full drive-wide "who is holding my space" walk was measured and rejected:
the user's Local app-data alone took 6.83 s over 14,224 folders and returned
22.19 GB, while a three-level skim took 1.87 s and returned 29.51 GB for the
whole of C - which is a *bigger* number than the deep pass on one folder, so
the cheap shape of this question reports fiction. That is why the temp and bin
numbers here are named spots, not a ranking.
"""

import os
import time
import winreg

from . import native

_CLASS_KEY = ("SYSTEM\\CurrentControlSet\\Control\\Class"
              "\\{4d36e968-e325-11ce-bfc1-08002be10318}")
_TEMP_CAP = 4000
_TEMP_BUDGET = 2.0

MISSING = "没量到"

# Both reports and the window quote this one line, so the caveat that the
# numbers are a snapshot - not a verdict - cannot be worded three ways.
NOTE = ("这几个数是打开程序这一刻量到的，不是结论。游戏或软件闪退时，"
        "先拿这里的显存、内存去对软件自己提的要求。")


def _gb(raw):
    return raw / 1024.0 ** 3


def _video_memory():
    """Fitted video memory per adapter, and how many adapters said so.

    The value is the card's own registration, not a live reading, so it is
    stable and readable without elevation. Some drivers store it as a wide
    integer and some as eight raw bytes, which is why both shapes are handled.
    """
    sizes = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CLASS_KEY) as root:
            index = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                if not sub.isdigit():
                    continue
                try:
                    with winreg.OpenKey(root, sub) as key:
                        try:
                            desc = str(winreg.QueryValueEx(key, "DriverDesc")[0])
                        except OSError:
                            continue
                        for name in ("HardwareInformation.qwMemorySize",):
                            try:
                                raw, kind = winreg.QueryValueEx(key, name)
                            except OSError:
                                continue
                            if isinstance(raw, (bytes, bytearray)):
                                if len(raw) < 8:
                                    continue
                                raw = int.from_bytes(raw[:8], "little")
                            elif kind == 4 and raw >= 2 ** 31:
                                # A 32-bit field cannot hold a big card; such a
                                # value is the classic truncated lie, so drop it
                                # rather than print 2 GB for an 8 GB board.
                                continue
                            if raw > 0:
                                sizes[desc] = max(sizes.get(desc, 0), int(raw))
                            break
                except OSError:
                    continue
    except OSError:
        return None, 0
    if not sizes:
        return None, 0
    return max(sizes.values()), len(sizes)


def _temp_folder():
    """Bytes waiting in the caller's own temp folder. Returns (bytes, partial)."""
    top = os.environ.get("TEMP") or os.environ.get("TMP") or ""
    if not top or not os.path.isdir(top):
        return None, False
    total = 0
    nodes = 0
    partial = False
    started = time.time()
    stack = [top]
    while stack:
        current = stack.pop()
        nodes += 1
        if nodes > _TEMP_CAP or time.time() - started > _TEMP_BUDGET:
            partial = True
            break
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total, partial


def read():
    """The four quantities, each None when it could not be obtained.

    Every field is independent: a machine whose shell call refuses, or whose
    graphics driver hides its registration, still gets the other three. This
    never raises, because a glance is not worth losing a scan over.
    """
    out = {"mem_load": None, "mem_avail": None, "mem_total": None,
           "vram": None, "vram_cards": 0, "temp": None, "temp_partial": False,
           "bin": None, "bin_items": 0}
    try:
        mem = native.memory_commit()
        if mem:
            out["mem_load"] = mem["load_percent"]
            out["mem_avail"] = _gb(mem["avail_phys"])
            out["mem_total"] = _gb(mem["total_phys"])
    except Exception:
        pass
    try:
        vram, cards = _video_memory()
        if vram:
            out["vram"] = _gb(vram)
            out["vram_cards"] = cards
    except Exception:
        pass
    try:
        raw, partial = _temp_folder()
        if raw is not None:
            out["temp"] = _gb(raw)
            out["temp_partial"] = partial
    except Exception:
        pass
    try:
        got = native.recycle_bin("C:")
        if got:
            out["bin"] = _gb(got["bytes"])
            out["bin_items"] = got["items"]
    except Exception:
        pass
    return out


def sentence(d):
    """One line of plain text, for the status bar and both reports."""
    parts = []
    if d.get("mem_avail") is not None:
        parts.append("内存还剩 %.1f GB（已用 %d%%）"
                     % (d["mem_avail"], d.get("mem_load") or 0))
    else:
        parts.append("内存" + MISSING)
    if d.get("vram") is not None:
        more = "" if d.get("vram_cards", 1) <= 1 else "，共 %d 块" % d["vram_cards"]
        parts.append("显存 %s%.1f GB%s（装了多少，不是此刻用了多少）"
                     % ("约 " if more else "", d["vram"], more))
    else:
        parts.append("显存" + MISSING)
    if d.get("temp") is not None:
        tail = "以上" if d.get("temp_partial") else ""
        parts.append("临时文件 %s%.1f GB%s" % ("约 " if tail else "",
                                              d["temp"], tail))
    else:
        parts.append("临时文件" + MISSING)
    if d.get("bin") is not None:
        parts.append("回收站 %d 项、%s" % (d["bin_items"],
                                          "空" if d["bin"] < 0.05
                                          else "%.1f GB" % d["bin"]))
    else:
        parts.append("回收站" + MISSING)
    return " ｜ ".join(parts)


def glance():
    """Measure and return the sentence, or None when nothing could be read."""
    try:
        d = read()
    except Exception:
        return None
    if d["mem_avail"] is None and d["vram"] is None and d["temp"] is None:
        return None
    return sentence(d)
