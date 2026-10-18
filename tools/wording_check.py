"""Wording gate: every sentence this program can put in front of a novice.

The live GUI smoke check only sees the branches this machine happens to hit, so
a red row that never fires on this laptop can ship with "0xc000007b" printed on
it unnoticed. This gate reads the source instead: it pulls the prose out of the
AST (the fields of every Finding, the lookup tables that prose is built from,
the UI widgets' own strings) plus the human-facing text shipped in the rule
library, and scans it against one shared banned-word list.

What it cannot see is text that only exists at run time - a process name from
the event log, a startup entry's own label. Those stay covered by gui_smoke.

    py -3 tools/wording_check.py

Exit 0 means clean; 1 means a banned word is printed somewhere a person reads.
"""

import ast
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# One list, three consumers (this gate, gui_smoke, limits_selftest). A word that
# only one of them knows about is a word that can still ship.
BANNED_WORDS = [
    "WHEA", "TDR", "0x", "sfc", "sc query", "PowerShell", "EventID", "Registry",
    "HKLM", "HKCU", "ctypes", "XPath", "Defender",
    "句柄", "HANDLE", "OpenProcess", "EnumWindows", "winreg", "十六进制", "GDI",
    "CLSID", "InprocServer", "Wow6432Node", "ShellIconOverlayIdentifiers",
    "PagingFiles", "pagefile.sys", "DLL", "进程号", "PID",
]

# Prose never lives in a string without Chinese in it: registry paths, dll names
# and error codes are all ASCII, and scanning those would drown the real hits.
PROSE_KEYS = {"headline", "plain", "why", "steps", "copy_cmd"}
# Helpers that take their prose positionally, so keyword matching misses them.
PROSE_HELPERS = {"failed"}
# The crash log is written for whoever maintains this program and never shown on
# screen, so its diagnostic strings are exempt - on purpose, in one place.
LOG_SINKS = {"note"}
WIDGET_SETTERS = {"setText", "setWindowTitle", "setPlaceholderText",
                  "setToolTip", "setStatusTip", "addItem", "addTab"}


def has_cjk(text):
    for ch in text:
        if "\u4e00" <= ch <= "\u9fff":
            return True
    return False


def strings_in(node, skip=frozenset()):
    return [c.value for c in ast.walk(node)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
            and id(c) not in skip and has_cjk(c.value)]


def collect_py(path):
    """Return (label, text) pairs for every human-facing literal in one file."""
    with io.open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    rel = os.path.relpath(path, ROOT).replace("\\", "/")
    widget_file = "/ui/" in ("/" + rel)
    # Text handed to the log sink is evidence for a developer, not prose for a
    # person holding the machine - exempt it before the sweep, or "pid=" in the
    # log line reads as a violation.
    logged = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in LOG_SINKS:
            logged.update(id(c) for c in ast.walk(node)
                          if isinstance(c, ast.Constant))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            # A table is prose when its strings are Chinese: _APPCODE's hints and
            # MODULE_LABEL get read out to a person, a tuple of dll names does not.
            for value in _assign_values(node):
                for text in strings_in(value, logged):
                    out.append(("%s:表" % rel, text))
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            texts = []
            for kw in node.keywords:
                if kw.arg in PROSE_KEYS or (name in WIDGET_SETTERS
                                            and kw.arg == "string"):
                    texts.extend(strings_in(kw.value, logged))
            if name in WIDGET_SETTERS or name in PROSE_HELPERS:
                for arg in node.args:
                    texts.extend(strings_in(arg, logged))
            for text in texts:
                out.append(("%s:%d" % (rel, node.lineno), text))
    if widget_file:
        # Widget strings are written everywhere (layout helpers, message boxes),
        # so in the UI package everything Chinese counts as prose.
        for const in ast.walk(tree):
            if isinstance(const, ast.Constant) and isinstance(const.value, str) \
                    and id(const) not in logged and has_cjk(const.value):
                out.append(("%s:%d" % (rel, const.lineno), const.value))
    return out


def _assign_values(node):
    return [node.value] if node.value is not None else []


def _call_name(node):
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def collect_json(path):
    with io.open(path, "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    rel = os.path.basename(path)
    out = []
    # steps[kind] and any free-text note per rule reach the screen; the matching
    # patterns (exe, path_prefix) are deliberately lowercase machine strings.
    for kind, rows in (data.get("steps") or {}).items():
        texts = rows if isinstance(rows, list) else [rows]
        for text in texts:
            if isinstance(text, str) and has_cjk(text):
                out.append(("%s:steps/%s" % (rel, kind), text))
    for entry in data.get("known_bad") or []:
        for key, text in entry.items():
            if key in ("exe", "path_prefix", "name", "path"):
                continue
            texts = text if isinstance(text, list) else [text]
            for item in texts:
                if isinstance(item, str) and has_cjk(item):
                    out.append(("%s:known_bad/%s" % (rel, key), item))
    for key in ("说明", "known_bad_用法说明"):
        text = data.get(key)
        if isinstance(text, str) and has_cjk(text):
            out.append(("%s:%s" % (rel, key), text))
    return out


def scan(pairs):
    bad = []
    for label, text in pairs:
        low = text.lower()
        for word in BANNED_WORDS:
            if word.lower() in low:
                bad.append((label, word, text))
    return bad


def main():
    pairs = []
    files = 0
    for base, dirs, names in os.walk(os.path.join(ROOT, "sysprobe")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in names:
            if name.endswith(".py"):
                files += 1
                pairs.extend(collect_py(os.path.join(base, name)))
    library = os.path.join(ROOT, "故障规则库.json")
    if os.path.exists(library):
        pairs.extend(collect_json(library))

    # A gate nobody proved fires is a rumour. Feed it one bad sentence and insist
    # it catches it.
    proof = scan([("自检注入", "如果提示缺少 dll 或 0xc000007b 就要补装")])
    print("闸口自检：故意塞一条含禁词的文案 -> 命中 %d 处（应为 2）%s"
          % (len(proof), "" if proof else "  <- 闸口失效"))

    print("扫了 %d 个 .py 文件 + 规则库，取出 %d 条会给人读的文字"
          % (files, len(pairs)))
    if len(pairs) < 150:
        print("取出条数低于 150，提取环节多半坏了（宁可当失败处理）")
        return 1

    bad = scan(pairs)
    if bad:
        print("\n人读文字里的底层词汇：")
        for label, word, text in bad[:40]:
            print("  %-34s 含「%s」：%s" % (label, word, text[:70]))
        if len(bad) > 40:
            print("  ...另有 %d 处" % (len(bad) - 40))
        print("\n不通过：%d 处" % len(bad))
        return 1
    print("\n通过：%d 条人读文字里没有一个底层词汇" % len(pairs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
