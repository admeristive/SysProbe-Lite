"""Fault rule library.

`故障规则库.json` sits next to the exe so a user can edit it. Because a novice will
eventually break that file, the built-in DEFAULTS below are the real source of truth
and the file is treated as an override. A corrupt file must never stop a scan.
"""

import json
import os

SCHEMA_VERSION = 1

DEFAULTS = {
    "schema": SCHEMA_VERSION,
    "version": "2026.10.08",
    "reviewed": "2026.10.08",
    "whea": {
        # 1/17/18/19 are the corrected-and-page-isolation family; 3 is fatal.
        # Kept in the rule file rather than in code because the mapping is the
        # kind of thing that needs a correction without rebuilding the program.
        "corrected": ["1", "17", "18", "19"],
        "uncorrected": ["3"],
    },
    "steps": {
        "bsod": [
            "记住报告里给出的原因和文件名，这是最有用的线索",
            "到笔记本/主板官网（不要用第三方驱动站）更新显卡、网卡、芯片组驱动",
            "卸载最近新装的驱动类、杀毒类、游戏修改类软件，观察一到两周",
            "如果反复出现同一个原因，把它交给维修点或售后，比描述\"电脑老重启\"有用得多",
        ],
    },
    # known_bad is intentionally shipped empty. Naming a vendor as malware in a
    # file that ships to thousands of machines is both a false-positive machine and
    # a legal exposure; the matcher below is what needs to be right, the list is
    # yours to fill. `name`/`exe` compare whole values, `path_prefix` compares
    # whole directory segments - never loose keywords.
    "known_bad": [],
}


def _norm_prefix(value):
    """Normalise a path rule so it can only ever match whole directory segments.

    A bare word would match inside another folder name (`king` inside
    `KingsoftWPS`), which is the false-positive class this matcher exists to
    block, so segment rules get backslash delimiters on both sides.
    """
    v = value.strip().strip('"').lower().replace("\\\\", "\\")
    if not v:
        return ""
    if ":" in v:  # drive-anchored rule: still anchored, just normalised
        return v if v.endswith("\\") else v + "\\"
    return "\\" + v.strip("\\") + "\\"


class Rules:
    def __init__(self, path=None, load_error=None):
        self.data = json.loads(json.dumps(DEFAULTS))
        self.path = path
        self.load_error = load_error
        self.external = False
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8-sig") as handle:
                    loaded = json.load(handle)
                if not isinstance(loaded, dict):
                    raise ValueError("top level must be an object")
                if int(loaded.get("schema", 0)) != SCHEMA_VERSION:
                    raise ValueError("schema mismatch")
                for key in ("whea", "steps", "known_bad", "version", "reviewed"):
                    if key in loaded:
                        self.data[key] = loaded[key]
                self.external = True
            except (OSError, ValueError, TypeError, AttributeError) as exc:
                self.load_error = "%s: %s" % (type(exc).__name__, exc)

    # ------------------------------------------------------------- accessors
    @property
    def version(self):
        return str(self.data.get("version", ""))

    @property
    def reviewed(self):
        return str(self.data.get("reviewed", ""))

    @property
    def whea_corrected(self):
        return {str(x) for x in self.data.get("whea", {}).get("corrected", [])}

    @property
    def whea_uncorrected(self):
        return {str(x) for x in self.data.get("whea", {}).get("uncorrected", [])}

    def steps(self, kind, default=()):
        got = self.data.get("steps", {}).get(kind)
        return list(got) if isinstance(got, list) and got else list(default)

    def known_bad(self):
        entries = self.data.get("known_bad", [])
        return entries if isinstance(entries, list) else []

    # ---------------------------------------------------------------- matcher
    def match_bad(self, item):
        """`name` and `exe` are whole-value comparisons. `path_prefix` matches a
        directory segment at any drive and any depth, because a bundled junk folder
        is the same junk folder whether it lands on C: or on
        `D:\\游戏\\Downloads\\`. It is still not a keyword match - a rule of
        "update" or "helper" flags Steam, Adobe and every vendor updater, which is
        exactly the panic this program exists to prevent. And a prefix must name a
        product directory, not a company: `\\Kingsoft\\` would mark that company's
        legitimate office suite red."""
        name = (item.get("name") or "").strip().lower()
        command = (item.get("command") or "").strip().lower().replace("\\\\", "\\")
        path = (item.get("path") or "").strip().lower().replace("\\\\", "\\")
        for entry in self.known_bad():
            if not isinstance(entry, dict):
                continue
            want_name = str(entry.get("name", "")).strip().lower()
            want_exe = str(entry.get("exe", "")).strip().lower()
            want_prefix = _norm_prefix(str(entry.get("path_prefix", "")))
            if want_name and name == want_name:
                return entry
            if want_exe:
                base = os.path.basename(path).strip('"')
                if base and base == want_exe:
                    return entry
            if want_prefix and want_prefix in path:
                return entry
            if want_exe and ("\\%s" % want_exe) in command:
                return entry
        return None


def load(root_dir):
    path = os.path.join(root_dir, "故障规则库.json")
    return Rules(path if os.path.isfile(path) else None)
