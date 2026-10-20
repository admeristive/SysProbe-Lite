"""Remember the last few scans beside the program, and say what changed.

Two rules shape this module. What lands on disk carries no sentence at all -
only module keys, probe kind keys and status codes, so a history file can never
leak a name, a path or an address the way free text might. And a comparison is
only made against a scan taken under the same program version, the same rule
library and the same permission level: an administrator's run sees readings a
normal run cannot, so the honest result of mixing them is "not comparable", not
"four more items are missing".
"""

import json
import os
import time
from collections import Counter

from .model import Status
from . import paths

SCHEMA = 1
KEEP = 12
NAME = "体检历史.json"

RANK = {Status.GRAY: 0, Status.GREEN: 1, Status.YELLOW: 2, Status.RED: 3}
SHORT = {
    "stability": "自动重启", "display": "画面显示", "network": "网络上网",
    "startup": "开机自启", "storage": "磁盘空间", "power": "电池电源",
    "badges": "桌面图标", "paging": "虚拟内存", "toollocks": "系统工具",
    "drawlimits": "界面资源", "refresh": "屏幕刷新", "applist": "已装软件",
    "audio": "声音", "nic": "网卡",
}
LEVEL = {Status.GREEN: "正常", Status.YELLOW: "要留意", Status.RED: "要处理"}

NO_PREV = "还没找到能对比的上一次记录，这次已经记下，下次体检就能比。"
NO_MATCH = "上次那次体检的条件和这次对不上（程序版本、规则库或权限不同），不拿来比。"
SHORT_NO_PREV = "还没可比的记录"
SHORT_NO_MATCH = "上次条件不同，不比较"
SHORT_NOWRITE = "这里不让写，没法比"


def path():
    directory, _ = paths.report_dir()
    return os.path.join(directory, NAME)


def build(findings, tool_version, rules_version, admin, ts=None):
    """The one record shape: counts, the worst call per module, the item multiset.

    Counts and module rows are both derived from items here rather than passed
    in, so the three views of the same scan cannot disagree with each other.
    """
    items = [[f.module, f.kind, f.status.value] for f in findings]
    counts = {s.value: sum(1 for f in findings if f.status is s) for s in Status}
    worst = {}
    for f in findings:
        cur = worst.get(f.module)
        if cur is None or RANK[f.status] > RANK[Status(cur)]:
            worst[f.module] = f.status.value
    return {
        "ts": ts or time.strftime("%Y-%m-%d %H:%M:%S"),
        "ver": tool_version,
        "rules": rules_version,
        "admin": bool(admin),
        "counts": counts,
        "worst": worst,
        "items": items,
    }


def load(where):
    """(records, why). A file we cannot read is reported, never half-trusted."""
    if not os.path.isfile(where):
        return [], "first"
    try:
        with open(where, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        return [], "broken: %s" % type(exc).__name__
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return [], "schema"
    scans = data.get("scans")
    if not isinstance(scans, list):
        return [], "schema"
    valid = {s.value for s in Status}
    clean = []
    for rec in scans:
        # The file sits in the report folder where a helper may open it with a
        # text editor, so a hand-edited status string is a real input, not a
        # theoretical one: it has to fail here instead of at the board.
        if (isinstance(rec, dict) and isinstance(rec.get("counts"), dict)
                and isinstance(rec.get("worst"), dict)
                and isinstance(rec.get("items"), list)
                and set(rec["counts"]) <= valid
                and set(rec["worst"].values()) <= valid
                and all(isinstance(i, list) and len(i) == 3 and i[2] in valid
                        for i in rec["items"])):
            clean.append(rec)
    if not clean and scans:
        return [], "schema"
    return clean, "ok"


def save(where, record, scans):
    """Rewrite the file from a temporary copy, so a crash leaves the old one."""
    body = {"schema": SCHEMA, "keep": KEEP, "scans": ([record] + scans)[:KEEP]}
    text = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    tmp = where + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    os.replace(tmp, where)
    return len(body["scans"])


def comparable(prev, cur):
    return (prev.get("ver") == cur.get("ver")
            and prev.get("rules") == cur.get("rules")
            and bool(prev.get("admin")) == bool(cur.get("admin")))


def pick(scans, cur):
    """Newest scan whose conditions match, or the reason there is none."""
    matched = [rec for rec in scans if comparable(rec, cur)]
    if matched:
        return matched[0], "ok"
    if scans:
        return None, "nomatch"
    return None, "empty"


def describe(prev, cur):
    """Two phrasings of the same arithmetic: the full one for the report, a
    short one for the window.

    The window cannot pay for a wrapped line: measured at 940x700, one extra
    full-width line costs two of the four conclusions that fit on the first
    screen. A report has no such budget, so it gets the sentence with the
    module names in it, and the window gets the count with the detail in its
    hover text.

    A reading that simply became visible or invisible stays out of the
    better/worse arithmetic: that number follows the permission level and the
    hardware present, not the machine's health.
    """
    clauses = []
    deltas = {}
    for status, name in ((Status.RED, "需处理"), (Status.YELLOW, "建议留意")):
        delta = cur["counts"].get(status.value, 0) - prev["counts"].get(
            status.value, 0)
        deltas[status] = delta
        if delta:
            clauses.append("%s%s %d 项" % (name, "多" if delta > 0 else "少",
                                          abs(delta)))
    moves = []
    for module in sorted(set(prev["worst"]) | set(cur["worst"])):
        was, now = prev["worst"].get(module), cur["worst"].get(module)
        if was == now:
            continue
        label = SHORT.get(module, module)
        if was is None:
            moves.append("%s（上次没查到，这次查到了）" % label)
        elif now is None:
            moves.append("%s（这次没查到结论）" % label)
        elif RANK[Status(was)] == 0 or RANK[Status(now)] == 0:
            seen = "这次看不到了" if now == Status.GRAY.value else "这次能看到了"
            moves.append("%s%s" % (label, seen))
        else:
            step = "比上次差" if RANK[Status(now)] > RANK[Status(was)] else "比上次好"
            moves.append("%s：上次%s，这次%s（%s）"
                         % (label, LEVEL.get(Status(was), "看不到"),
                            LEVEL.get(Status(now), "看不到"), step))
    if moves:
        text = "变的是 %d 项：%s" % (len(moves), "；".join(moves[:2]))
        if len(moves) > 2:
            text += "；另有 %d 项也变了" % (len(moves) - 2)
        clauses.append(text)
    if not clauses:
        return "结论和上次一条没变。", "没变化"
    for status, name in ((Status.RED, "需处理"), (Status.YELLOW, "建议留意")):
        if deltas[status]:
            return ("；".join(clauses) + "。",
                    "%s%s %d 项" % (name, "多" if deltas[status] > 0 else "少",
                                    abs(deltas[status])))
    return "；".join(clauses) + "。", "有 %d 项变了" % len(moves)


def observe(findings, tool_version, rules_version, admin, note=None):
    """Compare with the last comparable scan, then store this one.

    The window always gets a line, because silence reads as "nothing to say"
    when the real cause is a first run, a version change or a folder that
    refuses writes - and those three need telling. Every filesystem surprise
    ends up in `note` for the local log; the board never loses a finding
    because a history file misbehaved.
    """
    log = note or (lambda kind, text: None)
    cur = build(findings, tool_version, rules_version, admin)
    where = path()
    try:
        scans, state = load(where)
    except OSError as exc:
        log("历史记录", "读取失败：%s" % type(exc).__name__)
        return {"record": cur, "why": "read", "text": NO_PREV,
                "short": SHORT_NO_PREV, "known": 0}
    if state not in ("ok", "first"):
        log("历史记录", "这份记录用不了（%s），重新开始记" % state)
    history = scans if state == "ok" else []
    prev, why = pick(history, cur)
    text = ""
    short = ""
    if prev is not None:
        full, short = describe(prev, cur)
        text = "和 %s 那次比：%s" % (prev["ts"][5:16], full)
    try:
        kept = save(where, cur, history)
        log("历史记录", "写入 %s，留 %d 次" % (where, kept))
    except OSError as exc:
        log("历史记录", "写入失败：%s" % type(exc).__name__)
        return {"record": cur, "why": why, "known": 0, "short": SHORT_NOWRITE,
                "text": "还没找到能对比的上一次记录，"
                        "而且这个位置不让写，这次没法留下来下次比。"}
    if prev is None:
        text = NO_MATCH if why == "nomatch" else NO_PREV
        short = SHORT_NO_MATCH if why == "nomatch" else SHORT_NO_PREV
    return {"record": cur, "why": why, "text": text, "short": short,
            "known": kept}
