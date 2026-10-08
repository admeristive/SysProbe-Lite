"""Event log access through the signed system tool wevtutil.exe.

Measured on Windows 11 10.0.26300, non-elevated:
  * `wevtutil qe System "/q:<xpath>" /f:xml /c:20` returns the **oldest** 20
    matches of the window. `/rd:true` is required to get the newest ones.
    `/r:true` is not a valid switch (exit code 87).
  * One call costs 79-91 ms wall clock, so a handful of bounded queries is cheap
    and there is no reason to ever walk a log.

pywin32 is deliberately not used: its `pywintypes311.dll` is the single most
common cause of "works on my machine, DLL load failed on the user's machine"
for PyInstaller builds, and this project's whole promise is that a novice can
double-click one file.
"""

import os
import re
from xml.etree import ElementTree as ET

from . import native

WEVTUTIL = os.path.join(native.SYSTEM_ROOT, "System32", "wevtutil.exe")
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_MS_PER_DAY = 86400000


def window_ms(days):
    return int(days * _MS_PER_DAY)


def since(days):
    return "TimeCreated[timediff(@SystemTime) <= %d]" % window_ms(days)


def build(*event_clauses, days=30):
    """Wrap provider/event-id clauses in one System[] predicate with a time bound.

    `*[System[A] and System[B]]` is invalid - every predicate must live inside the
    single System[] node.
    """
    inner = " and ".join("(%s)" % clause for clause in event_clauses)
    return "*[System[%s and %s]]" % (since(days), inner)


def _ids(*pairs):
    """(provider, id...) -> XPath fragment."""
    parts = []
    for provider, ids in pairs:
        ors = " or ".join("EventID=%d" % i for i in ids)
        parts.append("(Provider[@Name='%s'] and (%s))" % (provider, ors))
    return " or ".join(parts)


XPATH = {
    "crash": ("System", build(_ids(
        ("Microsoft-Windows-Kernel-Power", (41,)),
        ("Microsoft-Windows-WER-SystemErrorReporting", (1001,)),
        ("EventLog", (6008,)),
    ), days=30)),
    "whea": ("System", build(
        "Provider[@Name='Microsoft-Windows-WHEA-Logger']", days=30)),
    "tdr": ("System", build(_ids(("Display", (4101, 4102, 4103))), days=30)),
    "appcrash": ("Application", build(_ids(
        ("Application Error", (1000,)),
        ("Application Hang", (1002,)),
        ("Windows Error Reporting", (1001,)),
    ), days=7)),
}


class EventLogError(Exception):
    pass


def query(channel, xpath, max_records=20, timeout=8.0):
    if not os.path.isfile(WEVTUTIL):
        raise EventLogError("wevtutil.exe not found")
    argv = [WEVTUTIL, "qe", channel, "/q:" + xpath, "/f:xml",
            "/c:%d" % int(max_records), "/rd:true"]
    rc, out, err = native.run_readonly(argv, timeout=timeout)
    if rc == -1:
        raise EventLogError("TIMEOUT")
    if rc != 0 and not out.strip():
        raise EventLogError("wevtutil rc=%s" % rc)
    return _parse_stream(out)


def _parse_stream(text):
    """wevtutil emits bare <Event/> fragments; they need a throwaway root."""
    cleaned = re.sub(r"^\ufeff", "", text).strip()
    if not cleaned:
        return []
    try:
        root = ET.fromstring("<root>%s</root>" % cleaned)
    except ET.ParseError:
        # One malformed record must not void the whole channel.
        return _salvage(cleaned)
    out = []
    for node in root.findall(NS + "Event"):
        row = _one(node)
        if row:
            out.append(row)
    return out


def _salvage(blob):
    out = []
    for chunk in re.findall(r"<Event\b.*?</Event>", blob, re.S):
        try:
            node = ET.fromstring(chunk)
        except ET.ParseError:
            continue
        row = _one(node)
        if row:
            out.append(row)
    return out


def _one(node):
    sysel = node.find(NS + "System")
    if sysel is None:
        return None
    provider = sysel.find(NS + "Provider")
    time_node = sysel.find(NS + "TimeCreated")
    computer = sysel.find(NS + "Computer")
    eventid = (sysel.findtext(NS + "EventID") or "").strip()
    data = {}
    ev = node.find(NS + "EventData")
    if ev is not None:
        for pos, item in enumerate(ev.findall(NS + "Data")):
            data[str(pos)] = (item.text or "").strip()
        named = ev.find(NS + "Data")
        if named is not None:
            data["_names"] = [d.get("Name", "") for d in ev.findall(NS + "Data")]
    return {
        "event_id": eventid,
        "provider": provider.get("Name", "") if provider is not None else "",
        "time": time_node.get("SystemTime", "") if time_node is not None else "",
        "level": (sysel.findtext(NS + "Level") or "").strip(),
        "computer": computer.text if computer is not None else "",
        "channel": (sysel.findtext(NS + "Channel") or "").strip(),
        "data": data,
    }


def by_id(rows, event_id):
    return [r for r in rows if r["event_id"] == str(event_id)]
