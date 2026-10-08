"""Shared data model. Status carries a shape+word so colour is never the only cue."""

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    RED = "red"
    YELLOW = "yellow"
    GREEN = "green"
    GRAY = "gray"


GLYPH = {
    Status.RED: "需处理",
    Status.YELLOW: "建议留意",
    Status.GREEN: "正常",
    Status.GRAY: "未获取",
}

MARK = {Status.RED: "●", Status.YELLOW: "▲", Status.GREEN: "○", Status.GRAY: "-"}

ORDER = [Status.RED, Status.YELLOW, Status.GREEN, Status.GRAY]


@dataclass
class Finding:
    module: str
    status: Status
    headline: str
    plain: str = ""
    why: str = ""
    steps: list = field(default_factory=list)
    copy_cmd: str = ""
    native: dict = field(default_factory=dict)
    kind: str = ""
    skip: bool = False
    needs_admin: bool = False

    def to_dict(self):
        return {
            "module": self.module,
            "status": self.status.value,
            "headline": self.headline,
            "plain": self.plain,
            "why": self.why,
            "steps": list(self.steps),
            "copy_cmd": self.copy_cmd,
            "native": dict(self.native),
            "kind": self.kind,
            "skip": self.skip,
            "needs_admin": self.needs_admin,
        }

    @classmethod
    def from_dict(cls, d):
        f = cls(module=d.get("module", ""), status=Status(d.get("status", "gray")),
                headline=d.get("headline", ""))
        f.plain = d.get("plain", "")
        f.why = d.get("why", "")
        f.steps = list(d.get("steps", []))
        f.copy_cmd = d.get("copy_cmd", "")
        f.native = dict(d.get("native", {}))
        f.kind = d.get("kind", "")
        f.skip = bool(d.get("skip", False))
        f.needs_admin = bool(d.get("needs_admin", False))
        return f


def failed(module, reason="未能获取"):
    """A visible-but-calm placeholder. Never an empty row, never a dialog."""
    return Finding(module=module, status=Status.GRAY,
                   headline=reason,
                   plain="这一项没取到数据，不影响其他检查项。",
                   kind="probe_failed")
