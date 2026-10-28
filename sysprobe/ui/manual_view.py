"""The handbook window: six pages of static text, no scan required.

Reached from one button that is enabled before the first体检, because the
questions it answers ("这个文件夹能删吗") arrive long before anyone presses
开始体检. It reads only sysprobe.manual, so nothing here can leak a machine
value into a page, and it writes nothing.

Six tabs rather than one long scroll: the person is looking for one answer, and
six titles read faster than nine screens of body text.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QTabWidget,
    QVBoxLayout, QWidget,
)

from .. import manual, theme
from .main_window import BODY_LS, _para


def _row(name, what, action):
    """One entry: the name at the card-title size, then what it is and what to do."""
    box = QFrame()
    box.setObjectName("Card")
    line = QVBoxLayout(box)
    line.setContentsMargins(14, 11, 14, 12)
    line.setSpacing(4)
    head = QLabel(name)
    head.setObjectName("Head")
    body = QLabel("<div style=\"line-height:%d%%\">%s%s</div>"
                  % (BODY_LS, _para("这是什么：" + what),
                     _para("怎么办：" + action) if action else ""))
    body.setObjectName("Plain")
    body.setWordWrap(True)
    body.setTextFormat(Qt.RichText)
    line.addWidget(head)
    line.addWidget(body)
    return box


class _Page(QWidget):
    """One page: its own lead sentence, then its rows, inside a scroll area."""

    def __init__(self, page):
        super().__init__()
        box = QVBoxLayout(self)
        box.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        body.setObjectName("Board")
        grid = QVBoxLayout(body)
        grid.setContentsMargins(12, 12, 12, 12)
        grid.setSpacing(9)
        lead = QLabel(page["一句话"])
        lead.setObjectName("GroupHead")
        lead.setWordWrap(True)
        grid.addWidget(lead)
        for name, what, action in page["条目"]:
            grid.addWidget(_row(name, what, action))
        grid.addStretch(1)
        scroll.setWidget(body)
        box.addWidget(scroll)


class ManualDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("新手手册")
        self.resize(900, 640)
        self.setMinimumSize(700, 480)
        self.setStyleSheet(theme.qss())

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(10)

        intro = QLabel("这里讲的是看懂电脑需要什么，不是替你动电脑。"
                       "手册里没有一个字会让你少个文件夹。")
        intro.setObjectName("Plain")
        intro.setWordWrap(True)
        outer.addWidget(intro)

        tabs = QTabWidget()
        self._tabs = tabs
        for page in manual.pages():
            tabs.addTab(_Page(page), page["标题"])
        asking = {"标题": manual.ASK_TITLE, "一句话": manual.ASK_ONE,
                  "条目": [("第 %d 句" % (n + 1), line, "")
                           for n, line in enumerate(manual.ASK_LINES)]}
        tabs.addTab(_Page(asking), manual.ASK_TITLE)
        outer.addWidget(tabs, 1)

        row = QHBoxLayout()
        row.setSpacing(8)
        hint = QLabel("手册里没写到的问题，体检报告末尾那句会教你怎么问人。")
        hint.setObjectName("Plain")
        hint.setWordWrap(True)
        close = QPushButton("关 闭")
        close.clicked.connect(self.accept)
        row.addWidget(hint, 1)
        row.addWidget(close)
        outer.addLayout(row)

    def pages(self):
        return self._tabs.count()
