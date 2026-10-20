"""Main window: one big button, one traffic-light board, no jargon.

Three rules shape everything below:
  * a status is never colour alone - each group of rows is headed by the word,
    and anything that is not normal also carries a pill of its own;
  * nothing is opened or switched to on the user's behalf;
  * raw readings (event ids, hexadecimal codes) stay out of the window.
"""

import os
import sys
import time
from html import escape

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QFrame, QGraphicsDropShadowEffect, QGridLayout,
    QHBoxLayout,
    QLabel, QMainWindow, QProgressBar, QPushButton, QScrollArea, QSizePolicy,
    QStatusBar,
    QVBoxLayout, QWidget,
)

from .. import history, paths, probes, report, theme
from ..model import GLYPH, MARK, ORDER, Finding, Status
from ..probes import os_label
from .elevate import relaunch_as_admin
from .worker import ScanWorker


TAG_STATUS = {Status.RED: "red", Status.YELLOW: "yellow",
              Status.GREEN: "green", Status.GRAY: "gray"}
# The type ramp, four steps: a verdict line, a card title, the body that
# explains it, and only then the aside. What is left at 12px is a label that
# names something (status pill, group head), never a sentence.
# Measured on this machine at the real column width of 413 px: every headline
# still fits one line at 18px, and a body goes from 2.1 lines at 12px to 2.3 at
# 14px - one card in eleven gains a line.
#
# QSS supports no letter-spacing and no font-feature-settings (measured here: a
# 14px label is 110 px at -1, 0 and +1 px; tnum is an empty operation because
# YaHei's digits are already tabular - 66 px for ten of them either way).
# Nothing in this window needs letterspaced Latin.
# exactly the glyph height (14px font measured at 19px per line). Qt Style Sheets
# have no line-height, but a QLabel in rich text does honour it - two lines of
# 14px measured 36 px at 100%, 54 px at 150%, 72 px at 200%.
BODY_LS = 150

# The mascot. One bundled png, one line of speech that changes with the state -
# she is not allowed to chatter, and she never names a setting to change.
MASCOT_NAME = "小检 · 本机体检员"
MASCOT_FILE = "mascot.png"
MASCOT_SAY = {
    "idle": "点旁边的按钮就开始。我只读不改，全程不联网。",
    "running": "正在逐条核对，稍等一下。",
    "clean": "都正常，没有要动的地方。",
    "watch": "没有要命的毛病，但有 %d 处值得留意，往下翻。",
    "fix": "有 %d 处要先处理，就在最上面几张卡里。",
    "broken": "这一轮没跑完，原因写在电脑本地的日志里。",
}

# The word for a status is written once, above its group, instead of eleven
# times on eleven identical pills. Colour still never carries the meaning alone.
GROUP_TITLE = {
    Status.RED: "要处理的",
    Status.YELLOW: "值得留意的",
    Status.GREEN: "都正常的",
    Status.GRAY: "这次没取到的",
}

# A person says what hurts - they do not look up a module name. Six words, each
# mapped onto keys the probes really emit (see MODULE_LABEL in the report), and
# short enough that the row still fits one line at the 760 px minimum. Two
# modules are deliberately on no chip (the icon marks and the restricted system
# tools): nobody asks for them by symptom, so 都看 stays the way to see them.
SYMPTOMS = (
    ("开机慢", ("startup", "paging", "storage", "applist")),
    ("上网卡", ("network", "nic")),
    ("屏幕闪", ("display", "refresh", "drawlimits")),
    ("没声音", ("audio",)),
    ("自己重启", ("stability", "display")),
    ("发烫", ("power",)),
)
SYMPTOM_ALL = "都看"


def _mascot_pixmap(height):
    """The bundled picture, or None when it is missing or cannot be decoded.

    A frozen build without the imageformats plugin, or a user who deleted a file
    from _internal, must not cost them the whole window.
    """
    try:
        path = paths.asset_path(MASCOT_FILE)
        if not os.path.isfile(path):
            return None
        pm = QPixmap(path)
        if pm.isNull():
            return None
        return pm.scaledToHeight(height, Qt.SmoothTransformation)
    except Exception:
        return None


def _para(text):
    """One body block with real line spacing.

    Everything reaching here is escaped first: a finding can carry a path or an
    address with angle brackets, and rich text would otherwise eat them.
    """
    return ('<div style="line-height:%d%%">%s</div>'
            % (BODY_LS, escape(text).replace("\n", "<br>")))


def _detail_lines(finding):
    lines = []
    if finding.why:
        lines.append("为什么：" + finding.why)
    for n, step in enumerate(finding.steps, 1):
        lines.append("%d) %s" % (n, step))
    if finding.copy_cmd:
        lines.append("官方地址（自己核对后打开）：" + finding.copy_cmd)
    if finding.needs_admin:
        lines.append("这一项用普通权限看不全，需要用管理员身份再体检一次。")
    return lines


def _soft_shadow(widget):
    """Depth without a picture.

    QSS has no box-shadow (Qt rejects the property outright), so the layer under
    a card is a graphics effect. Eleven of these measured +4.3 ms on a full
    repaint of this window at a 940 px size (4.5 ms without them, 8.8 ms with),
    which is why every card gets one and not just the ones on show.
    """
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(18)
    effect.setOffset(0, 4)
    effect.setColor(QColor(*theme.SHADOW))
    return effect


class FindingCard(QFrame):
    """One conclusion.

    A green or gray row folds to its headline: measured on this machine, the
    eleven of them go from 1356 px of board to 798 px at a 940 px window in two
    columns, and the line it hides is one click away. Red and yellow start open -
    they are the reason this window was opened.
    """

    def __init__(self, finding, parent=None):
        super().__init__(parent)
        self.f = finding
        self.folded = finding.status in (Status.GREEN, Status.GRAY)
        self.setObjectName("Card")
        self.setProperty("status", finding.status.value)
        self.setGraphicsEffect(_soft_shadow(self))
        box = QVBoxLayout(self)
        box.setContentsMargins(16, 14, 16, 14)
        box.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(10)
        if not self.folded:
            tag = QLabel("%s %s" % (MARK[finding.status], GLYPH[finding.status]))
            tag.setObjectName("Tag")
            tag.setProperty("status", finding.status.value)
            top.addWidget(tag, 0, Qt.AlignTop)
        head = QLabel(finding.headline)
        head.setObjectName("Head")
        head.setWordWrap(True)
        top.addWidget(head, 1)
        box.addLayout(top)

        body = []
        if finding.plain:
            plain = QLabel(_para(finding.plain))
            plain.setTextFormat(Qt.RichText)
            plain.setObjectName("Plain")
            plain.setWordWrap(True)
            box.addWidget(plain)
            body.append(plain)
        lines = _detail_lines(finding)
        if lines:
            detail = QLabel(_para("\n".join(lines)))
            detail.setTextFormat(Qt.RichText)
            detail.setObjectName("Steps")
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
            box.addWidget(detail)
            body.append(detail)

        self._fold = body if self.folded else ([detail] if lines else [])
        self.toggle = None
        if self._fold:
            self.toggle = QPushButton()
            self.toggle.setObjectName("Toggle")
            self.toggle.setCheckable(True)
            self.toggle.setFlat(True)
            self.toggle.setCursor(Qt.PointingHandCursor)
            box.addWidget(self.toggle)
            self.toggle.toggled.connect(self._set_open)
        self._set_open(not self.folded)

    def _set_open(self, is_open):
        for widget in self._fold:
            widget.setVisible(is_open)
        if self.toggle is not None:
            n = len(self.f.steps)
            if is_open:
                self.toggle.setText("收起（%d 条）" % n if n else "收起")
            else:
                self.toggle.setText("怎么做（%d 条）" % n if n else "展开说明")


class SpeechBubble(QFrame):
    """The mascot's one line, drawn as a bubble with a tail pointing at her.

    QSS cannot cut a tail out of a border, so this frame paints itself. The text
    stays a child label: the wording gate reads it like any other label and the
    gate that proves her line follows the result still calls .text() on this.
    """

    TAIL = 12

    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setObjectName("Bubble")
        # Maximum: handed the chance, a Preferred frame takes the whole banner
        # column and the bubble reads as a bar across the window instead of one
        # sentence. It still shrinks when the window goes narrow.
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
        box = QVBoxLayout(self)
        box.setContentsMargins(self.TAIL + 13, 9, 14, 9)
        box.setSpacing(0)
        self.label = QLabel(text)
        self.label.setObjectName("HeroSay")
        self.label.setWordWrap(True)
        box.addWidget(self.label)
        self._fit()

    def _fit(self):
        """Wide enough for the sentence on one line, no wider.

        A word-wrapped label reports a small sizeHint, so Maximum alone gave her
        a two-line bubble for a fourteen-character line. This is the width the
        text actually wants; Maximum then caps the frame at it.
        """
        fm = self.label.fontMetrics()
        want = fm.horizontalAdvance(self.label.text())
        self.setMinimumWidth(want + self.TAIL + 13 + 14 + 4)

    def text(self):
        return self.label.text()

    def setText(self, text):
        self.label.setText(text)
        self._fit()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        body = QRectF(self.TAIL + 1, 1, max(0, self.width() - self.TAIL - 3),
                      max(0, self.height() - 3))
        path = QPainterPath()
        path.addRoundedRect(body, 13, 13)
        tail = QPainterPath()
        tail.moveTo(self.TAIL + 1, 11)
        tail.lineTo(1, 17)
        tail.lineTo(self.TAIL + 1, 23)
        tail.closeSubpath()
        painter.setPen(QPen(QColor(theme.P["ink"]), 2))
        painter.setBrush(QColor(theme.P["white"]))
        painter.drawPath(path.united(tail))
        painter.end()


class MainWindow(QMainWindow):
    def __init__(self, ctx, entry_script=None, note=None):
        super().__init__()
        self.ctx = ctx
        self.entry_script = entry_script or sys.argv[0]
        self.note = note or (lambda kind, text: None)
        self.worker = None
        self.findings = []
        self.last_meta = {}
        self.san_summary = ""
        self.counts = {}
        self.quiet = 0
        self.unread = 0
        self.history_line = ""
        self.report_folder = paths.report_dir()[0]
        self.report_written = False
        self.is_admin = paths.running_as_admin()

        # The title is the only place the two windows differ from the outside,
        # and the user needs to tell them apart before clicking anything.
        self.setWindowTitle("系统简易体检仪（管理员权限）" if self.is_admin
                            else "系统简易体检仪")
        self.resize(940, 700)
        self.setMinimumSize(760, 520)
        self.setFont(QFont("Microsoft YaHei", 10))
        self.setStyleSheet(theme.qss())

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(20, 18, 20, 12)
        outer.setSpacing(12)

        hero = QFrame()
        hero.setObjectName("Hero")
        # The band spans the window instead of hugging its own text: the call to
        # action lives inside it now, to the mascot's right.
        hero_row = QHBoxLayout(hero)
        hero_row.setContentsMargins(16, 14, 18, 14)
        hero_row.setSpacing(16)
        art = QLabel()
        art.setObjectName("HeroArt")
        art.setFixedSize(118, 148)
        art.setAlignment(Qt.AlignBottom | Qt.AlignHCenter)
        pm = _mascot_pixmap(148)
        if pm is not None:
            art.setPixmap(pm)
        self.hero_art = art
        hero_row.addWidget(art, 0, Qt.AlignVCenter)

        words = QVBoxLayout()
        words.setSpacing(4)
        title = QLabel("系统简易体检仪")
        title.setObjectName("Title")
        who = QLabel(MASCOT_NAME)
        who.setObjectName("HeroName")
        subtitle = QLabel("只读取本机信息，不修改任何设置 · 全程离线 · 结果自动去掉个人身份信息")
        subtitle.setObjectName("Subtitle")
        subtitle.setWordWrap(True)
        self.hero_say = SpeechBubble(MASCOT_SAY["idle"])
        for widget in (title, who, subtitle, self.hero_say):
            words.addWidget(widget)
        words.addStretch(1)
        hero_row.addLayout(words, 1)

        self.run_btn = QPushButton("开始体检")
        self.run_btn.setObjectName("Primary")
        # Fixed keeps the button to its own text: the band would otherwise hand it
        # the leftover width, and "正在体检…" still grows it back to 151 px.
        self.run_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.run_btn.clicked.connect(self.start_scan)
        hero_row.addWidget(self.run_btn, 0, Qt.AlignRight | Qt.AlignVCenter)
        outer.addWidget(hero)

        # One line for the meter and the line that names the step it is on. They
        # used to be two lines with the button on a third of its own: measured at
        # 940x700 that stack left the board 217 px of viewport inside 483 px of
        # chrome, and the board is the reason this window exists.
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(230)
        self.progress.setRange(0, len(probes.PROBES))
        self.progress.setValue(0)
        self.step_label = QLabel("点上面的按钮开始，全程不需要联网，一般几秒钟。")
        self.step_label.setObjectName("Progress")
        self.step_label.setWordWrap(True)
        status_row = QHBoxLayout()
        status_row.setSpacing(14)
        status_row.addWidget(self.progress, 0, Qt.AlignVCenter)
        status_row.addWidget(self.step_label, 1)
        outer.addLayout(status_row)

        self.verdict = QLabel("")
        self.verdict.setObjectName("Verdict")
        self.verdict.setWordWrap(True)
        self.verdict.setVisible(False)
        outer.addWidget(self.verdict)

        # Six words of pain above the board. The row costs one line of height and
        # it only appears once there is something to narrow - before a scan an
        # empty filter bar is furniture. Filtering never touches the report: the
        # chips decide what the window shows, nothing more.
        self.symptom = None
        self.symptom_box = QFrame()
        self.symptom_box.setObjectName("Symptom")
        self.symptom_box.setVisible(False)
        chips = QHBoxLayout(self.symptom_box)
        chips.setContentsMargins(12, 9, 12, 9)
        chips.setSpacing(7)
        self._chip_group = QButtonGroup(self)
        self._chip_group.setExclusive(True)
        self._all_chip = QPushButton(SYMPTOM_ALL)
        self._all_chip.setObjectName("Chip")
        self._all_chip.setCheckable(True)
        self._all_chip.setChecked(True)
        self._all_chip.setToolTip("把收起来的结论卡都放回来。")
        self._all_chip.clicked.connect(lambda _c: self._apply_symptom(None))
        self._chip_group.addButton(self._all_chip)
        chips.addWidget(self._all_chip)
        for word, _mods in SYMPTOMS:
            chip = QPushButton(word)
            chip.setObjectName("Chip")
            chip.setCheckable(True)
            chip.setToolTip("只看和“%s”对得上的结论，其余的先收起来；"
                            "生成的报告里照旧是全部项目。" % word)
            chip.clicked.connect(lambda _c, w=word: self._apply_symptom(w))
            self._chip_group.addButton(chip)
            chips.addWidget(chip)
        # The comparison rides at the right end of the row the chips already
        # occupy: measured at 940x700 a full-width line costs two of the four
        # conclusions that fit without scrolling, while this label leaves the
        # row at 49 px, the viewport at 217 px and the first screen at 4 cards.
        # The window shows the count; the hover text and both reports carry the
        # sentence with the module names in it.
        self.compare = QLabel("")
        self.compare.setObjectName("Progress")
        chips.addWidget(self.compare)
        chips.addStretch(1)
        outer.addWidget(self.symptom_box)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.board = QWidget()
        self.board.setObjectName("Board")
        self.board_grid = QGridLayout(self.board)
        self.board_grid.setContentsMargins(11, 11, 11, 11)
        self.board_grid.setSpacing(9)
        self.board_grid.setColumnStretch(0, 1)
        self.board_grid.setColumnStretch(1, 1)
        self._board_rows = []
        self._note_rows = []
        self._heads = {}
        self._quiet_mods = []
        self._unread_mods = []
        self._filter_note = QLabel(self.board)
        self._filter_note.setObjectName("Progress")
        self._filter_note.setWordWrap(True)
        self._cols = 1
        self.scroll.setWidget(self.board)
        outer.addWidget(self.scroll, 1)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        # Short on the button, full in the tooltip: the four labels used to need
        # 826 px and the window is allowed to go down to 760, where they spilled.
        self.report_btn = QPushButton("生成报告")
        self.report_btn.setToolTip("同时写出网页版和文字版两个文件")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self.make_report)
        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.setToolTip("复制纯文字结果，粘贴给帮你看电脑的人")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_results)
        self.open_btn = QPushButton("打开文件夹")
        self.open_btn.setToolTip("打开报告所在的文件夹；程序不会自动替你打开")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self.open_folder)
        self.admin_btn = QPushButton("用管理员身份再看一遍")
        self.admin_btn.setToolTip("只有两处需要管理员权限：USB 的省电设置、"
                                  "服务到底在不在运行")
        self.admin_btn.clicked.connect(self.relaunch_elevated)
        for widget in (self.report_btn, self.copy_btn, self.open_btn, self.admin_btn):
            actions.addWidget(widget)
        actions.addStretch(1)
        outer.addLayout(actions)

        bar = QStatusBar()
        self.setStatusBar(bar)
        bar.showMessage("本机：%s" % os_label())
        if self.is_admin:
            self.admin_btn.setVisible(False)

    # ------------------------------------------------------------- scanning
    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        self.findings = []
        self.san_summary = ""
        self._clear_board()
        self.symptom = None
        self._all_chip.setChecked(True)
        self.symptom_box.setVisible(False)
        self.compare.setText("")
        self.compare.setToolTip("")
        self.report_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
        self.open_btn.setEnabled(self.report_written)
        self.verdict.setVisible(False)
        self.run_btn.setEnabled(False)
        self.run_btn.setText("正在体检…")
        self.hero_say.setText(MASCOT_SAY["running"])
        self.progress.setRange(0, len(probes.PROBES))
        self.progress.setValue(0)
        self._t0 = time.perf_counter()

        self.worker = ScanWorker(self.ctx, self)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.on_done)
        self.worker.broken.connect(self.on_broken)
        self.worker.start()

    def on_progress(self, title, index, total):
        self.progress.setRange(0, total)
        self.progress.setValue(index)
        self.step_label.setText("正在检查：%s（%d / %d）" % (title, index, total))

    def on_done(self, raw_dicts, san, elapsed, _count):
        self.findings = [Finding.from_dict(d) for d in raw_dicts]
        self.san_summary = san.summary()
        self.progress.setValue(self.progress.maximum())
        self.step_label.setText("检查完成，用时 %.1f 秒。" % (elapsed / 1000.0))
        self._render_board(elapsed, san)
        self.run_btn.setEnabled(True)
        self.run_btn.setText("重新体检")
        self.report_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self._status_counts()

    def on_broken(self, reason):
        self.step_label.setText("这一轮没能跑完，原因已经写进本机日志文件，"
                                "请重新体检一次；如果反复出现，把日志发给人帮你看看。")
        self.hero_say.setText(MASCOT_SAY["broken"])
        self.run_btn.setEnabled(True)
        self.run_btn.setText("重新体检")
        self.statusBar().showMessage("未完成：%s" % reason[:120])

    # ------------------------------------------------------------- rendering
    TWO_COL_AT = 800

    def _want_cols(self):
        """Two columns only pay for themselves while a card still gets ~400 px.

        Measured on this machine: at a 940 px window the column is 427 px and no
        headline wraps; at the 760 px minimum two columns would give 342 px, so it
        goes back to one column of 684 px instead of stacking wrapped text.
        """
        return 2 if self.scroll.viewport().width() >= self.TWO_COL_AT else 1

    def _layout_board(self):
        """Place what the current filter allows, and say what it folded away.

        Group headings are built here rather than stored once, because their count
        has to be the number of cards actually on screen - a header reading 11 over
        three cards is exactly the kind of mismatch this window cannot have.
        """
        self._cols = self._want_cols()
        while self.board_grid.count():
            self.board_grid.takeAt(0)
        cols = self._cols
        # An empty column keeps its stretch, so leaving column one stretched while
        # the board is in one column halved the card width: measured 342 px of a
        # 706 px viewport and a 1810 px board. It has to be taken out.
        self.board_grid.setColumnStretch(1, 1 if cols == 2 else 0)

        mods = dict(SYMPTOMS).get(self.symptom) if self.symptom else None
        cards = [r for r in self._board_rows
                 if mods is None or r[2] in mods]
        hidden = len(self._board_rows) - len(cards)

        for status in ORDER:
            n = sum(1 for r in cards if r[1] is status)
            head = self._heads.get(status)
            if not n:
                if head:
                    head.hide()
                continue
            if head is None:
                head = QLabel(self.board)
                head.setObjectName("GroupHead")
                head.setProperty("status", TAG_STATUS[status])
                self._heads[status] = head
            head.setText("%s（%d 项）" % (GROUP_TITLE[status], n))

        if mods is None:
            self._filter_note.clear()
        else:
            # A chip that lands on nothing is not a broken chip: on a healthy
            # machine most of what matches that word was judged normal and folded
            # into one line. Say that, or the filter reads like a missing answer.
            side = []
            quiet_hit = sum(1 for m in self._quiet_mods if m in mods)
            unread_hit = sum(1 for m in self._unread_mods if m in mods)
            if quiet_hit:
                side.append("%d 项和“%s”有关，判成正常就没单独占卡"
                            % (quiet_hit, self.symptom))
            if unread_hit:
                side.append("%d 项这台机器上看不到" % unread_hit)
            if cards:
                lead = ("只显示和“%s”对得上的 %d 条，其余 %d 条先收起来，"
                        "点“%s”放回来。"
                        % (self.symptom, len(cards), hidden, SYMPTOM_ALL))
            else:
                lead = ("“%s”这次没对上任何一张结论卡——没对上不等于没问题，"
                        "点“%s”看全部 %d 条。"
                        % (self.symptom, SYMPTOM_ALL, len(self._board_rows)))
            text = lead
            if side:
                text += "另有 " + "；另有 ".join(side) + "。"
            self._filter_note.setText(text + "生成的报告里写的都是全部。")

        shown = set()
        row = col = 0

        def stack(widget):
            """Add one full-width line, closing the current card row first."""
            nonlocal row, col
            if col:
                row += 1
                col = 0
            self.board_grid.addWidget(widget, row, 0, 1, cols)
            shown.add(id(widget))
            row += 1

        if mods is not None:
            stack(self._filter_note)
        for status in ORDER:
            group = [r for r in cards if r[1] is status]
            if not group:
                continue
            stack(self._heads[status])
            for _kind, _st, _module, widget in group:
                self.board_grid.addWidget(widget, row, col)
                shown.add(id(widget))
                col += 1
                if col >= cols:
                    col = 0
                    row += 1
        if mods is None:
            for widget in self._note_rows:
                stack(widget)
        self.board_grid.setRowStretch(row, 1)

        everything = ([r[3] for r in self._board_rows] + list(self._heads.values())
                      + list(self._note_rows) + [self._filter_note])
        for widget in everything:
            widget.setVisible(id(widget) in shown)

    def _apply_symptom(self, word):
        """Narrow the board to one complaint. Nothing here leaves the window."""
        self.symptom = word
        if word is None:
            self._all_chip.setChecked(True)
        self._layout_board()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if getattr(self, "_board_rows", None) and self._want_cols() != self._cols:
            self._layout_board()

    def _clear_board(self):
        for _kind, _st, _module, widget in self._board_rows:
            widget.setParent(None)
            widget.deleteLater()
        for widget in self._note_rows + list(self._heads.values()):
            widget.setParent(None)
            widget.deleteLater()
        self._board_rows = []
        self._note_rows = []
        self._heads = {}
        self._quiet_mods = []
        self._unread_mods = []
        while self.board_grid.count():
            self.board_grid.takeAt(0)

    def _render_board(self, elapsed, san):
        shown = [f for f in self.findings if not f.skip]
        # The four numbers describe all conclusions, not only the cards: a row
        # can be judged and still not take up space. Counting cards would report
        # "未获取 0" while four readings were never obtained.
        self.counts = {s: sum(1 for f in self.findings if f.status is s)
                       for s in ORDER}
        # The filter line has to name which modules the folded-away items came
        # from, so keep the module keys next to the counts instead of deriving
        # one from the other.
        self._quiet_mods = [f.module for f in self.findings
                           if f.skip and f.status is Status.GREEN]
        self._unread_mods = [f.module for f in self.findings
                            if f.skip and f.status is Status.GRAY]
        self.quiet = len(self._quiet_mods)
        self.unread = len(self._unread_mods)
        # Compared before the report meta is built, so the file a person sends
        # to whoever is helping them carries the same one line the window shows.
        self.history_line = ""
        try:
            got = history.observe(self.findings, report.TOOL_VERSION,
                                  self.ctx.rules.version, self.is_admin,
                                  note=self.note)
            self.history_line = got["text"]
            self.compare.setText(got.get("short", ""))
            self.compare.setToolTip(self.history_line)
        except Exception as exc:
            self.note("历史记录", "对比没跑成：%s" % type(exc).__name__)
        self.last_meta = report.build_meta(self.ctx, self.findings, san, elapsed,
                                           {"history_line": self.history_line})
        self.verdict.setText(report.verdict(self.findings))
        self.verdict.setVisible(True)
        red = self.counts.get(Status.RED, 0)
        yellow = self.counts.get(Status.YELLOW, 0)
        if red:
            self.hero_say.setText(MASCOT_SAY["fix"] % red)
        elif yellow:
            self.hero_say.setText(MASCOT_SAY["watch"] % yellow)
        else:
            self.hero_say.setText(MASCOT_SAY["clean"])
        for status in ORDER:
            group = [f for f in shown if f.status is status]
            for finding in group:
                self._board_rows.append(("card", status, finding.module,
                                         FindingCard(finding)))
        # Two different populations, so neither gets blamed for the other:
        # judged-normal is not unread, and unread is not normal. They are the
        # board's own lines and a filter folds them away - the filter talks about
        # the cards, not about them.
        if self.quiet:
            note = QLabel("另有 %d 项看过，结论正常，就不单独占一张卡；"
                          "生成的报告里能看到全部。" % self.quiet)
            note.setObjectName("Progress")
            note.setWordWrap(True)
            self._note_rows.append(note)
        if self.unread:
            note = QLabel("另有 %d 项这次没取到：这台机器本来就没有这一项，"
                          "或者普通权限看不到。没取到不等于有问题，"
                          "生成的报告里也写着。" % self.unread)
            note.setObjectName("Progress")
            note.setWordWrap(True)
            self._note_rows.append(note)
        self.symptom_box.setVisible(bool(self._board_rows))
        self._apply_symptom(None)

    def _status_counts(self):
        self.statusBar().showMessage(
            "需处理 %d ｜ 建议留意 %d ｜ 正常 %d ｜ 未获取 %d ｜ %s"
            % (self.counts.get(Status.RED, 0), self.counts.get(Status.YELLOW, 0),
               self.counts.get(Status.GREEN, 0), self.counts.get(Status.GRAY, 0),
               self.san_summary))

    # ------------------------------------------------------------- actions
    def make_report(self):
        if not self.findings:
            return
        written = report.write(self.findings, self.last_meta)
        self.report_folder = written["dir"]
        self.report_written = True
        self.open_btn.setEnabled(True)
        if written["in_place"]:
            where = "就在程序所在的文件夹里：%s" % self.report_folder
        else:
            where = ("程序所在的文件夹不允许写入，报告放到了临时文件夹：%s"
                     % self.report_folder)
        self.step_label.setText("报告已生成 2 个文件（网页版 + 文字版）。%s" % where)
        self.statusBar().showMessage("已生成报告，没有自动打开任何窗口——"
                                     "要看得点上面那个“打开报告所在的文件夹”")

    def copy_results(self):
        if not self.findings:
            return
        text = self.plain_text()
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage(
            "已复制 %d 行文字，可以直接粘贴给对方（已去掉姓名、机器名、IP）"
            % (text.count("\n") + 1))

    def plain_text(self):
        shown = [f for f in self.findings if not f.skip]
        lines = ["【系统简易体检仪】体检结果",
                 "总评：" + report.verdict(self.findings),
                 self.san_summary, ""]
        if self.history_line:
            lines.insert(2, self.history_line)
            lines.insert(3, "")
        for status in ORDER:
            group = [f for f in shown if f.status is status]
            if not group:
                continue
            for f in group:
                lines.append("%s %s｜%s" % (MARK[status], GLYPH[status], f.headline))
                if f.plain:
                    lines.append("   " + f.plain)
                lines.extend("   " + s for s in _detail_lines(f))
                lines.append("")
        # Whoever reads the paste needs to know the list above is not the whole
        # set, so the two suppressed populations are named separately here too.
        if self.quiet:
            lines.append("另有 %d 项判过、结论正常，没有在这里逐条列出。" % self.quiet)
        if self.unread:
            lines.append("另有 %d 项这次没取到：这台机器本来就没有这一项，"
                         "或者普通权限看不到。没取到不等于有问题。" % self.unread)
        return "\n".join(lines)

    def open_folder(self):
        target = self.report_folder
        if os.path.isdir(target):
            # Reached only by a click on a button the user has just read.
            os.startfile(target)

    def relaunch_elevated(self):
        ok, note, code = relaunch_as_admin(self.entry_script)
        pid = os.getpid()
        if ok:
            self.note("权限请求", "rc=%d 新实例已拉起 pid=%d 本窗口退出" % (code, pid))
            self.step_label.setText("正在请求管理员权限；新窗口打开后，这个窗口会自动关闭。")
            self.close()
        else:
            self.note("权限请求", "rc=%d 未提权 pid=%d 本窗口继续在普通权限下工作"
                      % (code, pid))
            self.statusBar().showMessage(note)
