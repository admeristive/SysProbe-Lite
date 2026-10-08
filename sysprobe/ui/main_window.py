"""Main window: one big button, one traffic-light board, no jargon.

Three rules shape everything below:
  * a status is never colour alone - each row carries a shape and a word;
  * nothing is opened or switched to on the user's behalf;
  * raw readings (event ids, hexadecimal codes) stay out of the window.
"""

import os
import sys
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QMainWindow, QProgressBar,
    QPushButton, QScrollArea, QStatusBar, QVBoxLayout, QWidget,
)

from .. import paths, probes, report
from ..model import GLYPH, MARK, ORDER, Finding, Status
from ..probes import os_label
from .elevate import relaunch_as_admin
from .worker import ScanWorker

QSS = """
QMainWindow, QWidget { background: #f4f5f7; color: #1c1f24; }
#Title { font-size: 21px; font-weight: 600; }
#Subtitle { font-size: 13px; color: #67707d; }
#Verdict { font-size: 17px; padding: 4px; }
#Progress { font-size: 13px; color: #67707d; }
QFrame#Card { background: #ffffff; border: 1px solid #dfe2e7;
              border-radius: 8px; padding: 4px; }
QFrame#Card[status="red"]    { border-left: 5px solid #c0392b; }
QFrame#Card[status="yellow"] { border-left: 5px solid #d8a400; }
QFrame#Card[status="green"]  { border-left: 5px solid #2f9e63; }
QFrame#Card[status="gray"]   { border-left: 5px solid #aab1bb; }
QLabel#Tag { font-size: 13px; font-weight: 600; }
QLabel#Head { font-size: 16px; font-weight: 600; }
QLabel#Plain { font-size: 14px; color: #3a4250; }
QLabel#Steps { font-size: 14px; }
QPushButton { background: #ffffff; border: 1px solid #cdd2da; border-radius: 6px;
              padding: 9px 16px; font-size: 14px; }
QPushButton:hover { background: #f0f2f5; border-color: #b9c0cb; }
QPushButton:pressed { background: #e7eaef; }
QPushButton:disabled { color: #a6adb8; background: #f2f3f5; border-color: #e3e6ea; }
QPushButton#Primary { background: #2f6feb; border: 1px solid #2f6feb; color: #ffffff;
                      font-size: 19px; font-weight: 600; padding: 16px 26px;
                      border-radius: 8px; }
QPushButton#Primary:hover { background: #2b64d8; border-color: #2b64d8; }
QPushButton#Primary:disabled { background: #c3d3f0; border-color: #c3d3f0; }
QProgressBar { background: #e9ebef; border: 1px solid #dfe2e7; border-radius: 6px;
               min-height: 8px; max-height: 8px; }
QProgressBar::chunk { background: #2f6feb; border-radius: 5px; }
QScrollArea { border: none; background: transparent; }
QStatusBar { background: #eef0f3; color: #67707d; font-size: 12px; }
"""

TAG_COLOR = {Status.RED: "#a5322a", Status.YELLOW: "#8a6d1b",
             Status.GREEN: "#227a4c", Status.GRAY: "#5c6470"}


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


class FindingCard(QFrame):
    def __init__(self, finding, parent=None):
        super().__init__(parent)
        self.f = finding
        self.setObjectName("Card")
        self.setProperty("status", finding.status.value)
        box = QVBoxLayout(self)
        box.setContentsMargins(16, 13, 16, 13)
        box.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)
        tag = QLabel("%s %s" % (MARK[finding.status], GLYPH[finding.status]))
        tag.setObjectName("Tag")
        tag.setStyleSheet("color:%s" % TAG_COLOR[finding.status])
        head = QLabel(finding.headline)
        head.setObjectName("Head")
        head.setWordWrap(True)
        top.addWidget(tag, 0, Qt.AlignTop)
        top.addWidget(head, 1)
        box.addLayout(top)

        if finding.plain:
            plain = QLabel(finding.plain)
            plain.setObjectName("Plain")
            plain.setWordWrap(True)
            box.addWidget(plain)

        lines = _detail_lines(finding)
        if lines:
            toggle = QPushButton(("怎么做（%d 条）" % len(finding.steps))
                                 if finding.steps else "补充说明")
            toggle.setCheckable(True)
            toggle.setFlat(True)
            toggle.setStyleSheet(
                "color:#4a5261; background:transparent; border:none;"
                "padding:2px 0; text-align:left; font-size:13px;")
            detail = QLabel("\n".join(lines))
            detail.setObjectName("Steps")
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
            detail.setVisible(False)
            toggle.toggled.connect(detail.setVisible)
            box.addWidget(toggle)
            box.addWidget(detail)


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
        self.setStyleSheet(QSS)

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(22, 20, 22, 12)
        outer.setSpacing(12)

        title = QLabel("系统简易体检仪")
        title.setObjectName("Title")
        subtitle = QLabel("只读取本机信息，不修改任何设置 · 全程离线 · 结果自动去掉个人身份信息")
        subtitle.setObjectName("Subtitle")
        outer.addWidget(title)
        outer.addWidget(subtitle)

        self.run_btn = QPushButton("开始体检")
        self.run_btn.setObjectName("Primary")
        self.run_btn.clicked.connect(self.start_scan)
        outer.addWidget(self.run_btn)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, len(probes.PROBES))
        self.progress.setValue(0)
        outer.addWidget(self.progress)

        self.step_label = QLabel("点上面的按钮开始，全程不需要联网，一般几秒钟。")
        self.step_label.setObjectName("Progress")
        self.step_label.setWordWrap(True)
        outer.addWidget(self.step_label)

        self.verdict = QLabel("")
        self.verdict.setObjectName("Verdict")
        self.verdict.setWordWrap(True)
        self.verdict.setVisible(False)
        outer.addWidget(self.verdict)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.board = QWidget()
        self.board_layout = QVBoxLayout(self.board)
        self.board_layout.setContentsMargins(0, 4, 0, 4)
        self.board_layout.setSpacing(10)
        self.board_layout.addStretch(1)
        self.scroll.setWidget(self.board)
        outer.addWidget(self.scroll, 1)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.report_btn = QPushButton("生成报告（网页版＋文字版）")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self.make_report)
        self.copy_btn = QPushButton("复制结果，发给帮我的人")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self.copy_results)
        self.open_btn = QPushButton("打开报告所在的文件夹")
        self.open_btn.setEnabled(False)
        self.open_btn.clicked.connect(self.open_folder)
        self.admin_btn = QPushButton("用管理员身份重新体检")
        self.admin_btn.clicked.connect(self.relaunch_elevated)
        for widget in (self.report_btn, self.copy_btn, self.open_btn, self.admin_btn):
            actions.addWidget(widget)
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
        self.report_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
        self.open_btn.setEnabled(self.report_written)
        self.verdict.setVisible(False)
        self.run_btn.setEnabled(False)
        self.run_btn.setText("正在体检…")
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
        self.run_btn.setEnabled(True)
        self.run_btn.setText("重新体检")
        self.statusBar().showMessage("未完成：%s" % reason[:120])

    # ------------------------------------------------------------- rendering
    def _clear_board(self):
        while self.board_layout.count() > 1:
            item = self.board_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _render_board(self, elapsed, san):
        shown = [f for f in self.findings if not f.skip]
        self.counts = {s: sum(1 for f in shown if f.status is s) for s in ORDER}
        self.last_meta = report.build_meta(self.ctx, self.findings, san, elapsed)
        self.verdict.setText(report.verdict(shown))
        self.verdict.setVisible(True)
        slot = self.board_layout.count() - 1
        for status in ORDER:
            for finding in [f for f in shown if f.status is status]:
                self.board_layout.insertWidget(slot, FindingCard(finding))
                slot += 1
        skipped = [f for f in self.findings if f.skip]
        if skipped:
            note = QLabel("另有 %d 项这次没有下判断（这台机器本来就没有这一项，"
                          "或者普通权限看不到）。看不到不等于有问题，"
                          "它们在生成的报告里能看到。" % len(skipped))
            note.setObjectName("Progress")
            note.setWordWrap(True)
            self.board_layout.insertWidget(slot, note)

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
                 "总评：" + report.verdict(shown),
                 self.san_summary, ""]
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
