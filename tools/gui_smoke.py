"""GUI smoke test that never opens a visible window.

Offscreen Qt was the obvious choice and it was wrong for measuring: with
QT_QPA_PLATFORM=offscreen the metrics of "Microsoft YaHei" came out identical to
a font that does not exist, so every height taken there is fiction (the board
measured 1092 px offscreen and 1482 px on the real platform). This gate now runs
on the real font engine and keeps the window unmapped with WA_DontShowOnScreen,
then proves with IsWindowVisible that nothing reached the desktop.

What it checks: the thread starts, signals land, the board renders, the report
button writes files, the copy button produces text, the bottom bar still fits at
the minimum window width, the banner actually paints the bundled artwork and its
one line of speech follows the result, the product rule that raw Windows
vocabulary stays out of the window, and the board skeleton - a call to action
that sits inside the mascot band without being stretched, the meter directly
under that band, one column at the minimum width that still fills that column, a
word for every status group, a shadow under every card, a three-pixel spine of
the group's own colour painted on the left edge of every card, a tail on the
speech bubble, and at least three conclusions on one screen.

Run:  py -3 tools/gui_smoke.py
"""

import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# One banned-word list for all three gates; a word only one of them knows is a
# word that can still ship.
from wording_check import BANNED_WORDS as BANNED_ON_SCREEN      # noqa: E402
sys.path.insert(0, ROOT)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import html as _html_mod

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QFrame, QLabel, QPushButton  # noqa: E402
from sysprobe import paths, probes, scan  # noqa: E402
from sysprobe import manual as MANUAL  # noqa: E402
from sysprobe.model import ORDER, Finding, Status  # noqa: E402
from sysprobe import theme  # noqa: E402
from sysprobe.ui.main_window import (  # noqa: E402
    GROUP_TITLE, MASCOT_SAY, SYMPTOMS, SYMPTOM_ALL, FindingCard, MainWindow,
    _mascot_pixmap, TAG_STATUS,
)


def make_app():
    """Real font engine first; offscreen only if the platform cannot start."""
    try:
        app = QApplication(sys.argv)
        return app, "真实平台（度量可信）"
    except Exception as exc:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        app = QApplication(sys.argv)
        return app, "退回 offscreen（高度数字会偏小，仅作接线检查）: %s" % exc


def wait_until(window, seconds=90.0):
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        QApplication.processEvents()
        if window.findings and not window.worker.isRunning():
            return True
        time.sleep(0.02)
    return False


def strip_markup(text):
    """A body label now carries rich-text markup for its line spacing. The word
    gate has to read what a person sees, not the tags around it."""
    return _html_mod.unescape(re.sub(r"<[^>]+>", " ", text))


def labels(window):
    out = []
    for widget in window.findChildren(QLabel):
        text = widget.text()
        if text:
            out.append((widget.objectName() or "label", strip_markup(text)))
    return out


def fits_at_minimum(window):
    """Measured on this machine, every run: the action row must still fit the
    760 px the window is allowed to shrink to. It used to be four buttons at
    826 px of want; the handbook button made five, so the sum is recomputed and
    the spare is printed instead of remembered."""
    window.resize(window.minimumWidth(), window.minimumHeight())
    QApplication.processEvents()
    bar = sum(b.sizeHint().width() for b in (window.manual_btn, window.report_btn,
                                             window.copy_btn, window.open_btn,
                                             window.admin_btn))
    spare = window.width() - bar - 20
    horiz = window.scroll.horizontalScrollBar().maximum()
    window.resize(940, 700)
    QApplication.processEvents()
    return bar, spare, horiz


def flush_layout(window):
    """Let every pending layout request land before anything is measured.

    Without this the numbers below are a mix of two states: the widget that
    paints is still where the last pass left it, the widget that reports a
    sizeHint has already moved on.
    """
    for _ in range(3):
        QApplication.processEvents()
        window.board_grid.activate()


def is_mapped(window):
    if not sys.platform.startswith("win"):
        return False
    try:
        import ctypes
        return bool(ctypes.windll.user32.IsWindowVisible(int(window.winId())))
    except Exception:
        return False


def main():
    app, platform_note = make_app()
    ctx = scan.build_ctx()
    window = MainWindow(ctx, entry_script=sys.argv[0])
    window.setAttribute(Qt.WA_DontShowOnScreen, True)
    window.show()
    QApplication.processEvents()
    mapped = is_mapped(window)
    print("度量平台：%s ｜ 窗口有没有真的显示到桌面：%s（应为 False）"
          % (platform_note, mapped))

    print("窗口标题：%s ｜ 大小 %dx%d" % (window.windowTitle(),
                                          window.width(), window.height()))
    print("按钮：主=%s 手册=%s 报告=%s 复制=%s 打开=%s 提权=%s"
          % (window.run_btn.text(), window.manual_btn.text(),
             window.report_btn.text(),
             window.copy_btn.text(), window.open_btn.text(),
             window.admin_btn.text()))
    print("手册按钮体检前就可点：%s（应为 True） ｜ 报告/复制体检前可点：%s %s（应为 False False）"
          % (window.manual_btn.isEnabled(), window.report_btn.isEnabled(),
             window.copy_btn.isEnabled()))
    box_off = window.symptom_box.isHidden()
    print("体检前症状条：%s（应为藏起来，这时没东西可筛） ｜ 按钮 %d 只"
          % ("藏著" if box_off else "露出",
             len(window.symptom_box.findChildren(QPushButton))))

    # The handbook is reachable before a scan, so the gate opens it here. Two
    # assertions: the tab bar shows every page the table declares (a page that
    # fails to build disappears quietly and reads as a shorter manual), and its
    # own rendered text clears the same word list the board is held to.
    window.show_manual()
    QApplication.processEvents()
    dlg = window._manual
    pages_want = len(MANUAL.pages()) + 1
    words = labels(dlg)
    dirty_manual = [(n, t) for n, t in words
                    if any(w.lower() in t.lower() for w in BANNED_ON_SCREEN)]
    tabs, rows, asks = MANUAL.counts()
    print("\n手册：%d 页（表里 %d 页 + 问人 1 页）｜ 取出 %d 条文字 ｜ 底层词汇：%s"
          % (dlg.pages(), tabs, len(words),
             "无" if not dirty_manual else dirty_manual[:3]))
    print("　内容量：%d 页 ｜ %d 条说明 ｜ 问人模板 %d 句 ｜ 状态栏那句：%s"
          % (tabs, rows, asks, window.statusBar().currentMessage()[:78]))
    dlg.close()

    window.start_scan()
    ok = wait_until(window)
    # The render posts a layout request that the loop above has already walked
    # past: measured here, the call to action still carried the 151 px it needed
    # for "正在体检…" while its text had gone back to 132, and the board's
    # sizeHint was still the empty 22 px. A window on a desktop gets that pass
    # for free; this one has to ask for it.
    flush_layout(window)
    cards = window.findChildren(FindingCard)
    print("\n扫描完成：%s ｜ 看板卡片 %d 张" % (ok, len(cards)))
    print("进度：%d / %d ｜ 状态行：%s"
          % (window.progress.value(), window.progress.maximum(),
             window.step_label.text()))
    print("总评：%s" % window.verdict.text())
    print("状态栏：%s" % window.statusBar().currentMessage())

    asset = paths.asset_path("mascot.png")
    size = os.path.getsize(asset) if os.path.isfile(asset) else 0
    painted = window.hero_art.pixmap()
    art_ok = painted is not None and not painted.isNull()
    scaled = _mascot_pixmap(148)
    print("\n看板娘素材：%s ｜ %d 字节 ｜ 独立缩放 %s"
          % (os.path.basename(asset), size,
             "没产出" if scaled is None else "%dx%d" % (scaled.width(), scaled.height())))
    print("横幅上真的画出了图：%s ｜ 她说的话：%s"
          % (art_ok, window.hero_say.text()))
    say_want = None
    if ok:
        red = window.counts.get(Status.RED, 0)
        yellow = window.counts.get(Status.YELLOW, 0)
        say_want = (MASCOT_SAY["fix"] % red if red
                    else MASCOT_SAY["watch"] % yellow if yellow
                    else MASCOT_SAY["clean"])
        print("这句话该是：%s ｜ 数字对得上：%s"
              % (say_want, window.hero_say.text() == say_want))

    total = sum(window.counts.values())
    print("\n四档计数合计 %d ｜ 结论 %d 条 ｜ 一致：%s"
          % (total, len(window.findings), total == len(window.findings)))
    print("看过且正常、不占卡 %d 项 ｜ 这次没取到 %d 项"
          % (window.quiet, window.unread))
    notes = [w.text() for w in window.findChildren(QLabel)
             if w.objectName() == "Progress" and w.text().startswith("另有")]
    for line in notes:
        print("   看板说明条：%s" % line)
    bar = window.statusBar().currentMessage()
    bar_ok = ("未获取 %d" % window.counts.get(Status.GRAY, 0)) in bar
    print("状态栏有没有把没取到的数报出来：%s（栏文：%s）"
          % (bar_ok, bar[:46]))

    print("\n看板骨架（乙档：宽度、层次、重复度都要有数）")
    rb = window.run_btn
    stretched = rb.width() - rb.sizeHint().width()
    band = window.findChild(QFrame, "Hero")
    in_band = band is not None and band.rect().contains(
        rb.geometry().center())
    meter_under = (band is not None
                   and window.progress.y() >= band.y() + band.height() - 2)
    print("  主按钮 %d px（文字本身 %d px，被拉伸 %+d px）｜ 它就在横幅带里：%s ｜ 带高 %d px"
          % (rb.width(), rb.sizeHint().width(), stretched, in_band,
             0 if band is None else band.height()))
    print("  进度条紧跟在横幅带下面：%s ｜ 和步骤文字同一行：%s"
          % (meter_under,
             abs((window.progress.y() + window.progress.height() // 2)
                 - (window.step_label.y() + window.step_label.height() // 2)) < 12))
    tags = [w for w in window.findChildren(QLabel) if w.objectName() == "Tag"]
    heads = [w for w in window.findChildren(QLabel) if w.objectName() == "GroupHead"]
    print("  分组标题 %d 个 ｜ 角标 %d 个（只挂在非正常项上）｜ 折叠卡 %d 张 ｜ 阴影 %d/%d 张"
          % (len(heads), len(tags), sum(1 for c in cards if c.folded),
             sum(1 for c in cards if c.graphicsEffect() is not None), len(cards)))
    bimg = window.hero_say.grab().toImage()
    kk = bimg.width() / float(max(1, window.hero_say.width()))
    tail = bimg.pixelColor(int(3 * kk), int(17 * kk)).value()
    print("  气泡尾巴尖那一点墨值 %d（<130 才算真画出一条尖）｜ 列数 %d ｜ 格里 %d 件"
          % (tail, window._cols, window.board_grid.count()))

    # A spine only counts when the pixels are there: the sheet can ask for three
    # pixels of colour and Qt can paint none of them. A healthy machine has no
    # red or yellow card to look at, so whatever the board did not produce is
    # painted from a stub instead - the four states get proven on every run.
    spine_bad, spine_note = [], []
    SPINE = {"red": "red_tag", "yellow": "yellow_tag",
             "green": "green_tag", "gray": "neutral"}
    for status in ORDER:
        card = next((r[3] for r in window._board_rows if r[1] is status), None)
        from_board = None
        if card is None:
            card = FindingCard(Finding(module="gate", status=status,
                                       headline="闸门用的假结论",
                                       plain="这一张只为量出左脊那三个像素。"),
                               window.board)
            card.resize(400, 80)
            card.show()
            from_board = card
        img = card.grab().toImage()
        px = img.pixelColor(1, img.height() // 2)
        got = "#%02x%02x%02x" % (px.red(), px.green(), px.blue())
        key = TAG_STATUS[status]
        want = theme.P[SPINE[key]]
        spine_note.append("%s %s%s" % (GROUP_TITLE[status], got,
                                       "" if from_board is None else "（补画）"))
        if got != want:
            spine_bad.append("%s：表里写 %s，画出来 %s"
                             % (GROUP_TITLE[status], want, got))
        if from_board is not None:
            from_board.setParent(None)
            from_board.deleteLater()
    print("  卡片左脊第一列：%s" % " ｜ ".join(spine_note))

    # Same proof for the group heading's word. A healthy machine shows only the
    # groups it has findings in, so the missing ones are painted from a stub the
    # same way - a selector that silently does not match would leave them grey.
    INK = {"red": "red_ink", "yellow": "yellow_ink",
           "green": "green_ink", "gray": "mute_strong"}
    head_bad, head_note = [], []
    for status in ORDER:
        real = window._heads.get(status)
        extra = None
        if real is not None and not real.isHidden() and real.width() >= 4:
            head = real
        else:
            head = QLabel("%s（1 项）" % GROUP_TITLE[status], window.board)
            head.setObjectName("GroupHead")
            head.setProperty("status", TAG_STATUS[status])
            head.resize(220, 26)
            head.show()
            extra = head
        want = theme.P[INK[TAG_STATUS[status]]]
        img = head.grab().toImage()
        hit = sum(1 for y in range(img.height()) for x in range(img.width())
                  if img.pixelColor(x, y).name() == want)
        head_note.append("%s %d 点%s" % (GROUP_TITLE[status], hit,
                                         "" if extra is None else "（补画）"))
        if hit < 3:
            head_bad.append(GROUP_TITLE[status])
        if extra is not None:
            extra.setParent(None)
    print("  分组标题里正中色的字：%s" % " ｜ ".join(head_note))

    text_labels = labels(window)
    dirty = [(name, t) for name, t in text_labels
             for word in BANNED_ON_SCREEN if word.lower() in t.lower()]
    print("\n界面上出现的底层词汇：%s" % ("无" if not dirty else dirty[:4]))

    window.make_report()
    folder_ok = os.path.isdir(window.report_folder)
    produced = [n for n in os.listdir(window.report_folder)
                if n.startswith(("体检报告-", "体检结果-"))] if folder_ok else []
    print("报告按钮写出文件：%d 个于 %s ｜ %s"
          % (len(produced), window.report_folder, window.step_label.text()[:50]))

    blob = window.plain_text()
    print("复制按钮产出：%d 行 / %d 字，开头=%r"
          % (blob.count("\n") + 1, len(blob), blob.splitlines()[0]))

    from sysprobe.sanitizer import Sanitizer
    live = [v for v, _ in Sanitizer()._live]
    leak = [len(v) for v in live if v.lower() in blob.lower()]
    print("剪贴板文本里的本机身份：%s" % ("无" if not leak else leak))

    # The comparison is claimed in three places, so all three are read back:
    # the widget, the bytes on disk and the two report files as written.
    from sysprobe import history as _hist
    where = _hist.path()
    scans, state = _hist.load(where)
    raw = open(where, "rb").read() if os.path.isfile(where) else b""
    short = window.compare.text()
    full = window.compare.toolTip()
    digits = re.findall(r"\d+", short)
    in_txt = in_html = False
    for name in produced:
        body = open(os.path.join(window.report_folder, name), "rb").read()
        if full and full in body.decode("utf-8-sig", "replace"):
            if name.startswith("体检结果"):
                in_txt = True
            else:
                in_html = True
    print("\n历史对比：这份文件第 %d 次记录（上限 %d）｜ %d 字节 ｜ 读回状态 %s"
          % (len(scans), _hist.KEEP, len(raw), state))
    print("　窗口那句：%s ｜ 悬停那句：%s" % (short or "空",
                                             (full[:40] + "…") if len(full) > 40
                                             else (full or "空")))
    print("　两份报告里有没有这句整话：文字版 %s ｜ 网页版 %s ｜ 剪贴板 %s"
          % ("有" if in_txt else "无", "有" if in_html else "无",
             "有" if full and full in blob else "无"))
    print("　文件里有没有人话（应无）：%s ｜ 短句里的数字 %s 都能在整句里找到: %s"
          % ("有" if raw and max(raw) >= 0x80 else "无",
             "、".join(digits) or "没数字",
             "是" if all(d in full for d in digits) else "否"))

    bar, spare, horiz = fits_at_minimum(window)
    print("收到最窄（%d px）时：底部按钮需要 %d px，余量 %+d px ｜ 横向滚动 %s"
          % (window.minimumWidth(), bar, spare, "有" if horiz else "无"))
    window.resize(window.minimumWidth(), window.minimumHeight())
    flush_layout(window)
    cols_min = window._cols
    vp_min = window.scroll.viewport().width()
    narrow_card = min(c.width() for c in cards)
    board_min = window.board.sizeHint().height()
    window.resize(940, 700)
    flush_layout(window)
    cols_wide = window._cols
    vp = window.scroll.viewport()
    per_screen = sum(1 for c in cards if c.y() + c.height() <= vp.height())
    # Machine-independent half of the same contract: whatever this machine
    # happens to report today, no single card may outgrow the viewport. Without
    # it a long step list on another person's PC reads as a layout bug later.
    tallest = max((c.height() for c in cards), default=0)
    # The first screen belongs to the cards, so the row that costs the most is
    # printed with what is inside it: a status tag and an inline 怎么做 both take
    # width from the headline, and that is what decides whether a conclusion
    # stands at 53 px or at 111 px.
    widest = max(cards, key=lambda c: c.height(), default=None)
    if widest is not None:
        bits = {l.objectName(): l.width() for l in widest.findChildren(QLabel)}
        print("　最占地方那张卡：%s，高 %d px ｜ 角标 %s px ｜ 展开按钮 %s px"
              % (widest.f.module, widest.height(),
                 bits.get("Tag", "没挂"),
                 widest.toggle.width() if widest.toggle is not None else "没挂"))
    print("窗口 %d px -> 列数 %d ｜ 一张卡 %d px，占口宽 %d px 的 %d%% ｜ 板 %d px"
          % (window.minimumWidth(), cols_min, narrow_card, vp_min,
             round(narrow_card * 100.0 / max(1, vp_min)), board_min))
    print("回到 940 px -> 列数 %d ｜ 板 %d px ｜ 一屏完整装下 %d 张 ｜ "
          "滚动口 %d px ｜ 外框 %d px ｜ 最高一张卡 %d px"
          % (cols_wide, window.board.sizeHint().height(), per_screen,
             vp.height(), window.height() - vp.height(), tallest))

    # The complaint chips fold cards away, so the gate checks both halves: what
    # stays must belong to the word pressed, and 都看 must hand every card back.
    chips = [c for c in window.symptom_box.findChildren(QPushButton)
             if c.text() != SYMPTOM_ALL]
    visible = lambda: sum(1 for c in cards if not c.isHidden())
    base = visible()
    rows = []
    filter_note = ""
    empty_note = ""
    num_bad = []
    for chip in chips:
        chip.click()
        flush_layout(window)
        left = [c for c in cards if not c.isHidden()]
        want = dict(SYMPTOMS)[chip.text()]
        stray = [c.f.module for c in left if c.f.module not in want]
        note = window._filter_note.text()
        rows.append((chip.text(), len(left), len(stray), bool(note)))
        # The line has to carry the numbers a reader can check against the board,
        # not the ones the code meant to write. A chip that lands on nothing
        # quotes only the total, so it is checked against that shape.
        nums = (len(left), base - len(left)) if left else (base,)
        if not all(("%d 条" % n) in note for n in nums):
            num_bad.append(chip.text())
        if left:
            filter_note = note
        else:
            empty_note = note
    window._all_chip.click()
    flush_layout(window)
    back = visible()
    from sysprobe.report.html import MODULE_LABEL
    known = set(MODULE_LABEL)
    mapped_keys = {m for _w, ms in SYMPTOMS for m in ms}
    unknown = sorted(m for m in mapped_keys if m not in known)
    uncovered = sorted(known - mapped_keys)
    window.resize(window.minimumWidth(), window.minimumHeight())
    flush_layout(window)
    chip_h = window.symptom_box.height()
    chip_horiz = window.scroll.horizontalScrollBar().isVisible()
    widest = max(c.width() for c in window.symptom_box.findChildren(QPushButton))
    chips_min = min(c.width() for c in chips)
    window.resize(940, 700)
    flush_layout(window)
    print("症状条：体检后露出 %s ｜ 共 %d 只词 ｜ 最窄一只 %d px ｜ 默认状态可见 %d 张"
          % ("是" if not window.symptom_box.isHidden() else "否",
             len(chips), chips_min, base))
    print("　逐个点：%s" % " ／ ".join("%s→%d张(越界%d%s)"
                                        % (w, n, bad, "" if has_note else "，无说明")
                                        for w, n, bad, has_note in rows))
    print("　点“%s”回来：%d 张 ｜ 收起时那行字：%s"
          % (SYMPTOM_ALL, back, filter_note[:38] or "没出现"))
    print("　筛空了那行字：%s" % (empty_note or "这次每只词都能对上卡"))
    print("　映射表：%d 只键，词指向不存在的：%s ｜ 没词管的：%s"
          % (len(known), "、".join(unknown) or "无",
             "、".join(MODULE_LABEL[m] for m in uncovered) or "无"))
    print("　收到最窄（%d px）：这条占 %d px（应只有一行）｜ 最大一只词 %d px ｜ 横向滚动 %s"
          % (window.minimumWidth(), chip_h, widest, "有" if chip_horiz else "无"))

    fails = []
    if mapped:
        fails.append("窗口被映射到了桌面（本该只在后台量）")
    if not ok:
        fails.append("线程没完成")
    if not cards:
        fails.append("看板是空的")
    if dirty:
        fails.append("界面出现底层词汇")
    if not window.manual_btn.isEnabled():
        fails.append("手册按钮体检前点不动")
    if dlg.pages() != pages_want:
        fails.append("手册页数和内容表对不上（有一页没建出来）")
    if dirty_manual:
        fails.append("手册文字里有底层词汇：%s" % (dirty_manual[:2],))
    if not window.report_written or len(produced) < 2:
        fails.append("报告没写出两个文件")
    if leak:
        fails.append("剪贴板泄露本机身份")
    if spare < 0:
        fails.append("最窄窗口放不下底部按钮")
    if horiz:
        fails.append("看板出现横向滚动条")
    if not size:
        fails.append("仓库里缺素材文件")
    if scaled is None or not art_ok:
        fails.append("看板娘没画上：素材读不到或解码失败")
    if say_want is not None and window.hero_say.text() != say_want:
        fails.append("横幅上那句话没跟着结果变")
    if total != len(window.findings):
        fails.append("四档计数与结论数对不上")
    if not bar_ok:
        fails.append("状态栏没把未获取的条数报出来")
    if (window.quiet and not any("看过" in n for n in notes)) or \
            (window.unread and not any("没取到" in n for n in notes)):
        fails.append("看板说明条把两种情况混着说了")
    if stretched > 8:
        fails.append("主按钮又被拉成了通宽横幅")
    if not in_band:
        fails.append("主按钮没待在横幅带里（上面那行几何数是从旧布局量的）")
    if not meter_under:
        fails.append("进度条没紧跟在横幅带下面")
    if len(tags) != sum(1 for c in cards if not c.folded):
        fails.append("正常项又挂上了重复角标")
    if cards and any(c.graphicsEffect() is None for c in cards):
        fails.append("卡片没挂上柔和阴影")
    if spine_bad:
        fails.append("状态左脊没画到像素上：%s" % "；".join(spine_bad))
    if head_bad:
        fails.append("分组标题没染上自己那档的颜色：%s" % "、".join(head_bad))
    if tail > 130:
        fails.append("看板娘的气泡尾巴没画出来")
    if not heads:
        fails.append("看板没有分组标题，状态只剩颜色在说话")
    if box_off is not True:
        fails.append("还没体检，症状条就已经露出来了")
    if len(chips) != len(SYMPTOMS):
        fails.append("症状条上的词和映射表对不上数")
    if base != len(cards) or back != base:
        fails.append("点“%s”没能把卡片全部放回来" % SYMPTOM_ALL)
    if any(bad for _w, _n, bad, _h in rows):
        fails.append("筛出来的卡里有对不上这个词的项")
    if any(not has_note for _w, n, _b, has_note in rows if n < base):
        fails.append("卡片收起来了，却没写清楚是被谁收走的")
    if num_bad:
        fails.append("说明里那两个数没对上看板：%s" % "、".join(num_bad))
    if state not in ("ok", "first"):
        fails.append("历史文件读不回来（状态 %s）" % state)
    if not short:
        fails.append("界面上那句对比没显示出来")
    if not full:
        fails.append("短句成了唯一说法，悬停里没有整句")
    if full and (not in_txt or not in_html):
        fails.append("两份报告里没写这句对比，窗口和文件说法不一致")
    if full and full not in blob:
        fails.append("复制出去的文本里没写这句对比")
    if raw and max(raw) >= 0x80:
        fails.append("历史文件里冒出人话（这文件本该只存编号）")
    if len(scans) > _hist.KEEP:
        fails.append("历史记录过了 %d 次还在往上堆" % _hist.KEEP)
    if empty_note and ("没对上" not in empty_note or SYMPTOM_ALL not in empty_note):
        fails.append("一只词对上 0 张卡时，那行字没告诉他下一步点哪")
    if unknown:
        fails.append("症状词指向了不存在的检查项")
    if min(c.width() for c in chips) <= 0:
        fails.append("症状条上的词被挤到看不见")
    if window.symptom_box.height() > 90:
        fails.append("症状条占了不止一行，看板能露出的高度又被吃掉一截")
    if chip_h > 90:
        fails.append("最窄处症状条挤成了两行")
    if chip_horiz:
        fails.append("加了症状条以后，看板出现横向滚动条")
    if cols_min != 1 or cols_wide != 2:
        fails.append("两列没在最窄处退回单列")
    if narrow_card * 10 < vp_min * 9:
        fails.append("退回单列后卡片仍只占半行，另一半是空的")
    if not 3 <= per_screen:
        fails.append("一屏装不下三张结论，看板又变回翻页")
    if tallest > vp.height():
        fails.append("有一张卡比滚动口还高：%d px > %d px" % (tallest, vp.height()))
    print("\n%s（检查项 %d 只，结论 %d 条）"
          % ("通过" if not fails else "失败：" + "、".join(fails),
             len(probes.PROBES), len(window.findings)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
