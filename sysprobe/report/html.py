"""HTML report. 100% self-contained: one <style> block, no images, no script,
no font, no link that the browser would fetch on its own. The only URLs that
appear are printed as text for a human to read and open deliberately.

Layout follows the product rule: disclaimer above the fold, then the traffic
lights, then the fixes. Colour is never the only signal - every row carries a
shape and a word, so the report still reads on a screen the colour is broken
on or to someone colour-blind.
"""

import html

from .. import theme
from ..model import GLYPH, ORDER, Status

CSS = """
*{box-sizing:border-box}
body{margin:0;background:%(page)s;color:%(text)s;
font:15px/1.8 "Microsoft YaHei","微软雅黑","Segoe UI",sans-serif
;-webkit-font-smoothing:antialiased}
::selection{background:%(sel_bg)s;color:%(ink)s}
.wrap{max-width:880px;margin:0 auto;padding:26px 24px 60px;
background:%(paper)s;border:1px solid %(line)s;
border-radius:18px 18px 4px 18px}
h1{font-size:23px;font-weight:700;color:%(ink)s;margin:0 0 3px}
h2{font-size:16px;font-weight:700;color:%(ink)s;margin:34px 0 12px;
padding-bottom:7px;border-bottom:1px solid %(line)s}
.sub{color:%(mute)s;font-size:13px;margin:0 0 24px}
.card{background:%(surface)s;border:1px solid %(line_card)s;
border-radius:12px 12px 4px 12px;padding:18px 20px;margin:0 0 12px}
.notice{background:%(yellow_bg)s;border:2px solid %(ink)s;
border-radius:14px 14px 5px 14px;padding:16px 20px;margin:0 0 24px}
.notice b{color:%(ink)s}
.notice p{margin:6px 0 0;color:%(text_soft)s}
.board{display:flex;flex-wrap:wrap;gap:9px;margin:0 0 24px}
.chip{flex:1 1 150px;border:1px solid %(line_card)s;
border-radius:12px 12px 4px 12px;padding:12px 14px;background:%(surface)s}
.chip .n{font-size:25px;font-weight:700;line-height:1.25;color:%(ink)s}
.chip .t{font-size:12px;color:%(mute)s}
.chip.red{background:%(red_bg)s;border-color:%(red_line)s}.chip.red .n{color:%(red_ink)s}
.chip.yellow{background:%(yellow_bg)s;border-color:%(yellow_line)s}.chip.yellow .n{color:%(yellow_ink)s}
.chip.green{background:%(green_bg)s;border-color:%(green_line)s}.chip.green .n{color:%(green_ink)s}
.chip.gray{background:%(surface)s}.chip.gray .n{color:%(mute_strong)s}
.row{background:%(surface)s;border:1px solid %(line_card)s;
border-radius:12px 12px 4px 12px;padding:15px 19px;margin:0 0 9px}
.row.red{background:%(red_bg)s;border-color:%(red_line)s}
.row.yellow{background:%(yellow_bg)s;border-color:%(yellow_line)s}
.row.green{background:%(green_bg)s;border-color:%(green_line)s}
.row.gray{background:%(surface)s;border-color:%(line_card)s}
.tag{display:inline-block;font-size:12px;font-weight:700;padding:2px 10px;
border-radius:10px 10px 4px 10px;margin-right:9px;vertical-align:2px;
background:%(neutral)s;color:%(white)s}
.tag.red{background:%(red_tag)s;color:%(white)s}
.tag.yellow{background:%(yellow_tag)s;color:%(yellow_tag_text)s}
.tag.green{background:%(green_tag)s;color:%(white)s}
.tag.gray{background:%(neutral)s;color:%(white)s}
.head{font-size:16px;font-weight:700;color:%(ink)s;margin:0 0 5px}
.plain{margin:0 0 6px;color:%(text)s}
.why{margin:0 0 6px;color:%(mute)s;font-size:13px}
ol{margin:6px 0 0;padding-left:20px}
ol li{margin:0 0 3px;color:%(text)s}
.cmd{font-family:Consolas,"Courier New",monospace;font-size:13px;
background:%(shelf)s;border:1px solid %(line_card)s;border-radius:8px;
padding:8px 10px;margin:9px 0 0;white-space:pre-wrap;word-break:break-all}
.note{font-size:12px;color:%(mute)s;margin-top:7px}
details{margin:8px 0 0}
summary{cursor:pointer;color:%(mute_strong)s;font-size:13px;font-weight:700}
summary:hover{color:%(accent)s}
table{border-collapse:collapse;width:100%%;font-size:13px;margin-top:8px}
th,td{border:1px solid %(line_card)s;padding:7px 10px;text-align:left;
vertical-align:top}
th{background:%(shelf)s;font-weight:700;color:%(ink)s}
tr:nth-child(even) td{background:%(zebra)s}
.tech{font-family:Consolas,"Courier New",monospace;font-size:12px;
color:%(mute_strong)s;word-break:break-all}
.foot{margin-top:32px;padding-top:14px;border-top:1px solid %(line)s;
color:%(mute)s;font-size:13px}
@media (max-width:620px){body{padding:0}.wrap{padding:20px 14px 46px;
border:none;border-radius:0}.chip{flex:1 1 120px}}
@media print{body{background:%(white)s;font-size:12px}.wrap{border:none;
background:%(white)s;padding:0}.row,.card,.chip,.notice,.cmd{border-color:%(print_line)s;
break-inside:avoid}h2{break-after:avoid}}
"""

LABEL = {Status.RED: "需处理", Status.YELLOW: "建议留意",
         Status.GREEN: "正常", Status.GRAY: "未获取"}
CLASS = {Status.RED: "red", Status.YELLOW: "yellow",
         Status.GREEN: "green", Status.GRAY: "gray"}

DISCLAIMER = (
    "这份报告由本机<b>只读</b>检查生成：程序不修改注册表、不删除文件、不结束进程、"
    "不联网上传任何东西，也不会改动杀毒软件的设置或白名单。"
    "所有可能造成影响的建议，都需要你自己确认后手动执行。"
    "红黄绿是提示，不是判决——绿色不等于电脑绝无问题，红色也不等于电脑已经坏了。"
)

MODULE_LABEL = {
    "stability": "突然关机与蓝屏",
    "display": "画面、显卡与软件冲突",
    "network": "网络、代理与系统服务",
    "startup": "开机自启动",
    "storage": "磁盘空间",
    "power": "电池与电源",
    "badges": "桌面图标角标",
    "paging": "虚拟内存",
    "toollocks": "系统工具是否被限制",
    "drawlimits": "软件界面资源占用",
    "refresh": "屏幕刷新率",
    "applist": "已装软件",
    "audio": "声音设备",
    "nic": "网卡",
}

E = html.escape


def _row(f):
    cls = CLASS[f.status]
    parts = ['<div class="row %s">' % cls]
    parts.append('<div class="head"><span class="tag %s">%s %s</span>%s</div>'
                 % (cls, E(GLYPH[f.status]), E(LABEL[f.status]), E(f.headline)))
    if f.plain:
        parts.append('<p class="plain">%s</p>' % E(f.plain))
    if f.why:
        parts.append('<p class="why">为什么会这样：%s</p>' % E(f.why))
    if f.steps:
        parts.append("<ol>")
        parts.extend("<li>%s</li>" % E(s) for s in f.steps)
        parts.append("</ol>")
    if f.copy_cmd:
        parts.append('<div class="cmd">%s</div>' % E(f.copy_cmd))
        parts.append('<p class="note">上面这一串只是地址，需要你自己在浏览器里核对'
                     '并打开；本程序不会替你访问它，也不会自动下载任何东西。</p>')
    if f.needs_admin:
        parts.append('<p class="note">这一项用普通权限看不全：'
                     '需要点“用管理员身份重新体检”再看一次。</p>')
    parts.append("</div>")
    return "".join(parts)


def _tech_table(findings, limit=40):
    if not findings:
        return '<p class="note">这一轮没有需要记录的原始线索。</p>'
    rows = []
    for f in findings[:limit]:
        native = "; ".join("%s=%s" % (k, v) for k, v in
                           sorted((f.native or {}).items())
                           if not isinstance(v, (list, dict)))
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                    % (E(MODULE_LABEL.get(f.module, f.module)), E(LABEL[f.status]),
                       E(f.headline), '<span class="tech">%s</span>' % E(native[:400])))
    more = ('<p class="note">另有 %d 条未在此列出。</p>' % (len(findings) - limit)
            if len(findings) > limit else "")
    return ("<p class=\"note\">前三栏已经把该做的事说完了。最后一栏是原始读数，"
            "给维修或懂电脑的人核对用，看不懂可以直接跳过。</p>"
            "<table><tr><th>检查项</th><th>结论</th><th>人话标题</th>"
            "<th>原始读数（已脱敏）</th></tr>%s</table>%s"
            % ("".join(rows), more))


def render(findings, meta):
    shown = [f for f in findings if not f.skip]
    skipped = [f for f in findings if f.skip]
    counts = {s: sum(1 for f in findings if f.status is s) for s in ORDER}

    out = ['<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           "<title>%s</title>" % E(meta.get("title", "系统体检报告")),
           "<style>%s</style></head><body><div class=\"wrap\">" % (CSS % theme.P)]

    out.append("<h1>%s</h1>" % E(meta.get("title", "系统简易体检仪 · 体检报告")))
    out.append('<p class="sub">生成时间 %s ｜ 检查项 %s 个 ｜ 耗时 %s ｜ 权限：%s</p>'
               % (E(meta.get("generated_at", "")), E(str(meta.get("probe_count", ""))),
                  E(meta.get("elapsed_text", "")), E(meta.get("admin_text", ""))))

    out.append('<div class="notice"><b>先读这一段</b><p>%s</p></div>' % DISCLAIMER)

    out.append('<div class="board">')
    for status in ORDER:
        out.append('<div class="chip %s"><div class="n">%d</div>'
                   '<div class="t">%s %s</div></div>'
                   % (CLASS[status], counts[status], E(GLYPH[status]),
                      E(LABEL[status])))
    out.append("</div>")

    hist = ('<p class="note">%s</p>' % E(meta["history_line"])
            if meta.get("history_line") else "")
    out.append('<div class="card"><b>一句话总评</b><p>%s</p>%s'
               '<p class="note">系统版本：%s ｜ 规则库：%s（%s 校订）｜ 隐私处理：%s</p></div>'
               % (E(meta.get("verdict", "")), hist, E(meta.get("os_label", "")),
                  E(meta.get("rules_version", "")), E(meta.get("rules_reviewed", "")),
                  E(meta.get("san_summary", ""))))

    if meta.get("rules_error"):
        out.append('<div class="card"><b>规则库没能读取，已改用程序内置规则</b>'
                   '<p class="note">%s</p></div>' % E(str(meta["rules_error"])[:300]))

    for status in (Status.RED, Status.YELLOW, Status.GREEN, Status.GRAY):
        group = [f for f in shown if f.status is status]
        if not group:
            continue
        out.append("<h2>%s %s（%d 项）</h2>"
                   % (E(GLYPH[status]), E(LABEL[status]), len(group)))
        if status is Status.RED:
            out.append('<p class="note">下面这些建议按顺序做，做完一项再看一次体检。'
                       '任何要你重装系统或花钱的步骤，报告里都不会主动推荐。</p>')
        by_mod = {}
        for f in group:
            by_mod.setdefault(MODULE_LABEL.get(f.module, f.module), []).append(f)
        for title in sorted(by_mod, key=lambda t: -len(by_mod[t])):
            out.append('<h2 style="font-size:16px;margin:20px 0 8px">%s</h2>' % E(title))
            out.extend(_row(f) for f in by_mod[title])

    quiet = [f for f in skipped if f.status is Status.GREEN]
    unread = [f for f in skipped if f.status is not Status.GREEN]
    if quiet:
        out.append("<h2>判过、结论正常的项（%d 项，不单独占一张卡）</h2>" % len(quiet))
        out.append('<p class="note">这些项核对过了，没有异常，就不各列一条；'
                   '原始读数在最下面的细节栏里都能看到。</p>')
        out.extend(_row(f) for f in quiet)
    if unread:
        out.append("<h2>这次没有取到的项（%d 项）</h2>" % len(unread))
        out.append('<p class="note">这些项要么是这台机器本来就没有（台式机没电池），'
                   '要么是普通权限看不到，要么是程序只给查法、不给猜。'
                   '没取到不等于有问题。</p>')
        out.extend(_row(f) for f in unread)

    out.append("<h2>给懂电脑的人看的细节</h2>")
    out.append('<div class="card"><details><summary>展开：每一项的原始读数'
               '（已去掉姓名、机器名、IP、网卡地址等个人信息）</summary>%s</details></div>'
               % _tech_table(shown + skipped))

    out.append('<div class="foot">报告文件：%s%s</div>'
               % (E(meta.get("report_path", "")),
                  "" if meta.get("in_place", True)
                  else "（程序所在文件夹不允许写入，已改放临时文件夹）"))
    out.append('<div class="foot">本程序是离线工具：这一页没有任何外部图片、字体、'
               '脚本或样式表，断网也能完整显示。</div>')
    out.append("</div></body></html>")
    return "".join(out)
