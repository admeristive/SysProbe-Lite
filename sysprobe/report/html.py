"""HTML report. 100% self-contained: one <style> block, no images, no script,
no font, no link that the browser would fetch on its own. The only URLs that
appear are printed as text for a human to read and open deliberately.

Layout follows the product rule: disclaimer above the fold, then the traffic
lights, then the fixes. Colour is never the only signal - every row carries a
shape and a word, so the report still reads on a screen the colour is broken
on or to someone colour-blind.
"""

import html

from ..model import GLYPH, ORDER, Status

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#f4f5f7;color:#1c1f24;
font:16px/1.75 "Microsoft YaHei","微软雅黑","Segoe UI",sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:28px 20px 72px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:.5px}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:8px;
border-bottom:1px solid #dfe2e7}
.sub{color:#67707d;font-size:14px;margin:0 0 22px}
.card{background:#fff;border:1px solid #dfe2e7;border-radius:8px;
padding:18px 20px;margin:0 0 14px}
.notice{background:#fffdf3;border:1px solid #e8dcae;border-radius:8px;
padding:18px 20px;margin:0 0 26px}
.notice b{color:#8a6d1b}
.board{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 26px}
.chip{flex:1 1 150px;background:#fff;border:1px solid #dfe2e7;border-radius:8px;
padding:14px 16px}
.chip .n{font-size:30px;font-weight:600;line-height:1.15}
.chip .t{font-size:14px;color:#67707d}
.row{background:#fff;border:1px solid #dfe2e7;border-left:5px solid #c9ced6;
border-radius:8px;padding:16px 18px;margin:0 0 12px}
.row.red{border-left-color:#c0392b}.row.yellow{border-left-color:#d8a400}
.row.green{border-left-color:#2f9e63}.row.gray{border-left-color:#aab1bb}
.tag{display:inline-block;font-size:13px;font-weight:600;padding:2px 10px;
border-radius:11px;margin-right:10px;vertical-align:2px}
.tag.red{background:#fbeceb;color:#a5322a}
.tag.yellow{background:#fdf5e3;color:#8a6d1b}
.tag.green{background:#e9f6ef;color:#227a4c}
.tag.gray{background:#eef0f3;color:#5c6470}
.head{font-size:18px;font-weight:600;margin:0 0 6px}
.plain{margin:0 0 8px;color:#3a4250}
.why{margin:0 0 8px;color:#67707d;font-size:14px}
ol{margin:8px 0 0;padding-left:22px}
ol li{margin:0 0 5px}
.cmd{font-family:Consolas,"Courier New",monospace;font-size:14px;
background:#eef0f3;border:1px solid #dfe2e7;border-radius:5px;
padding:8px 10px;margin:10px 0 0;white-space:pre-wrap;word-break:break-all}
.note{font-size:13px;color:#67707d;margin-top:8px}
details{margin:10px 0 0}
summary{cursor:pointer;color:#4a5261;font-size:14px}
table{border-collapse:collapse;width:100%;font-size:14px;margin-top:8px}
th,td{border:1px solid #dfe2e7;padding:6px 9px;text-align:left;
vertical-align:top}
th{background:#f4f5f7;font-weight:600}
.tech{font-family:Consolas,monospace;font-size:13px;color:#4a5261;
word-break:break-all}
.foot{margin-top:36px;padding-top:16px;border-top:1px solid #dfe2e7;
color:#67707d;font-size:14px}
@media print{body{background:#fff}.row,.card,.chip,.notice{border-color:#bbb}}
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
    counts = {s: sum(1 for f in shown if f.status is s) for s in ORDER}

    out = ['<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           "<title>%s</title>" % E(meta.get("title", "系统体检报告")),
           "<style>%s</style></head><body><div class=\"wrap\">" % CSS]

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

    out.append('<div class="card"><b>一句话总评</b><p>%s</p>'
               '<p class="note">系统版本：%s ｜ 规则库：%s（%s 校订）｜ 隐私处理：%s</p></div>'
               % (E(meta.get("verdict", "")), E(meta.get("os_label", "")),
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

    if skipped:
        out.append("<h2>本次没有下判断的项（%d 项）</h2>" % len(skipped))
        out.append('<p class="note">这些项要么是这台机器本来就没有（台式机没电池），'
                   '要么是普通权限看不到，要么是程序只给查法、不给猜。'
                   '看不到不等于有问题。</p>')
        out.extend(_row(f) for f in skipped)

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
