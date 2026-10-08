"""Plain-text report: what a novice pastes to whoever is helping them.

Everything here goes through the sanitizer at the call site, so this module
only formats. It deliberately carries the same step lists as the HTML report;
a screenshot-free conversation still needs the fix instructions.
"""

from ..model import GLYPH, ORDER, Status

DISCLAIMER = (
    "这份结果由本机只读检查生成：程序不修改注册表、不删除文件、不结束进程、"
    "不联网上传任何东西，也不改动杀毒软件设置。所有可能造成影响的建议都需要你自己"
    "确认后手动执行。红黄绿只是提示，不等于电脑一定能或一定不能开机。"
)

DIVIDER = "=" * 46


def _block(out, line):
    out.append(line)


def render(findings, meta):
    shown = [f for f in findings if not f.skip]
    skipped = [f for f in findings if f.skip]
    counts = {s: sum(1 for f in shown if f.status is s) for s in ORDER}

    out = [DIVIDER, "系统简易体检仪 · 体检结果", DIVIDER]
    _block(out, "生成时间：%s" % meta.get("generated_at", ""))
    _block(out, "系统版本：%s" % meta.get("os_label", ""))
    _block(out, "运行权限：%s" % meta.get("admin_text", ""))
    _block(out, "隐私处理：%s" % meta.get("san_summary", ""))
    _block(out, "程序版本：%s / 规则库：%s" % (meta.get("tool_version", ""),
                                             meta.get("rules_version", "")))
    out.append("")
    out.append("先读这一段")
    out.append("-" * 46)
    out.append(DISCLAIMER)
    out.append("")
    out.append("总览")
    out.append("-" * 46)
    out.append("需处理 %d 项 / 建议留意 %d 项 / 正常 %d 项 / 未获取 %d 项"
               % (counts[Status.RED], counts[Status.YELLOW],
                  counts[Status.GREEN], counts[Status.GRAY]))
    if meta.get("verdict"):
        out.append(meta["verdict"])
    out.append("")

    for status in (Status.RED, Status.YELLOW, Status.GREEN, Status.GRAY):
        group = [f for f in shown if f.status is status]
        if not group:
            continue
        out.append("【%s】%d 项" % (GLYPH[status], len(group)))
        out.append("-" * 46)
        for i, f in enumerate(group, 1):
            out.append("%d. %s" % (i, f.headline))
            if f.plain:
                out.append("   %s" % f.plain)
            if f.why:
                out.append("   为什么：%s" % f.why)
            if f.steps:
                out.append("   建议怎么做：")
                for n, step in enumerate(f.steps, 1):
                    out.append("     %d) %s" % (n, step))
            if f.copy_cmd:
                out.append("   官方下载地址（自己核对后打开）：%s" % f.copy_cmd)
            if f.needs_admin:
                out.append("   这一项用普通权限看不全，需要用管理员身份再体检一次")
            out.append("")

    if skipped:
        out.append("【本次没有下判断的项】%d 项" % len(skipped))
        out.append("-" * 46)
        for f in skipped:
            out.append("- %s" % f.headline)
            if f.plain:
                out.append("  %s" % f.plain)
            if f.steps:
                for n, step in enumerate(f.steps, 1):
                    out.append("  %d) %s" % (n, step))
        out.append("")

    out.append(DIVIDER)
    out.append("报告文件位置：%s" % meta.get("report_path", ""))
    if not meta.get("in_place", True):
        out.append("（程序所在文件夹不允许写入，已放到系统临时文件夹）")
    out.append("结束。把这一整段复制给别人就够了，不需要再截图。")
    return "\n".join(out)
