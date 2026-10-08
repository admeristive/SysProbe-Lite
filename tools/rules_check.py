"""Rule-library check: the loader must work, and it must not fire on innocent
software.

Four things are asserted here, because a blacklist is the one feature of this
tool that can both scare a novice and name a real company wrongly:
  1. the shipped 故障规则库.json parses and passes the schema check;
  2. all entry forms (name / exe / path_prefix, both drive-anchored and any-drive
     segment form) actually match;
  3. common legitimate software produces zero matches - checked against BOTH the
     synthetic test library and the shipped library, since the false positives
     live in the shipped data;
  4. this machine's real startup items and services still produce zero red labels.

Run:  py -3 tools/rules_check.py
"""

import json
import os
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from sysprobe import paths, probes, rules  # noqa: E402

# Innocent by any reasonable standard; some carry no Microsoft signature, which
# is exactly the condition a naive blacklist would misfire on. `path` is filled in
# as well as `command`, because the path rule is only exercised when a probe hands
# the matcher an extracted path - leaving it out would blind this gate to the one
# class of bug that actually shipped once (a vendor-root prefix eating WPS Office).
INNOCENT = [
    {"name": "Steam", "path": "C:\\Program Files (x86)\\Steam\\steam.exe",
     "command": '"C:\\Program Files (x86)\\Steam\\steam.exe" -silent'},
    {"name": "WeChat", "path": "C:\\Program Files (x86)\\Tencent\\WeChat\\WeChat.exe",
     "command": '"C:\\Program Files (x86)\\Tencent\\WeChat\\WeChat.exe"'},
    {"name": "RtkAudioUniversalService", "path": "C:\\Windows\\System32\\RtkAudioUniversalService.exe",
     "command": "C:\\Windows\\System32\\RtkAudioUniversalService.exe"},
    {"name": "NvContainerLocalSystem", "path": "C:\\Program Files\\NVIDIA Corporation\\NvContainer\\nvcontainer.exe",
     "command": '"C:\\Program Files\\NVIDIA Corporation\\NvContainer\\nvcontainer.exe"'},
    {"name": "OneDrive", "path": "C:\\Users\\me\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
     "command": '"C:\\Users\\me\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background'},
    {"name": "Logi Download Assistant", "path": "C:\\Program Files\\LogiDownloadAssistant\\LogiDownloadAssistant.exe",
     "command": '"C:\\Program Files\\LogiDownloadAssistant\\LogiDownloadAssistant.exe"'},
    {"name": "ctfmon", "path": "C:\\Windows\\System32\\ctfmon.exe",
     "command": "C:\\Windows\\System32\\ctfmon.exe"},
    {"name": "SogouImeCloud", "path": "C:\\Program Files (x86)\\SogouInput\\SgTool.exe",
     "command": '"C:\\Program Files (x86)\\SogouInput\\SgTool.exe"'},
    {"name": "WPS Office", "path": "C:\\Program Files (x86)\\Kingsoft\\WPS Office\\11.8.2.12345\\office6\\wps.exe",
     "command": '"C:\\Program Files (x86)\\Kingsoft\\WPS Office\\11.8.2.12345\\office6\\wps.exe" -autostart'},
    {"name": "WPS 云服务", "path": "C:\\Users\\me\\AppData\\Roaming\\Kingsoft\\wps\\addons\\kdesk.exe",
     "command": '"C:\\Users\\me\\AppData\\Roaming\\Kingsoft\\wps\\addons\\kdesk.exe"'},
    {"name": "WPSUpdater", "path": "C:\\Program Files (x86)\\Kingsoft\\WPS Office\\wpsupdate.exe",
     "command": '"C:\\Program Files (x86)\\Kingsoft\\WPS Office\\wpsupdate.exe" -fromschedule'},
    {"name": "QQExternal", "path": "D:\\Games\\Tencent\\QQ\\Bin\\QQExternal.exe",
     "command": '"D:\\Games\\Tencent\\QQ\\Bin\\QQExternal.exe" -min'},
    {"name": "CloudMusic", "path": "D:\\Tools\\NetEase\\CloudMusic\\cloudmusic.exe",
     "command": '"D:\\Tools\\NetEase\\CloudMusic\\cloudmusic.exe" --autolaunch'},
]

SYNTH = {
    "schema": rules.SCHEMA_VERSION,
    "version": "自检专用",
    "reviewed": "自检专用",
    "known_bad": [
        {"name": "某某影音助手", "reason": "按 name 完全匹配"},
        {"exe": "badhelper.exe", "reason": "按 exe 名匹配"},
        {"path_prefix": "C:\\ProgramData\\SneakyBundle\\", "reason": "按安装路径前缀匹配（写死盘符）"},
        {"path_prefix": "\\DeepJunk\\", "reason": "按目录片段匹配（任意盘符、任意深浅）"},
    ],
}


def ctx_with(library):
    return types.SimpleNamespace(
        root=ROOT, temp_dir=tempfile.gettempdir(), rules=library,
        win11=probes.win11(), app_codes=set(), started=0.0)


def main():
    fails = []

    shipped = rules.load(paths.app_root())
    entries = shipped.known_bad()
    print("出厂规则库：%s" % ("外部文件已加载" if shipped.external else "内置默认"))
    print("  版本 %s（%s 校订）｜ schema 校验 %s"
          % (shipped.version, shipped.reviewed,
             "失败：" + str(shipped.load_error) if shipped.load_error else "通过"))
    print("  known_bad 条目：%d 条" % len(entries))
    if shipped.load_error:
        fails.append("出厂规则库解析失败")

    with open(os.path.join(ROOT, "故障规则库.json"), "rb") as handle:
        raw = json.loads(handle.read().decode("utf-8-sig"))
    if not isinstance(raw.get("known_bad"), list):
        fails.append("故障规则库.json 的 known_bad 不是数组")
    print("  JSON 顶层键：%s" % ", ".join(sorted(raw)))

    # The loader only ever accepts the one contracted file name in a directory,
    # so the synthetic library has to be written under that name to be loaded.
    tmp_dir = os.path.join(tempfile.gettempdir(), "sysprobe_rules_check")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp = os.path.join(tmp_dir, "故障规则库.json")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(SYNTH, handle, ensure_ascii=False)
    loaded = rules.load(tmp_dir)
    if not loaded.external:
        print("  !! 自检库没有被当作外部文件加载")
    fired = 0
    for item in ({"name": "某某影音助手", "command": ""},
                 {"name": "updater", "path": "C:\\x\\BadHelper.EXE",
                  "command": '"C:\\x\\BadHelper.EXE" /s'},
                 {"name": "shell", "path": "C:\\ProgramData\\SneakyBundle\\run.exe"},
                 {"name": "deep", "path": "D:\\下载\\Tools\\DeepJunk\\2026\\helper.exe"}):
        hit = loaded.match_bad(item)
        print("  注入自检库：%-14s -> %s" % (item.get("name"), "命中" if hit else "未命中"))
        if hit:
            fired += 1
    os.remove(tmp)
    os.rmdir(tmp_dir)
    if fired != 4:
        fails.append("四种写法只有 %d 种能命中" % fired)

    quiet = [i["name"] for i in INNOCENT if loaded.match_bad(i)]
    print("  %d 个正常软件在装满黑名单的库下命中：%s" % (len(INNOCENT), quiet or "0 个"))
    if quiet:
        fails.append("误报：%s" % quiet)

    shipped_quiet = [i["name"] for i in INNOCENT if shipped.match_bad(i)]
    print("  %d 个正常软件在出厂规则库下命中：%s" % (len(INNOCENT), shipped_quiet or "0 个"))
    for i in INNOCENT:
        h = shipped.match_bad(i)
        if h:
            print("     !! %s 被规则「%s」点红：%s" % (i["name"], h.get("name"), i["path"]))
    if shipped_quiet:
        fails.append("出厂规则库误报：%s" % shipped_quiet)

    real = probes.probe_startup(ctx_with(loaded))
    red = [f for f in real if f.status is probes.Status.RED]
    print("  本机真实自启项用同一把黑名单去查：%d 条结论，红标 %d 条"
          % (len(real), len(red)))
    for f in real:
        print("     %s ｜ %s" % (f.status.value, f.headline[:70]))
    if red:
        fails.append("本机自启项被打红标 %d 条" % len(red))

    svc = probes.probe_services(ctx_with(loaded))
    print("  服务排查加载规则库：%s（结论 %d 条）"
          % (loaded.external, len(svc)))

    print("\n%s" % ("通过：库能读、能命中，冤枉不了正常软件"
                   if not fails else "失败：" + "；".join(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
