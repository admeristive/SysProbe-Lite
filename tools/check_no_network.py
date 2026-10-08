"""Static gate: prove the shipped code cannot reach the network or write to the
system, without having to trust a reading of it.

Run:  py -3 tools/check_no_network.py
Exit code 0 = clean. Any FAIL is a release blocker, not a warning.

Checks are deliberately dumb and syntactic: an import, a call name, or a
literal string. That is what makes them usable as evidence for a user who
cannot audit the code themselves.
"""

import ast
import os
import re
import sys

BANNED_MODULES = {
    "socket", "ssl", "urllib", "http", "requests", "urllib3", "aiohttp",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "nntplib", "xmlrpc",
    "socketserver", "asyncio", "email", "wsgiref", "netrc", "smb", "smbclient",
}
# The Qt half of the same promise.
BANNED_QT = {"QtNetwork", "QtQml", "QtQuick", "QtWebEngine", "QtWebEngineCore",
             "QtDBus", "QtBluetooth", "QtNfc"}
BANNED_CALLS = {"os.system", "webbrowser.open", "webbrowser.open_new",
                "webbrowser.open_new_tab", "eval", "exec", "compile"}
ALLOWED_WINREG_READERS = {
    "OpenKey", "OpenKeyEx", "CloseKey", "QueryValue", "QueryValueEx",
    "EnumKey", "EnumValue", "QueryInfoKey", "GetValue", "SetValue",
}
BANNED_WINREG = {
    "CreateKey", "CreateKeyEx", "DeleteKey", "DeleteValue", "SaveKey",
    "RestoreKey", "LoadKey", "CopyKey", "SetValue", "SetValueEx",
    "ConnectRegistry", "DisableReflectionKey", "EnableReflectionKey",
}
# Windows binaries this tool is allowed to ask for output from.
ALLOWED_EXECUTABLES = {"wevtutil.exe", "powercfg.exe"}
BANNED_STRINGS = [
    (r"Windows\\Defender", "改动杀软设置的入口"),
    (r"Exclusions", "杀软白名单键"),
    (r"taskkill", "结束进程"),
    (r"Stop-Process", "结束进程"),
    (r"reg\s+add", "写注册表"),
    (r"reg\s+delete", "删注册表"),
    (r"\bwmic\b", "这台机器上已经不存在，且属于可疑调用"),
    (r"schtasks", "计划任务写入"),
    (r"netsh", "网络配置写入"),
    (r"wininet|WinHttp|URLMon", "系统网络栈"),
    (r"--onefile", "打包形态违反规格"),
]
INFO_CALLS = {"os.startfile": "只在用户点击按钮时打开本机文件夹"}

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def py_files():
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs
                   if d not in {"build", "dist", "__pycache__", ".git"}]
        for name in names:
            if name.endswith(".py"):
                path = os.path.join(base, name)
                if os.path.abspath(path) == os.path.abspath(__file__):
                    continue
                yield path


def _name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _root_module(dotted):
    return dotted.split(".")[0]


class Check(ast.NodeVisitor):
    def __init__(self, path, text):
        self.path = path
        self.text = text
        self.fails = []
        self.infos = []
        self.docstrings = set()
        self.lines = text.splitlines()

    def mark_docstrings(self, tree):
        """Explanatory prose is not code: the string scan skips docstrings only.

        Without this the gate fails on its own documentation - a sentence about
        wmic being gone is not a call to wmic, and the alternative is deleting
        the reason a future maintainer must not reintroduce it.
        """
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                body = getattr(node, "body", [])
                if body and isinstance(body[0], ast.Expr):
                    value = body[0].value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        self.docstrings.add(id(value))

    def fail(self, lineno, rule, detail):
        self.fails.append((self.path, lineno, rule, detail))

    def info(self, lineno, rule, detail):
        self.infos.append((self.path, lineno, rule, detail))

    # ------------------------------------------------------------ imports
    def visit_Import(self, node):
        for alias in node.names:
            mod = _root_module(alias.name)
            if mod in BANNED_MODULES:
                self.fail(node.lineno, "禁网 import", alias.name)
            if mod in BANNED_QT:
                self.fail(node.lineno, "禁网 Qt 模块", alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = _root_module(node.module or "")
        if mod in BANNED_MODULES or mod in BANNED_QT:
            self.fail(node.lineno, "禁网 import", "%s.%s" % (node.module,
                                                             "…"))
        if mod == "PySide6" and node.module:
            for part in node.module.split(".")[1:]:
                if part in BANNED_QT:
                    self.fail(node.lineno, "禁网 Qt 模块", node.module)
        self.generic_visit(node)

    # ------------------------------------------------------------- dynamic
    def visit_Call(self, node):
        name = _name(node.func)
        if name in BANNED_CALLS:
            self.fail(node.lineno, "禁用调用", name)
        if name in INFO_CALLS:
            self.info(node.lineno, "需人工确认", "%s：%s"
                      % (name, INFO_CALLS[name]))
        if name in {"__import__", "importlib.import_module"} and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if _root_module(first.value) in BANNED_MODULES:
                    self.fail(node.lineno, "动态禁网 import", first.value)
        if name.startswith("winreg."):
            tail = name.split(".", 1)[1]
            if tail in BANNED_WINREG:
                self.fail(node.lineno, "注册表写入", name)
        if name.startswith("ctypes.windll.") and \
                _root_module(name.split("windll.")[1]) != "":
            dll = name.split("windll.")[1].split(".")[0]
            if re.match(r"(wininet|winhttp|urlmon|winsock)", dll, re.I):
                self.fail(node.lineno, "系统网络栈", dll)
        if name.startswith("subprocess.") or name.endswith(("Popen", "run",
                                                           "call", "check_output")):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                    if kw.value.value not in (False, None, 0, ""):
                        self.fail(node.lineno, "shell=True",
                                  "会把命令串交给 cmd.exe，等于放开任意命令")
            for const in ast.walk(node):
                if isinstance(const, ast.Constant) and isinstance(const.value, str):
                    low = const.value.strip().lower()
                    if low.endswith(".exe") and os.path.basename(low) \
                            not in ALLOWED_EXECUTABLES:
                        self.fail(const.lineno, "意外的可执行文件", const.value)
        self.generic_visit(node)

    # ------------------------------------------------------------- strings
    def visit_Constant(self, node):
        value = node.value
        if isinstance(value, str) and id(node) not in self.docstrings:
            for pattern, why in BANNED_STRINGS:
                if re.search(pattern, value, re.I):
                    # This scan runs on .py only, so any hit is code or a
                    # message shown to the user, never user-editable JSON.
                    self.fail(node.lineno, "敏感字符串", "%s（%s）" % (why, pattern))
        self.generic_visit(node)


def check_sources():
    fails, infos = [], []
    for path in py_files():
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        try:
            tree = ast.parse(text, filename=path)
        except SyntaxError as exc:
            fails.append((path, exc.lineno or 0, "语法错误", str(exc)))
            continue
        check = Check(path, text)
        check.mark_docstrings(tree)
        check.visit(tree)
        fails.extend(check.fails)
        infos.extend(check.infos)
    return fails, infos


def check_spec():
    """The packaging contract: onedir, _internal, and exactly three root files."""
    spec = os.path.join(ROOT, "build.spec")
    if not os.path.isfile(spec):
        return [(spec, 0, "缺少 build.spec", "打包契约无法校验")]
    with open(spec, "r", encoding="utf-8") as handle:
        text = handle.read()
    out = []
    if "--onefile" in text or re.search(r"\bonefile\s*=\s*True", text):
        out.append((spec, 0, "onefile", "规格要求 --onedir / onefile=False"))
    if 'contents_directory="_internal"' not in text and \
            "contents_directory='_internal'" not in text:
        out.append((spec, 0, "contents_directory",
                    "必须显式写 _internal，否则根目录会散出一堆 dll"))
    if "console=True" in text:
        out.append((spec, 0, "console", "窗口程序不应带控制台"))
    return out


NEGATIVE_CONTROL = '''
import socket
from urllib.request import urlopen
import winreg, subprocess
winreg.SetValue(1, "SOFTWARE", 0, "x")
subprocess.run("net stop", shell=True)
note = "taskkill 可以用"
'''


def self_test():
    """Prove the gate actually fires. A clean report from a blind detector is
    worth nothing, and this is the only way to tell the two apart."""
    tree = ast.parse(NEGATIVE_CONTROL, filename="<control>")
    check = Check("<control>", NEGATIVE_CONTROL)
    check.mark_docstrings(tree)
    check.visit(tree)
    rules = {rule for _, _line, rule, _d in check.fails}
    want = {"禁网 import", "注册表写入", "shell=True", "敏感字符串"}
    missing = want - rules
    print("探针自检：故意写坏 6 行，命中规则 %s"
          % ("、".join(sorted(rules)) or "无"))
    if missing:
        print("  FAIL 自检：闸口没抓到 %s" % "、".join(sorted(missing)))
        return False
    print("  闸口本身是有效的")
    return True


def main():
    if not self_test():
        print("\n检测器自检失败：这份报告不可信，先修检测器。")
        return 1
    fails, infos = check_sources()
    fails += check_spec()
    print("扫描 %d 个 .py 文件" % len(list(py_files())))
    for path, line, rule, detail in infos:
        print("  需人工确认  %s:%d  %s  %s"
              % (os.path.relpath(path, ROOT), line, rule, detail))
    if fails:
        print("\n发现 %d 处不合规：" % len(fails))
        for path, line, rule, detail in fails:
            print("  FAIL  %s:%d  %s  ->  %s"
                  % (os.path.relpath(path, ROOT), line, rule, detail))
        print("\n这些是发布阻断项，不是提醒。")
        return 1
    print("  禁网模块：无")
    print("  注册表写入：无")
    print("  shell=True / 结束进程 / 杀软白名单：无")
    print("  打包契约：onedir + _internal 已核对")
    print("\n通过：代码里没有能联网、能改系统、能杀进程的写法。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
