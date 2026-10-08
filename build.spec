# -*- coding: utf-8 -*-
# PyInstaller spec for 系统简易体检仪.
#
# Contract, and why each line is load-bearing:
#   * onedir (never onefile): onefile unpacks itself into %TEMP% on every
#     launch, which is exactly the behaviour antivirus flags as suspicious,
#     and it makes the first start take 10+ seconds on a slow disk.
#   * contents_directory="_internal": without it the exe sits in a pile of
#     loose Qt dlls, which looks like malware dropping files next to itself.
#   * the two user-facing files are NOT bundled. They must be editable and
#     visible, so tools/build.py copies them next to the exe instead.
#   * excludes kill the whole Qt network surface plus the Python network
#     stack: if a future commit accidentally imports socket, the build fails
#     loudly instead of shipping a binary that can talk out.

import os

block_cipher = None
ROOT = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821 - set by PyInstaller
APP_NAME = "双击运行体检"

a = Analysis(  # noqa: F821
    [os.path.join("sysprobe", "app.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Qt bindings import their C++ halves dynamically; without these the
        # frozen build dies on QApplication with a missing plugin, not a
        # readable error.
        "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # --- network, all of it
        "socket", "ssl", "select", "selectors", "asyncio",
        "urllib", "urllib.request", "urllib.parse", "http", "http.client",
        "xmlrpc", "ftplib", "smtplib", "poplib", "imaplib", "nntplib",
        "telnetlib", "socketserver", "netrc", "email", "wsgiref",
        "multiprocessing", "sqlite3", "test", "unittest", "pydoc_data",
        # --- Qt we never use and that would drag chromium in
        "PySide6.QtNetwork", "PySide6.QtQml", "PySide6.QtQuick",
        "PySide6.QtWebEngine", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
        "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtDBus",
        "PySide6.QtMultimedia", "PySide6.QtPdf", "PySide6.QtPositioning",
        "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSvgWidgets",
        "PySide6.QtTest", "PySide6.Qt3DCore", "PySide6.QtCharts",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    contents_directory="_internal",
    name=APP_NAME,
)
