# 第三方组件与许可证说明

本文件说明发布包 `SysProbe-Lite_v1.0.0_Portable.zip` 里**不属于本项目**的运行库。
构建时这份文件会被复制进 `_internal\licenses\`，用户端也能在包内看到它。

以下组件名称与许可证标识取自本机安装包的元数据实测（不是推测）：

| 组件 | 版本（本机实测） | 许可证（元数据原文） | 在发布包里的位置 |
| --- | --- | --- | --- |
| PySide6 | 6.11.2 | `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` | `_internal\PySide6\` |
| shiboken6 | 6.11.2 | 同上 | `_internal\shiboken6\` |
| Qt 6 运行库（QtCore / QtGui / QtWidgets 等 dll） | 随 PySide6 6.11.2 | LGPL-3.0-only（Qt 官方条款） | `_internal\PySide6\Qt\` |
| CPython 运行时 `python3.dll`、`python314.dll` | Python 3.14 | Python Software Foundation License | `_internal\` 顶层 |
| PyInstaller 引导器（已链进 `双击运行体检.exe`） | 6.22.2 | GPL-2.0-only **WITH** PyInstaller bootloader exception；该例外明确允许分发打包产物 | 主程序 exe 内部 |

构建期使用、**不在发布包内**的工具：PyInstaller hooks contrib 2026.7、pip 及站点包。

## LGPL 组件的处理方式

1. **只做动态链接，不改库。** 本项目不修改 PySide6 / Qt 的任何一行代码，也不静态编译进主程序；
   所有 Qt 相关 dll 都以独立文件形式留在 `_internal\` 里。
2. **可以替换。** 发布格式是 onedir（`_internal` 目录）而不是 onefile——onefile 会在每次启动时
   把自己解压到临时目录，用户无法替换里面的库。当前的目录结构允许用户把 `_internal\PySide6\` 、
   `_internal\shiboken6\` 里的文件换成他自己编译的同版本库，仍能正常运行。
   这条同时是打包契约里"绝对禁止 --onefile"的技术原因之一。
3. **源码可得。** 本项目源码在仓库根目录；Qt / CPython 的官方源码地址见下。

## 还差一件事（如实标注，发版前请补齐）

LGPL-3.0 要求各组件的**许可证全文**随分发提供。当前本机安装的 PySide6 wheel 里只有厂商自带的
一个 470 字节的商业授权声明片段（`LicenseRef-Qt-Commercial.txt`），**没有 LGPL 全文**，
而本项目禁止任何联网抓取，所以我没有把全文放进包里。

补齐办法（任选一条，都不需要动代码）：

```
# 1) 从 GNU 官网取 LGPL-3.0 正文，存到本仓库的 licenses\ 目录
curl -L -o licenses\LPGL-3.0.txt https://www.gnu.org/licenses/lgpl-3.0.txt

# 2) 或在你自己机器上的 Qt 安装目录里找 LICENSE 文件复制过去
```

放好之后 `tools\build.py` 会把 `licenses\` 下的所有文件一并复制进 `_internal\licenses\`，
不需要重新设计打包流程。

官方条款获取地址（仅供你自己核对后打开，本程序不会访问任何网络）：
- LGPL-3.0：https://www.gnu.org/licenses/lgpl-3.0.txt
- Qt 授权条款：https://www.qt.io/terms-conditions
- Python 许可：https://docs.python.org/3/license.html
- PyInstaller 许可与引导器例外：https://pyinstaller.org

## 免责声明

本程序按"现状"提供，不构成维修承诺；界面与报告里的所有判断都来自本机只读检查结果，
红黄绿只是提示，不等于硬件一定有问题或一定没问题。详见 README.md 的免责声明一节。
