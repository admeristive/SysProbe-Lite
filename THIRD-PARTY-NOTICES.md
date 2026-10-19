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

## LGPL 全文（已随包提供）

LGPL-3.0 要求许可证全文随分发提供。包内 `_internal\licenses\LGPL-3.0.txt` 即 FSF 的
lgpl-3.0.txt 正文：7,634 字节、166 行、纯 ASCII，SHA256
`ade78d04982d69972d444a8e14a94f87a2334dd3855cc80348ea8e240aa0df2d`。
该文件本身开头就写着"允许复制和分发本文档的逐字副本，但不允许更改"，所以我们只做原样搬运。
`tools\build.py` 每次构建都会把仓库 `licenses\` 下的文件复制进 `_internal\licenses\`。

这份全文的来源，如实说明：本项目禁止联网抓取，构建期也没有下载，它取自本机既有的两处
独立副本——setuptools 内置依赖的一份，和 Git for Windows 里 libunistring 的一份。
两份逐行比对下来只差一处（FSF 网址写作 `https://` 与旧的 `http://`），入库的是较新的那一处。
如果你要在联网的机器上与 GNU 官网逐字核对，可以执行（本程序不会访问任何网络）：

```
curl -L -o licenses\LGPL-3.0.txt https://www.gnu.org/licenses/lgpl-3.0.txt
certutil -hashfile licenses\LGPL-3.0.txt SHA256
```

哈希与上一致即为同文；若不一致，以官网为准覆盖 `licenses\`，再跑一次 `py -3 tools\build.py`
即可，不需要改任何代码。

官方条款获取地址（仅供你自己核对后打开，本程序不会访问任何网络）：
- LGPL-3.0：https://www.gnu.org/licenses/lgpl-3.0.txt
- Qt 授权条款：https://www.qt.io/terms-conditions
- Python 许可：https://docs.python.org/3/license.html
- PyInstaller 许可与引导器例外：https://pyinstaller.org

## 界面插图（不是第三方组件）

`assets\mascot.png` 是本项目界面顶部的插图。它由开发期在本仓库内用 AI 图像生成工具产出，
不属于任何已有作品的角色，也没有从网络上下载——本项目的代码闸口禁止任何出网行为。
产出后只用本机的一次性脚本做过背景透明处理，脚本不入库，仓库里只有处理完的那一张。

入仓文件实测：669,653 字节、1024×1024、8 位 RGBA、非隔行，SHA256 前 16 位 `89ca3e6ba2a37ac5`。
构建时随 `build.spec` 的 `datas` 复制到 `_internal\assets\mascot.png`；
HTML 报告**不内嵌这张图**，报告仍然只有一个 `<style>`、零图片、零字体。
它由 MIT 许可证覆盖，与源码同许可；如果你要分发修改后的发布包，连同 `LICENSE` 一起保留即可。

## 免责声明

本程序按"现状"提供，不构成维修承诺；界面与报告里的所有判断都来自本机只读检查结果，
红黄绿只是提示，不等于硬件一定有问题或一定没问题。详见 README.md 的免责声明一节。
