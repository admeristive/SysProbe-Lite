"""The handbook a novice can read without running a scan.

Everything here is static text: no reading, no path, no machine value enters
it, so the same pages ship to every machine. That is deliberate - the shapes
of a Windows system drive are fixed, and what a person actually has in those
folders is theirs to look at.

The wording gate (tools/wording_check.py) sweeps this file because every
string with Chinese in it counts as prose. Two rules follow from that list and
are worth naming here because they bind the copy:

- the low-level repair commands a helper would type are not written out. A
  novice cannot tell "look this up" from "run this", so those rows say who to
  ask instead of what to type;
- a product's own name is avoided where a category word works ("杀毒软件"),
  because the page has to stay true for whoever's antivirus happens to be
  installed.

Deleting is never offered as a button. The program does not touch files, so
every row hands the action back to the person and names the place they must
open themselves.
"""

# One page = a title, one line saying what the page is for, and rows. A row is
# (名字, 这是什么, 可以自己动手吗) - the third field is a verdict first, then
# the how, because the question a novice asks is "can I delete this folder".
PAGES = (
    {
        "标题": "C 盘上就那几类文件夹",
        "一句话": "看清一个文件夹归哪一类，比记住它叫什么有用。",
        "条目": [
            ("Windows",
             "系统自己的东西都在里面，包括界面、字体、驱动程序和更新。",
             "别删，也别改里面的任何东西。真要腾地方看第 2 页。"),
            ("Program Files 和 Program Files (x86)",
             "软件装进来时的默认位置。两个都是，一个给常规软件，一个给老软件。",
             "别从里面删文件夹。不想用某个软件了，去 设置 → 应用 里卸载。"),
            ("Users\\你自己的名字",
             "你自己的地盘：桌面、文档、下载、图片、音乐、视频都在这一层下面。",
             "只删你认得出的。认不出的先挪到 D 盘放几天，用着没事再删。"),
            ("Users\\你自己的名字\\AppData",
             "软件存自己数据的地方，也是 C 盘悄悄变胖最主要的原因。里面分 Local 和 Roaming 两半。",
             "别整个删。只有明确写着缓存的几处能清，见第 2 页。看到陌生的软件名字，先看它是不是在这层里。"),
            ("ProgramData",
             "所有用户共用的软件数据，一些软件的存档和配置在这儿。",
             "别删。要清某个软件留下的东西，用那个软件自己的清理入口。"),
            ("回收站的位置",
             "每个盘都有一个隐藏的回收站存放处，你删掉的东西先落到那儿，还占着 C 盘。",
             "只能靠右键回收站 → 清空 来清它，别自己去翻那个隐藏文件夹。"),
            ("两个占地方的系统文件",
             "一个叫休眠文件（记你合盖前的状态），一个叫虚拟内存文件（内存不够时借硬盘顶上）。它们都在 C 盘根上，体积跟着内存大小走。",
             "别手动删。要改大小只能从设置里改，改错了会出现软件打不开，见第 4 页的提醒。"),
        ],
    },
    {
        "标题": "能腾出地方的地方",
        "一句话": "每一处都写清是什么、怎么删，程序不替你动手。",
        "条目": [
            ("临时文件",
             "软件干活时留下的中间产物，正常情况下没用。体检时会顺手量一眼给你个数。",
             "最稳的路：设置 → 系统 → 存储 → 临时文件，勾上再点删除。它认得出的才会勾上。"),
            ("回收站",
             "你删过但还没真正清掉的东西。",
             "右键桌面回收站 → 清空回收站。清空前挨个看一眼，删掉的工作文件在这儿还能捞回来。"),
            ("下载",
             "浏览器存下来的安装包、压缩包、图片都在这里。装完的安装包通常没用了。",
             "自己打开这个文件夹，按大小排一下，只删认得出的。这里是最常白占十几个 G 的地方。"),
            ("浏览器缓存",
             "网页的图片文件副本，为了下次打开快。占几个 G 很正常。",
             "在浏览器自己的设置里清，别手动删它的文件夹。"),
            ("软件留下的旧版本和日志",
             "更新过的软件常把旧的安装包留着。",
             "只清软件名你认得出的那几处，或者用软件自己的清理功能。"),
            ("系统更新留下的旧版本",
             "大版本更新后，老系统的部分会留一阵子，为了让你能退回去。",
             "在 设置 → 系统 → 存储 里以独立一项列出来。确认当前系统用着没问题再清，清了就退不回去。"),
        ],
    },
    {
        "标题": "这几处别自己动手",
        "一句话": "省不下多少地方，出事却是大事。",
        "条目": [
            ("系统文件夹里的任何东西",
             "网上有教程让人进 Windows 文件夹挑文件删，省不了几百兆。",
             "别照做。删错的后果是开不了机。"),
            ("AppData 里认不出名字的整个文件夹",
             "聊天记录、游戏存档、工程文件、软件配置都藏在这层里。",
             "名字陌生不等于没用。删之前先在搜索里查这个软件名，或把它整个挪走几天。"),
            ("杀毒软件自己的文件夹",
             "它在 C 盘占的地方是它自保用的。",
             "别删也别禁用它的文件。真嫌它占地方，去它的设置里调，或者换软件时正常卸载。"),
            ("别人发的一键清理脚本",
             "一个批处理文件，双击就跑，说是能把 C 盘清空出来。",
             "别双击。这类脚本常把系统服务项和启动项一起删掉，出事时连诊断记录都没了。"),
            ("清理注册表类的工具",
             "号称扫出几千条错误、清完更快。",
             "别用。省不下空间，还可能删掉软件的卸载记录，之后那个软件卸不掉。"),
            ("固态硬盘的碎片整理",
             "老机械硬盘才需要的动作。",
             "不用做，做了反而多写一遍盘。系统自己会区分，不用你管。"),
        ],
    },
    {
        "标题": "值得打开的几个设置",
        "一句话": "都改得回去，也都能说出为什么改。",
        "条目": [
            ("存储感知",
             "让系统隔一阵自己清临时文件和空的回收站。",
             "设置 → 系统 → 存储 → 存储感知，打开，选个频率。有用在不用你记着去清。"),
            ("活动时间",
             "告诉系统什么时候你在用电脑，它就不在那个时段自动重启装更新。",
             "设置 → Windows 更新 → 高级选项 → 活动时间。不想第二天开机卡在更新界面就打开它。"),
            ("任务管理器",
             "看谁在占内存、谁在占硬盘。体检量出来的内存数，这里是它的详细版。",
             "Ctrl + Shift + Esc 直接开。首次打开点详细信息。别在这儿结束不认识的任务，先看清楚它属于哪个软件。"),
            ("显示刷新率",
             "屏幕一秒换几张画面。标着高刷屏却只有 60，就是这里没调。",
             "设置 → 系统 → 屏幕 → 高级显示。体检里那项屏幕刷新率就是看这个。"),
            ("通知与专注",
             "把没用的软件通知关掉，桌面安静下来。",
             "设置 → 系统 → 通知。挨个关你确实不看的，别一键全关，安全软件的提醒要留着。"),
            ("备份",
             "把文档、图片这类只有份的东西放到别处。",
             "设置 → 账户 → Windows 备份，或自己拷一份到外接盘。在动第 6 页那些事之前，这一步先做。"),
        ],
    },
    {
        "标题": "常用的快捷键",
        "一句话": "十二个够用，其余的都是花活。",
        "条目": [
            ("Win + E", "打开资源管理器，进到 此电脑。", "找文件夹、看还剩多少地方。"),
            ("Win + I", "打开设置。", "第 4 页那些开关都在里面。"),
            ("Win + D", "最小化所有窗口，露出桌面。", "再按一次回去。"),
            ("Win + L", "锁屏。", "离开工位按一下，别人就翻不了你东西。"),
            ("Alt + Tab", "在开着的窗口之间切。", "按住 Alt 再连按 Tab 可以挨个看。"),
            ("Win + Shift + S", "截一块屏幕。", "给帮忙看电脑的人发截图就用它，截完整那张卡。"),
            ("Ctrl + Shift + Esc", "打开任务管理器。", "卡住时先看是谁占满了。"),
            ("Win + P", "接了外接屏或投影仪时选怎么显示。", "第二块屏幕不亮先按它。"),
            ("Ctrl + Z", "撤销上一步。", "删错文件后立刻按，很多时候能退回来。"),
            ("F5", "刷新当前窗口。", "文件夹里东西没变过来时按。"),
            ("Ctrl + C 和 Ctrl + V", "复制和粘贴。", "剪切是 Ctrl + X，移动大文件夹时慢，别中途断电。"),
            ("Win + 数字", "从任务栏启动第几个位置上的软件。", "把常用的三个钉在任务栏，按 Win + 1 就开。"),
        ],
    },
    {
        "标题": "这几件事先停一下",
        "一句话": "不是不能做，是必须先有备份、必须有懂的人在旁边。",
        "条目": [
            ("格式化",
             "把整块盘或整个分区清空。做完东西就没了，普通手段捞不回来。",
             "需要它时：先把只有这一份的东西复制到别处，再确认你要格式化的是哪个盘符。对着 C 盘格式化等于抹掉系统。"),
            ("重置此电脑、重装系统",
             "会软件清空，选保留文件时也保不住装过的软件。",
             "先备份，先想清楚驱动和激活怎么办，再动手。能定位到某个软件的问题就别重装整台机器。"),
            ("压缩卷、扩展卷",
             "改动盘的大小边界。",
             "动之前先想清楚 D 盘能不能解决问题。分错一次可能整块盘的数据都要重来。"),
            ("改虚拟内存大小",
             "有人教你关掉它腾地方。关掉以后大内存软件会直接打不开。",
             "别关。真要把 C 盘腾开，挪到 D 盘也比关掉安全，改完要重启。"),
            ("长按电源键关机",
             "断电式关机，正在写文件的软件会受伤。",
             "偶尔卡死了这么来一次可以，别当日常关机方式。"),
            ("别人的远程协助",
             "装个远程控制，让陌生人上来就操作你电脑。",
             "只接受你确实认识、并且知道你是谁的人。全程屏幕别离开眼睛，用完立刻卸载。"),
        ],
    },
)

# The template a person sends when the board has nothing for their symptom. It
# lives here once so the window, the handbook and both reports all quote the
# same lines instead of three slightly different versions of the advice.
ASK_LINES = (
    "先跑一次体检，点生成报告，会得到一个网页版文件和一个文字版文件。",
    "发给帮你看电脑的人时，发文字版那份，或者点复制结果把纯文字贴过去。",
    "说清楚三件事：症状是什么、什么时候开始、已经自己试过什么。",
    "要发截图就截完整一张卡，别只截半句话。",
    "别把体检报告那个文件夹里的日志整份贴到公开场合，里面的错误记录带着你这台机器的路径。",
)

ASK_TITLE = "找人帮忙时，这样说"
ASK_ONE = "体检没查到原因，不等于没原因。把下面几句说全，比多描述十句更有用。"


def pages():
    return PAGES


def counts():
    """Numbers the handbook's own footer quotes, so they cannot drift."""
    rows = sum(len(p["条目"]) for p in PAGES)
    return len(PAGES), rows, len(ASK_LINES)
