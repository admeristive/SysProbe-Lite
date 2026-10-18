"""Build 双击运行体检.exe, then verify the release contract.

Run:  py -3 tools/build.py            (adds --clean to throw away build cache)

The contract it checks afterwards is the one the product spec set:
the released folder holds exactly three files and one _internal folder.
Anything looser there is a bug, not a cosmetic choice - loose dlls next to
the exe are what makes a novice's antivirus (and their friend) nervous.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist", "双击运行体检")
APP_NAME = "双击运行体检"
APP_VERSION = "1.1.0"
PACKAGE = os.path.join(ROOT, "dist", "SysProbe-Lite_v%s_Portable.zip" % APP_VERSION)
ALLOWED_ROOT_FILES = {"%s.exe" % APP_NAME, "故障规则库.json", "必须看的使用说明.txt"}
ALLOWED_ROOT_DIRS = {"_internal"}


def run(cmd):
    print(">> %s" % " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, shell=False)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backfill_hash(hex_text, stamp):
    """Write the exe fingerprint into 必须看的使用说明.txt, before it is copied.

    The line is rewritten in place on every build, so a rebuilt binary never
    ships a stale fingerprint - which would be worse than none, because a user
    who compared it and found a mismatch would conclude he had been given a
    tampered file.
    """
    doc = os.path.join(ROOT, "必须看的使用说明.txt")
    with open(doc, "r", encoding="utf-8-sig") as handle:
        text = handle.read()
    line = "  本版 exe 的 SHA256：%s（打包时间 %s）" % (hex_text, stamp)
    if re.search(r"^  本版 exe 的 SHA256：.*$", text, re.M):
        text = re.sub(r"^  本版 exe 的 SHA256：.*$", line, text, count=1, flags=re.M)
    elif "（本说明在打包后会补上对应版本的指纹。）" in text:
        text = text.replace("（本说明在打包后会补上对应版本的指纹。）", line)
    else:
        anchor = "certutil -hashfile 双击运行体检.exe SHA256"
        if anchor not in text:
            print("  !! 说明里找不到指纹锚点，已跳过回填")
            return False
        text = text.replace(anchor, anchor + "\n\n" + line.split("\n")[0], 1)
    with open(doc, "wb") as handle:
        handle.write(b"\xef\xbb\xbf"
                     + text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    print("  指纹已回填进 必须看的使用说明.txt")
    return True


def folder_bytes(path):
    total = 0
    count = 0
    for base, _dirs, files in os.walk(path):
        for name in files:
            total += os.path.getsize(os.path.join(base, name))
            count += 1
    return total, count


def build_package():
    """Zip the release folder (Deflate 9) and prove the archive reads back.

    The zip is built here rather than by hand so the numbers written into
    RELEASE_NOTES.md can only ever come from the archive that actually shipped.
    """
    if os.path.isfile(PACKAGE):
        os.remove(PACKAGE)
    entries = 0
    with zipfile.ZipFile(PACKAGE, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for base, dirs, files in os.walk(DIST):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(base, name)
                archive.write(full, os.path.relpath(full, os.path.dirname(DIST)))
                entries += 1
    with zipfile.ZipFile(PACKAGE) as archive:
        broken = archive.testzip()
    if broken is not None:
        print("  !! 归档包 CRC 校验失败：%s" % broken)
        return None
    return entries


def backfill_release_notes(fingerprint, zip_hex, zip_bytes, entries):
    """Sync the three release numbers into RELEASE_NOTES.md, line by line.

    Anchored on the label text, so a hand-edited value is overwritten and a
    deleted line fails the build loudly instead of shipping a stale fingerprint -
    the same class of bug as the rule-library version drifting behind the report.
    """
    doc = os.path.join(ROOT, "RELEASE_NOTES.md")
    if not os.path.isfile(doc):
        print("  !! 没找到 RELEASE_NOTES.md，跳过回填")
        return False
    with open(doc, "r", encoding="utf-8-sig") as handle:
        text = handle.read()
    subs = (
        (r"^- 压缩包大小：.*$",
         "- 压缩包大小：**{:,} 字节（{:.2f} MB）**，{:,} 个条目，ZIP_DEFLATED level 9"
         .format(zip_bytes, zip_bytes / 1048576.0, entries)),
        (r"^- 压缩包 SHA256：.*$", "- 压缩包 SHA256：`%s`" % zip_hex),
        (r"^- 主程序 `.*` 官方指纹（SHA256）：.*$",
         "- 主程序 `%s.exe` 官方指纹（SHA256）：`%s`" % (APP_NAME, fingerprint)),
    )
    for pattern, line in subs:
        if not re.search(pattern, text, re.M):
            print("  !! RELEASE_NOTES.md 里找不到锚点：%s" % line[:24])
            return False
        text = re.sub(pattern, line.replace("\\", "\\\\"), text, count=1, flags=re.M)
    with open(doc, "wb") as handle:
        handle.write(text.replace("\r\n", "\n").encode("utf-8"))
    print("  三项发布数据已回填进 RELEASE_NOTES.md")
    return True


def main():
    clean = "--clean" in sys.argv[1:]
    pyi = [sys.executable, "-m", "PyInstaller", "build.spec", "--noconfirm"]
    if clean:
        pyi.append("--clean")
    result = run(pyi)
    if result.returncode != 0:
        print("打包失败，PyInstaller 返回 %d" % result.returncode)
        return 1

    exe = os.path.join(DIST, "%s.exe" % APP_NAME)
    if not os.path.isfile(exe):
        print("没找到产出的 exe：%s" % exe)
        return 1
    fingerprint = sha256_of(exe)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print("\nexe 的 SHA256：%s" % fingerprint)
    backfill_hash(fingerprint, stamp)

    for name in ("故障规则库.json", "必须看的使用说明.txt"):
        src = os.path.join(ROOT, name)
        if not os.path.isfile(src):
            print("缺少根目录文件：%s" % name)
            return 1
        shutil.copy2(src, os.path.join(DIST, name))

    # Third-party licence notices have to travel inside the binary folder: the
    # root is contractually three files, and a user who unzips without the repo
    # still needs to be able to read what Qt / PySide6 / CPython terms are.
    lic_dir = os.path.join(DIST, "_internal", "licenses")
    os.makedirs(lic_dir, exist_ok=True)
    shipped = []
    sources = [os.path.join(ROOT, n) for n in ("LICENSE", "THIRD-PARTY-NOTICES.md")]
    lic_extra = os.path.join(ROOT, "licenses")
    if os.path.isdir(lic_extra):
        sources += [os.path.join(lic_extra, n) for n in sorted(os.listdir(lic_extra))]
    for src in sources:
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(lic_dir, os.path.basename(src)))
            shipped.append(os.path.basename(src))
    print("\n许可证副本随包发布：%d 个文件 → _internal\\licenses（%s）"
          % (len(shipped), ", ".join(shipped) or "无"))
    if not shipped:
        print("  !! 包里没有任何许可证文件")
        return 1

    entries = set(os.listdir(DIST))
    extra = {e for e in entries
             if e not in ALLOWED_ROOT_FILES | ALLOWED_ROOT_DIRS}
    missing = ALLOWED_ROOT_FILES - entries
    print("\n发布目录：%s" % DIST)
    print("  条目：%s" % ", ".join(sorted(entries)))
    if extra:
        print("  不符合规格，多出来：%s" % ", ".join(sorted(extra)))
    if missing:
        print("  不符合规格，缺少：%s" % ", ".join(sorted(missing)))

    inside, inside_files = folder_bytes(os.path.join(DIST, "_internal"))
    exe_bytes = os.path.getsize(exe)
    whole, whole_files = folder_bytes(DIST)
    print("\n体积实测：")
    print("  主程序 exe：%d 字节（%.2f MB）" % (exe_bytes, exe_bytes / 1048576.0))
    print("  _internal：%d 个文件，%.1f MB" % (inside_files, inside / 1048576.0))
    print("  整个发布夹：%d 个文件，%.1f MB" % (whole_files, whole / 1048576.0))

    zip_items = build_package()
    if zip_items is None:
        return 1
    zip_bytes = os.path.getsize(PACKAGE)
    zip_hex = sha256_of(PACKAGE)
    print("\n归档包：%s" % PACKAGE)
    print("  %d 个条目，%d 字节（%.2f MB），压缩率 %.1f%%"
          % (zip_items, zip_bytes, zip_bytes / 1048576.0,
             100.0 * zip_bytes / whole))
    print("  zip 的 SHA256：%s" % zip_hex)
    if zip_items != whole_files:
        print("  !! 归档包条目数 %d 与发布夹文件数 %d 不一致" % (zip_items, whole_files))
        return 1
    if not backfill_release_notes(fingerprint, zip_hex, zip_bytes, zip_items):
        return 1

    # The txt the user reads must carry the same fingerprint the exe actually
    # has; verify it on the shipped copy, not on the source copy.
    with open(os.path.join(DIST, "必须看的使用说明.txt"), "r",
              encoding="utf-8-sig") as handle:
        shipped_doc = handle.read()
    hash_ok = fingerprint in shipped_doc
    with open(os.path.join(ROOT, "RELEASE_NOTES.md"), "r",
              encoding="utf-8-sig") as handle:
        notes = handle.read()
    notes_ok = (fingerprint in notes and zip_hex in notes
                and "**{:,} 字节".format(zip_bytes) in notes
                and "**{:,} 字节（{:.2f} MB）**，{:,} 个条目".format(
                    zip_bytes, zip_bytes / 1048576.0, zip_items) in notes)
    print("\n验收断言：")
    print("  根目录严格 3 文件 + _internal：%s"
          % ("通过" if not extra and not missing else "不通过"))
    print("  说明文件内含本版指纹：%s" % ("通过" if hash_ok else "不通过"))
    print("  Release 文案三项数据与实测逐字一致：%s" % ("通过" if notes_ok else "不通过"))
    if extra or missing or not hash_ok or not notes_ok:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
