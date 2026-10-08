"""Data Sanitizer.

Three passes, in this exact order:

  1. protect  - hide technical evidence (hashes, GUIDs, exception addresses,
                version numbers, C:\\Windows paths) behind opaque placeholders so
                the generic patterns below cannot chew them up.
  2. redact   - live identity values first (USERNAME/COMPUTERNAME/SID *values*,
                not the variable names), then structural patterns.
  3. restore  - put the protected evidence back.

Order matters twice over: literal replacement must precede the generic Base64
rule (a username sitting inside a path is not base64), and protection must
precede both (an exception address is 0xc0000005, which a lazy hex rule would
erase along with the very clue the report exists to show).
"""

import os
import re
import getpass

# Folders under \Users\ that are machine-wide and carry no personal identity.
_PUBLIC_USER_DIRS = {
    "public", "default", "default user", "defaultuser0", "all users",
    "wdagutilityaccount", "default app", "desktop.ini",
}

# Loopback/unspecified addresses appear inside fix instructions on purpose.
_KEEP_IPV4 = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.0", "169.254.0.0"}

_MARK = "\x01"


class Sanitizer:
    # ------------------------------------------------------------ 1. protect
    PROTECT = [
        re.compile(r"\b[0-9a-fA-F]{64}\b"),
        re.compile(r"\b[0-9a-fA-F]{40}\b"),
        re.compile(r"\b[0-9a-fA-F]{32}\b"),
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
        re.compile(r"\b0[xX][0-9a-fA-F]{4,16}\b"),
        re.compile(r"\b[A-Za-z]:\\Windows\\[^\s\"'<>|]{0,180}"),
        re.compile(r"\bMicrosoft-Windows-[A-Za-z0-9-]+\b"),
        re.compile(r"\bS-1-5-(?:18|19|20|32|11[1-9]|80)\b"),
    ]
    # Version numbers are protected by a decision, not a bare pattern: 10.0.26300.9457
    # is evidence, 192.168.10.23 is an address. A plain "[\d.]{4}" rule protected both
    # and silently disabled the IPv4 redactor.
    RX_VERSIONISH = re.compile(r"\b\d+(?:\.\d+){2,4}\b")

    # ------------------------------------------------------------ 2. redact
    # MAC before IPv6: both use colon-separated hex, MAC is the stricter shape.
    RX_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
    RX_IPV4 = re.compile(
        r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w])(?!\.\d)")
    # Tail is {1,40} on purpose: a {1,4} tail masked only "fe80::1234" and left the
    # rest of the address - which is the MAC-derived interface ID - in the report.
    RX_IPV6 = re.compile(
        r"(?<![\w.])(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F:]{1,40}(?:%\d{1,3})?(?![\w])"
        r"|(?<![\w.])(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F:]{1,40}(?![\w])"
        r"|(?<![\w:])::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F.:]{1,40}(?![\w])")
    RX_SID = re.compile(r"\bS-1-5(?:-\d+){2,}\b")
    RX_URLCRED = re.compile(r"\b[\w.+-]{2,}:[^\s/@]{3,}@(?:[\w-]+\.)+[A-Za-z]{2,}\b")
    RX_JWT = re.compile(r"\beyJ[A-Za-z0-9_+-]{8,}\.[A-Za-z0-9_+-.]{8,}\.[A-Za-z0-9_+-]{8,}\b")
    RX_CTX = re.compile(r"(?i)\b(token|passwd|password|pwd|secret|api[-_]?key|"
                        r"authorization|bearer|cookie|session[-_]?id)"
                        r"([\s_.\-]{0,3}[:=]\s*)(\S{3,})")
    # Mixed case AND a digit AND >=32 chars, no dots/dashes inside. That conjunction
    # is what keeps file names and all-lowercase hex blobs from being eaten alive.
    RX_B64 = re.compile(r"\b(?=[A-Za-z0-9+/]{32,}\b)"
                        r"(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[A-Z])"
                        r"(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{32,}={0,2}\b")
    RX_USERS = re.compile(r"([A-Za-z]:\\Users\\)(?!\.)([^\\/:*?\"<>|\r\n]{1,64})", re.I)
    # Two groups + a lookahead, so _user_dir() can reuse the same shape and the
    # trailing separator survives (one capture group here raised IndexError).
    RX_HOME = re.compile(r"(?<![\\\w])([\\/](?:home|Users)[\\/])"
                         r"([^\\/:*?\"<>|\s]{2,64})(?=[\\/])", re.I)

    def __init__(self, seed_extra=()):
        self.stats = {}
        self._seq = 0
        self._live = self._seed(seed_extra)

    # ------------------------------------------------------------------ seed
    # Only personal identifiers. The first version of this list also pulled the
    # path segments of TEMP/APPDATA, which meant the literal "C:" got replaced by
    # USER and every C:\Program Files path looked like a broken startup entry.
    _GENERIC = {"users", "public", "default", "appdata", "local", "roaming",
                "program files", "program files (x86)", "programdata", "windows",
                "temp", "tmp", "microsoft", "documents", "desktop", "downloads"}

    def _seed(self, extra):
        # Two kinds of identity, two kinds of replacement: a machine name masked
        # as "USER" makes the report claim a user that does not exist.
        user, host = set(), set()
        for key in ("USERNAME", "USERPROFILE", "HOMEPATH"):
            raw = os.environ.get(key, "")
            if raw:
                user.add(os.path.basename(raw.rstrip("\\/")))
        try:
            user.add(getpass.getuser())
        except Exception:
            pass
        for key in ("COMPUTERNAME", "USERDOMAIN", "LOGONSERVER"):
            raw = os.environ.get(key, "")
            if raw:
                host.add(raw.lstrip("\\"))
        user.update(v for v in extra if v)
        # The floor is 2, not 3: the earlier >=3 filter silently dropped every
        # short real name, and a two-character machine name leaked straight
        # through the gate. One-character names are skipped as collateral damage.
        vals = {}
        for pool, repl in ((user, "USER"), (host, "[已隐藏机器名]")):
            for v in pool:
                if v and len(v) >= 2 and ":" not in v and "\\" not in v \
                        and v.lower() not in self._GENERIC:
                    vals.setdefault(v, repl)
        # Windows names are case-insensitive; the longest match must win so that
        # "zhangsan" is not shredded into "USERsan" by a shorter "zhang".
        return sorted(vals.items(), key=lambda kv: len(kv[0]), reverse=True)

    # --------------------------------------------------------------- helpers
    def _hit(self, rule, n=1):
        if n:
            self.stats[rule] = self.stats.get(rule, 0) + n

    def _decide_version(self, keep):
        def decide(match):
            token = match.group(0)
            parts = token.split(".")
            if len(parts) == 4 and all(len(p) <= 3 and int(p) <= 255 for p in parts):
                return token
            return keep(match)
        return decide

    def _user_dir(self, match):
        seg = match.group(2).strip("\\")
        if not seg or seg.lower() in _PUBLIC_USER_DIRS:
            return match.group(0)
        self._hit("user_dir")
        return match.group(1) + "USER"

    # ---------------------------------------------------------------- public
    def text(self, src):
        if not isinstance(src, str) or not src:
            return src
        s = src

        held = {}

        def keep(match):
            token = "%sP%d%s" % (_MARK, self._seq, _MARK)
            self._seq += 1
            held[token] = match.group(0)
            return token

        for rx in self.PROTECT:                      # 1
            s = rx.sub(keep, s)
        s = self.RX_VERSIONISH.sub(self._decide_version(keep), s)

        for value, repl in self._live:                # 2a
            if not value:
                continue
            try:
                s, n = re.subn(re.escape(value), repl, s, flags=re.I)
            except re.error:
                continue
            self._hit("identity", n)

        s = self.RX_MAC.sub(lambda m: self._r("mac", "[已隐藏网卡地址]"), s)
        s = self.RX_IPV4.sub(self._ipv4, s)
        s = self.RX_IPV6.sub(self._ipv6, s)
        s = self.RX_SID.sub(lambda m: self._r("sid", "[已隐藏用户标识]"), s)
        s = self.RX_URLCRED.sub(lambda m: self._r("urlcred", "USER:****@主机"), s)
        s = self.RX_JWT.sub(lambda m: self._r("jwt", "[已隐藏登录凭证]"), s)
        s = self.RX_CTX.sub(
            lambda m: self._r("token", "%s%s[已隐藏]" % (m.group(1), m.group(2))), s)
        s = self.RX_B64.sub(lambda m: self._r("base64", "[已隐藏]"), s)
        s = self.RX_USERS.sub(self._user_dir, s)
        s = self.RX_HOME.sub(self._user_dir, s)

        for token, original in held.items():         # 3
            s = s.replace(token, original)

        return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", s)

    def _ipv4(self, match):
        if match.group(0) in _KEEP_IPV4:
            return match.group(0)
        return self._r("ipv4", "[已隐藏IP]")

    def _ipv6(self, match):
        value = match.group(0)
        if value in ("::1", "::", "fe80::"):
            return value
        return self._r("ipv6", "[已隐藏IP]")

    def _r(self, rule, replacement):
        self._hit(rule)
        return replacement

    def deep(self, obj):
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.text(str(k)): self.deep(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.deep(x) for x in obj]
        return obj

    def summary(self):
        total = sum(self.stats.values())
        if not total:
            return "本次未发现需要隐藏的个人信息"
        return "本次已自动隐藏 %d 处个人信息" % total
