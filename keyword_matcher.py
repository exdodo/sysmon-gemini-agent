"""
コマンドライン不審キーワードの精密マッチングモジュール (keyword_matcher.py)

単純な部分一致（サブストリング検索）による誤検知（例: `msiexec.exe` 内の `iex`、
`--proxy-bypass-list` 内の `bypass`、正規 System32 パスの `rundll32.exe` 等）を防ぐため、
単語境界・PowerShell 引数構文・正規 Windows システムDLL除外を組み合わせた判定を提供します。
"""

from __future__ import annotations

import re

_SYSTEM_RUNDLL32_EXE_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32\\rundll32.exe",
    "c:\\windows\\syswow64\\rundll32.exe",
)

_SYSTEM_REGSVR32_EXE_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32\\regsvr32.exe",
    "c:\\windows\\syswow64\\regsvr32.exe",
)

_SYSTEM32_DIR_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
)

# rundll32 がパス省略（ベアファイル名）で呼び出す代表的な正規 OS 標準 DLL / CPL
_TRUSTED_BARE_RUNDLL32_TARGETS: frozenset[str] = frozenset(
    {
        "acproxy.dll",
        "appwiz.cpl",
        "appxdeploymentextensions.onecore.dll",
        "bthprops.cpl",
        "cryptext.dll",
        "davclnt.dll",
        "desk.cpl",
        "devmgr.dll",
        "dfshim.dll",
        "firewall.cpl",
        "hotplug.dll",
        "iedkcs32.dll",
        "ieframe.dll",
        "iernonce.dll",
        "inetcpl.cpl",
        "intl.cpl",
        "irprops.cpl",
        "joy.cpl",
        "keymgr.dll",
        "main.cpl",
        "mmsys.cpl",
        "msdtctm.dll",
        "msutb.dll",
        "ncpa.cpl",
        "netplwiz.dll",
        "newdev.dll",
        "pcasvc.dll",
        "powercfg.cpl",
        "powrprof.dll",
        "printui.dll",
        "sendmail.dll",
        "shdocvw.dll",
        "shell32.dll",
        "shwebsvc.dll",
        "srchadmin.dll",
        "stobject.dll",
        "sysdm.cpl",
        "telephon.cpl",
        "timedate.cpl",
        "twinui.dll",
        "twinui.pcshell.dll",
        "usercpl.dll",
        "wscui.cpl",
        "wuaucpl.cpl",
    }
)

# System32 配下にあっても LOLBin 悪用・プロキシ実行に頻用される危険ターゲット/引数パターン
_ABUSED_RUNDLL32_RE = re.compile(
    r"(?:"
    r"https?://|ftp://|javascript:|vbscript:"
    r"|comsvcs\.dll|minidump"
    r"|mshtml(?:\.dll)?[,;\s]+runhtmlapplication"
    r"|pcwutl\.dll|launchapplication"
    r"|advpack\.dll|ieadvpack\.dll|registerocx"
    r"|syssetup\.dll|setupapi\.dll"
    r"|shell32\.dll[,;\s]+shellexec_rundll"
    r"|url\.dll[,;\s]+fileprotocolhandler"
    r"|zipfldr\.dll|scrobj\.dll"
    r"|\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\"
    r")",
    re.IGNORECASE,
)

_UNC_PATH_RE = re.compile(r"(?:^|[\s\"'])\\\\(?![.?]\\)")
_ARG_TOKEN_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'|(\S+)')

# (キーワード表示名, 正規表現, HIGH_RISK判定用フラグ)
KEYWORD_RULES: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    (
        "-enc",
        re.compile(
            r"(?:^|[\s\"'])(?:-|/)(?:enc|encodedcommand)(?=$|[\s\"':=])"
            r"|(?:^|\s)[-/]e(?:n|nc|nco|ncod|ncode|ncoded(?:command)?)?\s+[A-Za-z0-9+/]{16,}={0,2}(?=$|\s)",
            re.IGNORECASE,
        ),
        True,
    ),
    (
        "bypass",
        re.compile(
            r"(?:(?:^|[\s\"';&|])(?:-|/)(?:ep|exec|executionpolicy)|set-executionpolicy)"
            r"(?:[\s:=]+(?:(?:-scope|-s)\s+\S+\s+)?['\"]?bypass\b)",
            re.IGNORECASE,
        ),
        False,
    ),
    (
        "hidden",
        re.compile(
            r"(?:^|[\s\"';&|])(?:-|/)(?:w|win|window|windowstyle)[\s:=]+['\"]?hidden\b",
            re.IGNORECASE,
        ),
        False,
    ),
    ("downloadstring", re.compile(r"\bdownloadstring\b", re.IGNORECASE), True),
    ("downloadfile", re.compile(r"\bdownloadfile\b", re.IGNORECASE), False),
    (
        "iex",
        re.compile(r"(?:^|[\s\"'(|;&`])iex(?=$|[\s(\"'`;|&])", re.IGNORECASE),
        True,
    ),
    ("invoke-expression", re.compile(r"\binvoke-expression\b", re.IGNORECASE), True),
    ("invoke-webrequest", re.compile(r"\binvoke-webrequest\b", re.IGNORECASE), False),
    (
        "certutil -urlcache",
        re.compile(r"\bcertutil(?:\.exe)?\s+(?:.*\s)?[-/]urlcache\b", re.IGNORECASE),
        True,
    ),
    ("rundll32", re.compile(r"\brundll32(?:\.exe)?\b", re.IGNORECASE), False),
    ("regsvr32", re.compile(r"\bregsvr32(?:\.exe)?\b", re.IGNORECASE), False),
    ("mshta", re.compile(r"\bmshta(?:\.exe)?\b", re.IGNORECASE), True),
    ("bitsadmin", re.compile(r"\bbitsadmin(?:\.exe)?\b", re.IGNORECASE), False),
    ("frombase64string", re.compile(r"\bfrombase64string\b", re.IGNORECASE), True),
    ("wscript", re.compile(r"\bwscript(?:\.exe)?\b", re.IGNORECASE), False),
    ("cscript", re.compile(r"\bcscript(?:\.exe)?\b", re.IGNORECASE), False),
    ("vssadmin", re.compile(r"\bvssadmin(?:\.exe)?\b", re.IGNORECASE), True),
    ("wevtutil", re.compile(r"\bwevtutil(?:\.exe)?\b", re.IGNORECASE), True),
    ("fltmc", re.compile(r"\bfltmc(?:\.exe)?\b", re.IGNORECASE), True),
    ("sysmondrv", re.compile(r"\bsysmondrv\b", re.IGNORECASE), True),
    ("sc stop", re.compile(r"\bsc(?:\.exe)?\s+stop\b", re.IGNORECASE), False),
    ("sc delete", re.compile(r"\bsc(?:\.exe)?\s+delete\b", re.IGNORECASE), False),
    ("sc config", re.compile(r"\bsc(?:\.exe)?\s+config\b", re.IGNORECASE), False),
    ("net stop", re.compile(r"\bnet1?(?:\.exe)?\s+stop\b", re.IGNORECASE), False),
    ("clear-winevent", re.compile(r"\bclear-winevent\b", re.IGNORECASE), True),
    ("clear-eventlog", re.compile(r"\bclear-eventlog\b", re.IGNORECASE), True),
    ("auditpol", re.compile(r"\bauditpol(?:\.exe)?\b", re.IGNORECASE), True),
    ("evtclearlog", re.compile(r"\bevtclearlog\b", re.IGNORECASE), True),
    ("mimikatz", re.compile(r"\bmimikatz\b", re.IGNORECASE), True),
    ("sekurlsa", re.compile(r"\bsekurlsa\b", re.IGNORECASE), True),
    ("net user", re.compile(r"\bnet1?(?:\.exe)?\s+user(?:\s|$)", re.IGNORECASE), False),
    (
        "net localgroup administrators",
        re.compile(r"\bnet1?(?:\.exe)?\s+localgroup\s+administrators\b", re.IGNORECASE),
        False,
    ),
)

_NEVER_ALLOWLIST_RE = re.compile(
    r"\b(?:mimikatz|sekurlsa|clear-winevent|clear-eventlog|evtclearlog"
    r"|wevtutil(?:\.exe)?|vssadmin(?:\.exe)?|auditpol(?:\.exe)?|sysmondrv|fltmc(?:\.exe)?)\b",
    re.IGNORECASE,
)


def _split_command_tokens(command_line: str) -> list[str]:
    tokens: list[str] = []
    for match in _ARG_TOKEN_RE.finditer(command_line or ""):
        token = match.group(1) if match.group(1) is not None else (
            match.group(2) if match.group(2) is not None else match.group(3)
        )
        if token is not None:
            tokens.append(token)
    return tokens


def _normalize_win_path(raw: str) -> str:
    cleaned = raw.strip().strip("\"'").replace("/", "\\").lower()
    if cleaned.startswith("\\??\\"):
        cleaned = cleaned[4:]
    for env_prefix in ("%systemroot%\\", "%windir%\\"):
        if cleaned.startswith(env_prefix):
            cleaned = "c:\\windows\\" + cleaned[len(env_prefix):]
    return cleaned


def _is_system32_dll_path(path_str: str) -> bool:
    norm = _normalize_win_path(path_str)
    if ".." in norm:
        return False
    return norm.startswith(_SYSTEM32_DIR_PREFIXES)


def _is_benign_system_rundll32(command_line: str, image: str = "") -> bool:
    """
    正規の Windows System32/SysWOW64 配下の rundll32.exe が安全な OS 標準 DLL/CPL を
    呼び出している場合のみ True を返します。
    """
    if not command_line:
        return False
    if _ABUSED_RUNDLL32_RE.search(command_line) or _UNC_PATH_RE.search(command_line):
        return False

    tokens = _split_command_tokens(command_line)
    if not tokens:
        return False

    exe_norm = _normalize_win_path(tokens[0])
    img_norm = _normalize_win_path(image)
    if img_norm and img_norm not in _SYSTEM_RUNDLL32_EXE_PREFIXES:
        return False
    if exe_norm not in _SYSTEM_RUNDLL32_EXE_PREFIXES:
        if not (exe_norm in ("rundll32", "rundll32.exe") and img_norm in _SYSTEM_RUNDLL32_EXE_PREFIXES):
            return False

    # rundll32.exe 直後のオプション (/d 等) をスキップし、DLL/CPL ターゲットを取得
    target_token = ""
    for tok in tokens[1:]:
        if tok.startswith(("/", "-")) and "," not in tok and "\\" not in tok and "." not in tok:
            continue
        target_token = tok
        break

    if not target_token:
        return False

    target_dll_part = target_token.split(",", 1)[0]
    norm_dll = _normalize_win_path(target_dll_part)
    if not norm_dll:
        return False

    # 全引数中に System32/SysWOW64 以外のファイルシステムパスがあれば安全とみなさない
    for tok in tokens[1:]:
        for part in tok.split(","):
            raw_part = part.strip().strip("\"'")
            if re.fullmatch(r"[-/][a-zA-Z0-9_-]+", raw_part):
                continue
            norm_tok = _normalize_win_path(raw_part)
            if ("\\" in norm_tok or ":" in norm_tok) and not _is_system32_dll_path(norm_tok):
                # GUID 引数 ({...}) や数値パラメータはパスではないため除外
                if not (norm_tok.startswith("{") and norm_tok.endswith("}")):
                    return False

    if "\\" in norm_dll or ":" in norm_dll:
        return _is_system32_dll_path(norm_dll)
    return norm_dll in _TRUSTED_BARE_RUNDLL32_TARGETS


def _is_benign_system_regsvr32(command_line: str, image: str = "") -> bool:
    """
    正規 System32/SysWOW64 の regsvr32.exe が /i:URL や scrobj.dll を伴わず
    System32/SysWOW64 配下の DLL/OCX のみを登録する場合に True を返します。
    """
    if not command_line:
        return False
    lower = command_line.lower()
    if any(tok in lower for tok in ("http://", "https://", "ftp://", "scrobj.dll", "/i:", "-i:")):
        return False
    if _UNC_PATH_RE.search(command_line):
        return False

    tokens = _split_command_tokens(command_line)
    if not tokens:
        return False

    exe_norm = _normalize_win_path(tokens[0])
    img_norm = _normalize_win_path(image)
    if img_norm and img_norm not in _SYSTEM_REGSVR32_EXE_PREFIXES:
        return False
    if exe_norm not in _SYSTEM_REGSVR32_EXE_PREFIXES:
        if not (exe_norm in ("regsvr32", "regsvr32.exe") and img_norm in _SYSTEM_REGSVR32_EXE_PREFIXES):
            return False

    dll_targets = [
        _normalize_win_path(t)
        for t in tokens[1:]
        if not t.startswith(("/", "-"))
    ]
    if not dll_targets:
        return False
    return all(_is_system32_dll_path(target) for target in dll_targets)


def find_suspicious_keywords(command_line: str, image: str = "") -> list[str]:
    """コマンドライン文字列から精密ルールに合致した不審キーワード名リストを返します。"""
    if not command_line:
        return []

    matched: list[str] = []
    for label, pattern, _ in KEYWORD_RULES:
        if not pattern.search(command_line):
            continue
        if label == "rundll32" and _is_benign_system_rundll32(command_line, image=image):
            continue
        if label == "regsvr32" and _is_benign_system_regsvr32(command_line, image=image):
            continue
        matched.append(label)
    return matched


def has_high_risk_keyword(
    command_line: str,
    reasons: list[str] | tuple[str, ...] = (),
    image: str = "",
) -> bool:
    """オフライン即時 [CRITICAL] 判定対象となる高危険キーワードが成立しているかを返します。"""
    reasons_lower = " ".join(reasons).lower()
    if "[critical候補]" in reasons_lower or "sysmon のアンインストール" in reasons_lower:
        return True

    matched_set = set(find_suspicious_keywords(command_line or "", image=image))
    for label, _, is_high_risk in KEYWORD_RULES:
        if not is_high_risk:
            continue
        if label in matched_set:
            return True
        if f"'{label}'" in reasons_lower:
            return True
    return False


def has_never_allowlist_keyword(text: str) -> bool:
    """許可リスト適用不可の絶対警戒キーワードが単語境界一致で含まれるかを返します。"""
    if not text:
        return False
    return bool(_NEVER_ALLOWLIST_RE.search(text))
