"""
ホワイトリスト（誤検知除外ルール）管理モジュール (allowlist.py)

ユーザーが信頼済みと判断した自作プログラムや正規スクリプトを
`allowlist.json` で管理し、変更時はエージェント再起動なしで自動リロードします。

安全設計上の制約:
- Sysmon 改ざん・ログ消去 (ID 4/16/255/1102/104/4719/7036/7040)
- スレッド注入 (ID 8) および LSASS メモリアクセス (ID 10)
- 危険キーワード（mimikatz / sekurlsa / wevtutil / clear-eventlog 等）
を含むイベントは、ホワイトリスト登録対象であっても絶対にスキップしません。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
import threading
from typing import TYPE_CHECKING, Any

import config
import keyword_matcher
from runtime_settings import atomic_write_json

if TYPE_CHECKING:
    from event_reader import NormalizedEvent

logger = logging.getLogger("sysmon_gemini_agent.allowlist")

_LOCK = threading.Lock()
_CACHE_SIGNATURE: tuple[str, int, int] | None = None
_CACHE_DATA: dict[str, list[str]] = {}

DEFAULT_ALLOWLIST_DATA: dict[str, list[str]] = {
    "trusted_image_prefixes": [],
    "trusted_images": [],
    "trusted_command_line_contains": [],
    "trusted_dns_domains": [],
}

# 汎用インタプリタ/LOLBin名（これら単体を無条件許可する誤設定を防ぐ）
GENERIC_INTERPRETER_BASENAMES: frozenset[str] = frozenset(
    {
        "python.exe",
        "pythonw.exe",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
    }
)

# ホワイトリスト適用対象外とする高危険キーワード（小文字）
_NEVER_ALLOWLIST_KEYWORDS: tuple[str, ...] = (
    "mimikatz",
    "sekurlsa",
    "clear-winevent",
    "clear-eventlog",
    "evtclearlog",
    "wevtutil",
    "vssadmin",
    "auditpol",
    "sysmondrv",
    "fltmc",
)

_SCRIPT_PATH_RE = re.compile(
    r'["\']?([a-zA-Z]:\\[^"\'\r\n<>|?*]+?\.(?:py|pyw|ps1|bat|cmd|js|mjs|ts|vbs))["\']?',
    re.IGNORECASE,
)

# コマンド連結記号・改行・バッククォート（便乗実行防止のため常に遮断）
_SHELL_CHAINING_RE = re.compile(r"(?:&&|\|\||[;&|`\r\n])")

# インラインコード実行・エンコードコマンド等のフラグ指定
_INLINE_EXEC_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-|/)(?:c|cmd|command|ec|enc|encodedcommand)(?=$|\s)",
    re.IGNORECASE,
)

# Windows が .cmd / .bat を起動する際の標準ラッパー形式: cmd.exe [/d] /c "<batch_path> ..."
_CMD_BATCH_WRAPPER_RE = re.compile(
    r'^\s*(?:"[^"]*\bcmd(?:\.exe)?"|\S*\bcmd(?:\.exe)?)\s+'
    r'(?:(?:/[dsq]|/[a-z]:(?:on|off))\s+)*'
    r'/c\s+(?P<body>.+)$',
    re.IGNORECASE,
)
_LEADING_BATCH_PATH_RE = re.compile(
    r'^\s*"*([a-zA-Z]:\\[^"\'\r\n<>|?*]+?\.(?:cmd|bat))"?(?=$|\s|")',
    re.IGNORECASE,
)

# 後方互換性・参照用の複合パターン
_CHAINING_OR_INLINE_RE = re.compile(
    r"(?:&&|\|\||[;&|`\r\n]|(?:^|\s)(?:-|/)(?:c|cmd|command|ec|enc|encodedcommand)(?=$|\s))",
    re.IGNORECASE,
)


def _extract_safe_cmd_wrapped_batch(img_base: str, cmd_raw: str) -> str | None:
    """
    `cmd.exe /c "<trusted>.cmd"` のような正規バッチラッパー起動である場合のみ、
    先頭で呼び出される `.cmd` / `.bat` の正規化小文字フルパスを返します。
    コマンド連結・ネストしたインラインフラグ・ディレクトリトラバーサルを含む場合は `None` を返します。
    """
    if img_base != "cmd.exe" or not cmd_raw:
        return None
    if _SHELL_CHAINING_RE.search(cmd_raw):
        return None
    match = _CMD_BATCH_WRAPPER_RE.match(cmd_raw)
    if not match:
        return None
    body = match.group("body").strip()
    if not body or _SHELL_CHAINING_RE.search(body) or _INLINE_EXEC_FLAG_RE.search(body):
        return None
    lead = _LEADING_BATCH_PATH_RE.match(body)
    if not lead:
        return None
    batch_path = lead.group(1).strip().replace("/", "\\").lower()
    if ".." in batch_path:
        return None
    return batch_path


def _normalize_str_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    result: list[str] = []
    for item in raw:
        val = str(item).strip()
        if val:
            result.append(val)
    return list(dict.fromkeys(result))


def ensure_allowlist_file(allowlist_path: Path | None = None) -> Path:
    """`allowlist.json` が存在しない場合、空の初期テンプレートを作成してパスを返します。"""
    target_path = allowlist_path or config.ALLOWLIST_FILE
    if not target_path.exists():
        atomic_write_json(target_path, DEFAULT_ALLOWLIST_DATA)
    return target_path


def load_allowlist(allowlist_path: Path | None = None) -> dict[str, list[str]]:
    """
    `allowlist.json` を読み込みます。ファイル更新時のみ再読み込みして軽量に保ちます。
    """
    global _CACHE_SIGNATURE, _CACHE_DATA
    target_path = allowlist_path or config.ALLOWLIST_FILE
    with _LOCK:
        if not target_path.exists():
            _CACHE_SIGNATURE = None
            _CACHE_DATA = {k: [] for k in DEFAULT_ALLOWLIST_DATA}
            return {k: list(v) for k in _CACHE_DATA for v in [_CACHE_DATA[k]]}

        try:
            stat = target_path.stat()
            sig = (str(target_path), stat.st_mtime_ns, stat.st_size)
            if _CACHE_SIGNATURE == sig and _CACHE_DATA:
                return {k: list(v) for k, v in _CACHE_DATA.items()}

            raw_text = target_path.read_text(encoding="utf-8").strip()
            parsed = json.loads(raw_text) if raw_text else {}
            if not isinstance(parsed, dict):
                parsed = {}

            normalized = {
                key: _normalize_str_list(parsed.get(key))
                for key in DEFAULT_ALLOWLIST_DATA
            }
            _CACHE_SIGNATURE = sig
            _CACHE_DATA = normalized
            return {k: list(v) for k, v in normalized.items()}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("allowlist.json の読み込みに失敗しました: %s", exc)
            return {k: [] for k in DEFAULT_ALLOWLIST_DATA}


def is_high_risk_protected_event(event: NormalizedEvent) -> bool:
    """改ざん検知・注入・LSASSアクセス等の絶対警戒イベントかどうかを返します。"""
    if event.channel == config.SYSMON_CHANNEL and event.event_id in (4, 8, 10, 16, 255):
        return True
    if event.event_id in (104, 1102, 4719):
        return True
    if event.channel == config.SYSTEM_CHANNEL and event.event_id in (7036, 7040):
        return True

    combined_lower = " ".join(
        [
            event.command_line or "",
            event.parent_command_line or "",
            *event.screening_reasons,
        ]
    ).lower()
    if "[critical候補]" in combined_lower:
        return True
    if keyword_matcher.has_never_allowlist_keyword(combined_lower):
        return True
    return False


def _is_protected_against_allowlist(event: NormalizedEvent) -> bool:
    """後方互換エイリアス: `is_high_risk_protected_event` を呼び出します。"""
    return is_high_risk_protected_event(event)


def is_event_allowlisted(
    event: NormalizedEvent,
    allowlist_path: Path | None = None,
) -> tuple[bool, str]:
    """
    イベントが `allowlist.json` の許可ルールに合致するかを判定します。
    安全上の重要イベントは絶対にスキップしません。
    """
    if _is_protected_against_allowlist(event):
        return (False, "")

    rules = load_allowlist(allowlist_path)
    img_norm = (event.image or "").strip().replace("/", "\\").lower()
    img_base = img_norm.rsplit("\\", 1)[-1]
    is_generic_interp = img_base in GENERIC_INTERPRETER_BASENAMES
    cmd_raw = (event.command_line or "").strip()
    cmd_lower = cmd_raw.lower()
    cmd_scripts = [
        m.group(1).strip().replace("/", "\\").lower()
        for m in _SCRIPT_PATH_RE.finditer(cmd_raw)
    ]

    has_shell_chaining = bool(_SHELL_CHAINING_RE.search(cmd_raw))
    has_inline_flag = bool(_INLINE_EXEC_FLAG_RE.search(cmd_raw))
    safe_wrapped_batch = _extract_safe_cmd_wrapped_batch(img_base, cmd_raw)

    for trusted_img in rules["trusted_images"]:
        if img_norm and img_norm == trusted_img.replace("/", "\\").lower():
            return (True, f"trusted_images 一致: {trusted_img}")

    for prefix in rules["trusted_image_prefixes"]:
        p_norm = prefix.replace("/", "\\").lower()
        if not p_norm:
            continue
        if img_norm and img_norm.startswith(p_norm):
            return (True, f"trusted_image_prefixes 一致: {prefix}")
        if (
            is_generic_interp
            and bool(cmd_scripts)
            and not has_shell_chaining
            and (
                not has_inline_flag
                or (safe_wrapped_batch is not None and safe_wrapped_batch.startswith(p_norm))
            )
            and all(sp.startswith(p_norm) and ".." not in sp for sp in cmd_scripts)
        ):
            return (True, f"trusted_image_prefixes (スクリプト) 一致: {prefix}")

    for pattern in rules["trusted_command_line_contains"]:
        pat_low = pattern.lower()
        if not pat_low or pat_low not in cmd_lower:
            continue
        # 連結記号・改行・バッククォートを含む場合は常に拒否（パターン自体に含む場合を除く）
        if has_shell_chaining and not _SHELL_CHAINING_RE.search(pattern):
            continue
        # インラインフラグ (/c, -c, -enc 等) がある場合は正規 cmd.exe /c <trusted>.cmd ラッパーのみ許可
        if has_inline_flag and not _INLINE_EXEC_FLAG_RE.search(pattern):
            pat_norm = pat_low.replace("/", "\\")
            if safe_wrapped_batch is None or safe_wrapped_batch != pat_norm:
                continue
        return (True, f"trusted_command_line_contains 一致: {pattern}")

    if event.event_id == 22:
        qname = (event.event_details.get("query_name") or "").strip().lower().rstrip(".")
        for dom in rules["trusted_dns_domains"]:
            d_low = dom.lower().lstrip("*.")
            if qname and (qname == d_low or qname.endswith("." + d_low)):
                return (True, f"trusted_dns_domains 一致: {dom}")

    return (False, "")


def extract_rule_candidate(event: NormalizedEvent) -> tuple[bool, str, str, str]:
    """
    イベントから安全に追加できるホワイトリストルール候補を抽出します。
    戻り値: (成功可否, JSONセクションキー, 登録値, ユーザー向け説明)
    """
    if _is_protected_against_allowlist(event):
        return (
            False,
            "",
            "",
            "改ざん検知・スレッド注入・LSASSアクセス等の高危険イベントはホワイトリスト登録対象外です。",
        )

    img = (event.image or "").strip()
    img_base = img.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    cmd = (event.command_line or "").strip()

    # 汎用インタプリタの場合は実行スクリプトパスをコマンドラインから抽出してピンポイント許可する
    if img_base in GENERIC_INTERPRETER_BASENAMES or not img:
        match = _SCRIPT_PATH_RE.search(cmd)
        if match:
            script_path = match.group(1).strip()
            return (
                True,
                "trusted_command_line_contains",
                script_path,
                f"スクリプトパス '{script_path}' をコマンドライン許可ルールとして登録します。",
            )
        return (
            False,
            "",
            "",
            f"汎用インタプリタ ({img_base or '不明'}) の実行スクリプトパスがコマンドラインから取得できないため、"
            "安全性維持のため自動登録できません。allowlist.json に手動でスクリプトパスやフォルダを追記してください。",
        )

    return (
        True,
        "trusted_images",
        img,
        f"実行ファイル '{img}' を許可リストに登録します。",
    )


_SAFE_RULE_MIN_LEN: int = 4

# 許可フォルダ登録時に過度に広範なルートパスを誤登録するのを防ぐ一覧（正規化小文字・末尾\なし）
_OVERBROAD_PREFIXES: frozenset[str] = frozenset(
    {
        "c:",
        "c:\\",
        "c:\\windows",
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\windows\\temp",
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\programdata",
        "c:\\users",
        "c:\\users\\public",
        "\\appdata\\roaming\\",
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
        "\\programdata\\",
    }
)


def validate_rule_entry(section_key: str, value: str) -> tuple[bool, str]:
    """
    ホワイトリストのセクションと登録値が安全ポリシーを満たしているか検証します。
    汎用インタプリタ単体、広範すぎるディレクトリ、絶対警戒キーワードを拒否します。
    """
    if section_key not in DEFAULT_ALLOWLIST_DATA:
        return (False, f"不正なホワイトリストセクションです: {section_key}")

    cleaned = (value or "").strip()
    if len(cleaned) < _SAFE_RULE_MIN_LEN:
        return (False, "登録値が短すぎるため安全上許可できません。")

    if keyword_matcher.has_never_allowlist_keyword(cleaned):
        return (False, "改ざん・攻撃ツール等の絶対警戒キーワードを含むため登録できません。")

    lower = cleaned.replace("/", "\\").lower()
    norm_no_slash = lower.rstrip("\\")
    base_name = norm_no_slash.rsplit("\\", 1)[-1]

    if section_key == "trusted_images":
        if base_name in GENERIC_INTERPRETER_BASENAMES:
            return (
                False,
                f"汎用インタプリタ/LOLBin ({base_name}) 単体は安全維持のため登録できません。",
            )
    elif section_key == "trusted_image_prefixes":
        if lower in _OVERBROAD_PREFIXES or norm_no_slash in _OVERBROAD_PREFIXES:
            return (
                False,
                f"対象範囲が広すぎるディレクトリ ({cleaned}) は登録できません。",
            )
        if re.fullmatch(r"[a-z]:", norm_no_slash) or re.fullmatch(
            r"[a-z]:\\users\\[^\\]+(?:\\appdata(?:\\(?:local|roaming)(?:\\temp)?)?)?",
            norm_no_slash,
        ):
            return (
                False,
                f"ユーザー/AppData ルート直下のような広範パス ({cleaned}) は登録できません。",
            )
    elif section_key == "trusted_command_line_contains":
        if base_name in GENERIC_INTERPRETER_BASENAMES and "\\" not in lower:
            return (
                False,
                f"汎用コマンド名 ({base_name}) 単体は登録できません。",
            )

    return (True, "")


def add_rule_entry(
    section_key: str,
    value: str,
    allowlist_path: Path | None = None,
) -> tuple[bool, str]:
    """
    セクションと値を直接指定し、安全検証のうえで `allowlist.json` へ追記保存します。
    戻り値: (成功フラグ, メッセージ)
    """
    global _CACHE_SIGNATURE, _CACHE_DATA
    cleaned = (value or "").strip()
    ok, err_msg = validate_rule_entry(section_key, cleaned)
    if not ok:
        return (False, err_msg)

    target_path = allowlist_path or config.ALLOWLIST_FILE
    with _LOCK:
        ensure_allowlist_file(target_path)
        try:
            raw_text = target_path.read_text(encoding="utf-8").strip()
            data = json.loads(raw_text) if raw_text else {}
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError, json.JSONDecodeError):
            data = {}

        normalized = {
            k: _normalize_str_list(data.get(k))
            for k in DEFAULT_ALLOWLIST_DATA
        }
        existing_lower = {v.lower() for v in normalized[section_key]}
        if cleaned.lower() in existing_lower:
            return (True, f"既に許可リストに登録済みです: {cleaned}")

        normalized[section_key].append(cleaned)
        atomic_write_json(target_path, normalized)

        _CACHE_SIGNATURE = None
        _CACHE_DATA = normalized
        logger.info("許可リスト (%s) にルールを追加しました [%s]: %s", target_path.name, section_key, cleaned)
        return (True, f"許可リストに追加しました（次回巡回から自動適用）:\n[{section_key}] {cleaned}")


def add_rule_for_event(
    event: NormalizedEvent,
    allowlist_path: Path | None = None,
) -> tuple[bool, str, str]:
    """
    イベントに対応する安全な許可ルールを `allowlist.json` へ追記保存します。
    戻り値: (登録/既存確認成功フラグ, 登録した値, メッセージ)
    """
    ok, section_key, value, desc = extract_rule_candidate(event)
    if not ok:
        return (False, "", desc)

    saved, msg = add_rule_entry(section_key, value, allowlist_path=allowlist_path)
    return (saved, value if saved else "", msg)
