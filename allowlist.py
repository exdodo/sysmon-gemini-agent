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
        serialized = json.dumps(DEFAULT_ALLOWLIST_DATA, indent=2, ensure_ascii=False)
        with open(target_path, mode="w", encoding="utf-8") as fp:
            fp.write(serialized + "\n")
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


def _is_protected_against_allowlist(event: NormalizedEvent) -> bool:
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
    if any(kw in combined_lower for kw in _NEVER_ALLOWLIST_KEYWORDS):
        return True
    return False


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
    img_lower = (event.image or "").strip().lower()
    cmd_lower = (event.command_line or "").strip().lower()

    for trusted_img in rules["trusted_images"]:
        if img_lower and img_lower == trusted_img.lower():
            return (True, f"trusted_images 一致: {trusted_img}")

    for prefix in rules["trusted_image_prefixes"]:
        p_low = prefix.lower()
        if p_low and (p_low in img_lower or p_low in cmd_lower):
            return (True, f"trusted_image_prefixes 一致: {prefix}")

    for pattern in rules["trusted_command_line_contains"]:
        pat_low = pattern.lower()
        if pat_low and pat_low in cmd_lower:
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


def add_rule_for_event(
    event: NormalizedEvent,
    allowlist_path: Path | None = None,
) -> tuple[bool, str, str]:
    """
    イベントに対応する安全な許可ルールを `allowlist.json` へ追記保存します。
    戻り値: (登録/既存確認成功フラグ, 登録した値, メッセージ)
    """
    global _CACHE_SIGNATURE, _CACHE_DATA
    target_path = allowlist_path or config.ALLOWLIST_FILE
    ok, section_key, value, desc = extract_rule_candidate(event)
    if not ok:
        return (False, "", desc)

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
        if value.lower() in existing_lower:
            return (True, value, f"既に許可リストに登録済みです: {value}")

        normalized[section_key].append(value)
        serialized = json.dumps(normalized, indent=2, ensure_ascii=False)
        with open(target_path, mode="w", encoding="utf-8") as fp:
            fp.write(serialized + "\n")

        _CACHE_SIGNATURE = None
        _CACHE_DATA = normalized
        logger.info("許可リスト (%s) にルールを追加しました [%s]: %s", target_path.name, section_key, value)
        return (True, value, f"許可リストに追加しました（次回巡回から自動適用）:\n[{section_key}] {value}")
