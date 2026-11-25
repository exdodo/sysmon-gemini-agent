"""
機微情報・認証情報マスキングモジュール (sanitizer.py)

Gemini API へ送信するプロンプト/ツール応答および `alerts/incident_*.md` 出力前に、
コマンドライン引数等に誤って含まれた API キー・トークン・パスワード等を
`<REDACTED>` へ自動置換し、外部送信・ログ残存リスクを低減します。
"""

from __future__ import annotations

import re

_REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Google / Gemini API キー (AIza...)
    (
        re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
        "AIza***REDACTED***",
    ),
    # GitHub / Slack / OpenAI 等の汎用シークレットトークンプレフィックス
    (
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{20,}\b"),
        "<REDACTED_GH_TOKEN>",
    ),
    (
        re.compile(r"\bgithub_pat_[0-9A-Za-z_]{20,}\b"),
        "<REDACTED_GH_TOKEN>",
    ),
    (
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "<REDACTED_SLACK_TOKEN>",
    ),
    (
        re.compile(r"\bsk-[A-Za-z0-9\-_]{20,}\b"),
        "<REDACTED_API_TOKEN>",
    ),
    # HTTP Authorization ヘッダー値 (Bearer / Basic)
    (
        re.compile(r"(\b(?:Bearer|Basic)\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
        r"\1<REDACTED>",
    ),
    # CLI フラグ・環境変数代入形式のシークレット (--token=..., password=..., -p ...)
    (
        re.compile(
            r"((?:--?|/)(?:api[-_]?key|apikey|token|secret|client[-_]?secret|password|passwd|"
            r"access[-_]?token|refresh[-_]?token|csrf[-_]?token|auth[-_]?token)"
            r"(?:\s+|=|:))(?:\"[^\"]*\"|'[^']*'|\S+)",
            re.IGNORECASE,
        ),
        r"\1<REDACTED>",
    ),
    # URL クエリパラメータ内の認証値
    (
        re.compile(
            r"([?&](?:api_key|apikey|key|token|secret|password|sig|signature|access_token)=)"
            r"[^&\s\"']+",
            re.IGNORECASE,
        ),
        r"\1<REDACTED>",
    ),
)


def redact_sensitive_text(text: str) -> str:
    """文字列中の API キー・トークン・パスワード等を検出し安全な伏せ字へ置換します。"""
    if not text:
        return ""
    masked = text
    for pattern, replacement in _REDACTION_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked
