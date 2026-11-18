"""
同一パターン [CLEAN] トリアージ結果キャッシュモジュール (triage_cache.py)

一次スクリーニングを通過したものの Gemini API により `[CLEAN]` と判定された
イベントパターンを正規化フィンガープリント（SHA-256）でローカルキャッシュ (`triage_cache.json`) し、
有効期限（デフォルト24時間）内の同一パターンに対する重複 API 問い合わせを抑止します。

安全設計上の制約:
- 改ざん検知・防衛妨害 (Sysmon 4/16/255, Security 1102/4719, System 104/7036/7040)
- スレッド注入 (ID 8) および LSASS メモリアクセス (ID 10)
- 危険キーワード (mimikatz, wevtutil 等) および [CRITICAL候補]
- リモートログオン失敗 (Security 4625)
- `[SUSPICIOUS]` / `[CRITICAL]` 判定結果
は絶対にキャッシュせず、毎回必ず検査を行います。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import re
import threading
import time
from typing import TYPE_CHECKING, Any

import allowlist
import config

if TYPE_CHECKING:
    from event_reader import NormalizedEvent

logger = logging.getLogger("sysmon_gemini_agent.triage_cache")

# 毎回変わる動的セッション引数を正規化して同一プロセス起動を識別するパターン
# (悪性ペイロード自体を潰さないよう、既知のローカルホスト/セッション識別子のみ対象)
_DYNAMIC_ARG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(--csrf_token[=\s]+)[^\s\"']+", re.IGNORECASE), r"\1<token>"),
    (re.compile(r"(--host_bridge_token[=\s]+)[^\s\"']+", re.IGNORECASE), r"\1<token>"),
    (re.compile(r"(https?://127\.0\.0\.1:)\d+", re.IGNORECASE), r"\1<port>"),
    (re.compile(r"(--server_port[=\s]+)\d+", re.IGNORECASE), r"\1<port>"),
    (re.compile(r"(--parent_pid[=\s]+)\d+", re.IGNORECASE), r"\1<pid>"),
)

_WHITESPACE_RE = re.compile(r"\s+")

# キャッシュキーに含めるイベント詳細フィールド (IPローテーションする query_results 等は除外)
_FINGERPRINT_DETAIL_KEYS: tuple[str, ...] = (
    "query_name",
    "target_filename",
    "target_object",
    "details",
    "target_image",
    "start_module",
    "granted_access",
)


def _norm_text(value: str | None) -> str:
    return _WHITESPACE_RE.sub(" ", (value or "").strip()).lower()


def _normalize_command_line(value: str | None) -> str:
    text = _norm_text(value)
    if not text:
        return ""
    for pattern, replacement in _DYNAMIC_ARG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def is_cacheable_event(event: NormalizedEvent) -> bool:
    """
    このイベントが `[CLEAN]` キャッシュの対象として安全に扱えるかを判定します。
    改ざん検知・注入・LSASSアクセス・危険キーワード・ログオン失敗は対象外とします。
    """
    if allowlist.is_high_risk_protected_event(event):
        return False
    if event.event_id == 4625:
        return False
    return True


def compute_event_fingerprint(event: NormalizedEvent) -> str:
    """
    `UtcTime` / `ProcessId` / `ParentProcessId` / `EventRecordID` 等の揮発値を除いた
    イベント本質要素から SHA-256 フィンガープリントを生成します。
    """
    details_payload = {
        k: _norm_text(event.event_details.get(k))
        for k in _FINGERPRINT_DETAIL_KEYS
        if event.event_details.get(k)
    }
    canonical = {
        "channel": _norm_text(event.channel),
        "event_id": int(event.event_id),
        "image": _norm_text(event.image),
        "command_line": _normalize_command_line(event.command_line),
        "parent_image": _norm_text(event.parent_image),
        "parent_command_line": _normalize_command_line(event.parent_command_line),
        "destination_ip": _norm_text(event.destination_ip),
        "destination_port": event.destination_port,
        "user": _norm_text(event.user),
        "screening_reasons": sorted({_norm_text(r) for r in event.screening_reasons if r}),
        "details": details_payload,
    }
    serialized = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def summarize_clean_report(report_text: str, max_chars: int = 160) -> str:
    """キャッシュ保存・ログ表示用に `[CLEAN]` 判定理由の1行サマリを抽出します。"""
    for raw_line in (report_text or "").splitlines():
        line = raw_line.strip()
        if not line or line in ("---", "### Gemini 分析・判定結果"):
            continue
        cleaned = re.sub(r"^[-*・#\s`]+", "", line)
        if not cleaned or cleaned.upper() == "[CLEAN]":
            continue
        if cleaned.startswith("判定レベル"):
            continue
        if cleaned.startswith("**判定理由**") or cleaned.startswith("判定理由"):
            cleaned = re.sub(r"^(?:\*\*)?判定理由(?:\*\*)?\s*[:：]\s*", "", cleaned)
        if cleaned:
            return cleaned[:max_chars]
    return "正規動作と判定済み"


class CleanTriageCache:
    """
    `[CLEAN]` と判定されたイベントパターンの永続キャッシュ管理クラス。
    """

    def __init__(
        self,
        cache_path: Path = config.TRIAGE_CACHE_FILE,
        ttl_seconds: int = config.CLEAN_CACHE_TTL_SECONDS,
        max_entries: int = config.CLEAN_CACHE_MAX_ENTRIES,
    ) -> None:
        self.cache_path: Path = cache_path
        self.ttl_seconds: int = max(int(ttl_seconds), 0)
        self.max_entries: int = max(int(max_entries), 1)
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._pending_hit_writes: int = 0
        self._load()

    def _purge_expired_locked(self, now_ts: float) -> int:
        expired_keys = [
            key
            for key, entry in self._entries.items()
            if float(entry.get("expires_at", 0.0)) <= now_ts
        ]
        for key in expired_keys:
            self._entries.pop(key, None)

        if len(self._entries) > self.max_entries:
            overflow = len(self._entries) - self.max_entries
            ordered = sorted(
                self._entries.items(),
                key=lambda kv: float(kv[1].get("last_hit_at", kv[1].get("cached_at", 0.0))),
            )
            for key, _ in ordered[:overflow]:
                self._entries.pop(key, None)

        return len(expired_keys)

    def _load(self) -> None:
        with self._lock:
            if not self.cache_path.exists():
                self._entries = {}
                return
            try:
                raw_text = self.cache_path.read_text(encoding="utf-8").strip()
                if not raw_text:
                    self._entries = {}
                    return
                parsed = json.loads(raw_text)
                entries = parsed.get("entries", {}) if isinstance(parsed, dict) else {}
                if isinstance(entries, dict):
                    self._entries = {
                        str(k): dict(v)
                        for k, v in entries.items()
                        if isinstance(v, dict)
                    }
                else:
                    self._entries = {}
                self._purge_expired_locked(time.time())
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("トリアージキャッシュ (%s) の読み込みに失敗したため初期化します: %s", self.cache_path.name, exc)
                self._entries = {}

    def _save_locked(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "ttl_seconds": self.ttl_seconds,
            "entries": self._entries,
        }
        serialized = json.dumps(payload, indent=2, ensure_ascii=False)
        tmp_path = self.cache_path.with_suffix(".tmp")
        with open(tmp_path, mode="w", encoding="utf-8") as fp:
            fp.write(serialized + "\n")
        os.replace(tmp_path, self.cache_path)
        self._pending_hit_writes = 0

    def lookup(
        self,
        event: NormalizedEvent,
        now_ts: float | None = None,
    ) -> dict[str, Any] | None:
        """
        有効期限内の `[CLEAN]` キャッシュに一致するエントリがあれば返します。
        一致しない場合や保護対象イベントの場合は `None` を返します。
        """
        if self.ttl_seconds <= 0 or not is_cacheable_event(event):
            return None

        current_ts = time.time() if now_ts is None else now_ts
        key = compute_event_fingerprint(event)

        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None

            if float(entry.get("expires_at", 0.0)) <= current_ts:
                self._entries.pop(key, None)
                return None

            entry["hit_count"] = int(entry.get("hit_count", 0)) + 1
            entry["last_hit_at"] = current_ts
            self._pending_hit_writes += 1
            if self._pending_hit_writes >= 10:
                try:
                    self._save_locked()
                except OSError as exc:
                    logger.debug("キャッシュヒット数の永続化に失敗しました: %s", exc)

            result = dict(entry)
            result["cache_key"] = key
            return result

    def store_clean(
        self,
        event: NormalizedEvent,
        report_text: str,
        now_ts: float | None = None,
    ) -> str | None:
        """
        Gemini API で `[CLEAN]` と確定した安全なイベントパターンをキャッシュへ保存します。
        保存した場合はキャッシュキー（SHA-256）、対象外の場合は `None` を返します。
        """
        if self.ttl_seconds <= 0 or not is_cacheable_event(event):
            return None

        current_ts = time.time() if now_ts is None else now_ts
        key = compute_event_fingerprint(event)
        summary = summarize_clean_report(report_text)

        with self._lock:
            self._purge_expired_locked(current_ts)
            self._entries[key] = {
                "severity": config.SEVERITY_CLEAN,
                "event_id": int(event.event_id),
                "image": event.image,
                "summary": summary,
                "cached_at": current_ts,
                "last_hit_at": current_ts,
                "expires_at": current_ts + self.ttl_seconds,
                "hit_count": 0,
            }
            self._purge_expired_locked(current_ts)
            try:
                self._save_locked()
            except OSError as exc:
                logger.warning("トリアージキャッシュ (%s) の保存に失敗しました: %s", self.cache_path.name, exc)
                return None
        return key
