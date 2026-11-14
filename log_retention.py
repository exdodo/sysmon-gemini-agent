"""
過去アラート・日次レポート保持制限モジュール (log_retention.py)

`alerts/` ディレクトリ配下の `incident_YYYYMMDD.md` について、
保持期間（デフォルト30日）およびディレクトリ合計容量上限（デフォルト100MB）に基づき、
古い日付のレポートファイルのみを安全に整理します。

安全設計上の制約:
- 対象は `alerts/` 直下の `incident_YYYYMMDD.md` 形式のファイルのみに厳密限定します。
- 当日分のレポートファイルおよび `agent_runtime.log*` は削除対象外とします。
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
import logging
from pathlib import Path
import re
from typing import Any

import config

logger = logging.getLogger("sysmon_gemini_agent.log_retention")

_INCIDENT_FILE_RE = re.compile(r"^incident_(\d{8})\.md$")


def _parse_incident_date(filename: str) -> date | None:
    match = _INCIDENT_FILE_RE.match(filename)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%d").date()
    except ValueError:
        return None


def cleanup_old_incident_reports(
    alerts_dir: Path = config.ALERTS_DIR,
    retention_days: int = config.INCIDENT_LOG_RETENTION_DAYS,
    max_total_bytes: int = config.ALERTS_DIR_MAX_BYTES,
    today: date | None = None,
) -> dict[str, Any]:
    """
    `alerts/` 配下の古い `incident_YYYYMMDD.md` を保持日数・容量上限に従って削除します。
    当日分 (`file_date >= today`) は容量超過時でも絶対に削除しません。
    """
    result: dict[str, Any] = {
        "deleted_files": [],
        "freed_bytes": 0,
        "remaining_total_bytes": 0,
    }
    if not alerts_dir.exists() or not alerts_dir.is_dir():
        return result

    today_date = today or datetime.now().astimezone().date()
    incident_files: list[tuple[date, Path, int]] = []
    total_bytes = 0

    try:
        entries = list(alerts_dir.iterdir())
    except OSError as exc:
        logger.warning("alerts ディレクトリの走査に失敗しました: %s", exc)
        return result

    for path in entries:
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total_bytes += size
        file_date = _parse_incident_date(path.name)
        if file_date is not None:
            incident_files.append((file_date, path, size))

    incident_files.sort(key=lambda item: (item[0], item[1].name))
    remaining_incidents: list[tuple[date, Path, int]] = []

    # 1. 保持日数超過チェック
    cutoff_date = (
        today_date - timedelta(days=int(retention_days))
        if retention_days > 0
        else None
    )
    for file_date, path, size in incident_files:
        if cutoff_date is not None and file_date < cutoff_date and file_date < today_date:
            try:
                path.unlink()
                total_bytes = max(0, total_bytes - size)
                result["deleted_files"].append(str(path))
                result["freed_bytes"] += size
                logger.info(
                    "保持期間 (%d日) 超過の過去レポートを削除しました: %s (%d bytes)",
                    retention_days,
                    path.name,
                    size,
                )
            except OSError as exc:
                logger.warning("過去レポート '%s' の削除に失敗しました: %s", path.name, exc)
                remaining_incidents.append((file_date, path, size))
        else:
            remaining_incidents.append((file_date, path, size))

    # 2. alerts/ 合計容量上限チェック (古い日付の過去レポートから順に削除、当日分は保護)
    if max_total_bytes > 0 and total_bytes > max_total_bytes:
        for file_date, path, size in remaining_incidents:
            if total_bytes <= max_total_bytes:
                break
            if file_date >= today_date:
                continue
            try:
                path.unlink()
                total_bytes = max(0, total_bytes - size)
                result["deleted_files"].append(str(path))
                result["freed_bytes"] += size
                logger.info(
                    "alerts/ 合計容量上限 (%d MB) 超過のため古いレポートを削除しました: %s (%d bytes)",
                    max_total_bytes // (1024 * 1024),
                    path.name,
                    size,
                )
            except OSError as exc:
                logger.warning("過去レポート '%s' の削除に失敗しました: %s", path.name, exc)

    result["remaining_total_bytes"] = total_bytes
    return result
