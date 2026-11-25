"""
ランタイム設定・原子的JSON保存・単一インスタンスミューテックスモジュール (runtime_settings.py)

機能:
1. `atomic_write_json`: 一意な一時ファイル + `os.replace()` による原子的 JSON 保存
2. `RuntimeSettings`: トレイ等から実行中に変更可能なサービスティア設定 (`flex` / `standard`) の永続管理
3. `SingleInstanceMutex`: Windows 名前付きミューテックス (`CreateMutexW`) による二重起動防止
"""

from __future__ import annotations

import ctypes
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import threading
from typing import Any

import config

logger = logging.getLogger("sysmon_gemini_agent.runtime_settings")

VALID_SERVICE_TIERS: tuple[str, ...] = ("flex", "standard")
_ERROR_ALREADY_EXISTS = 183


def atomic_write_json(path: Path, data: Any, indent: int = 2) -> None:
    """一意な一時ファイルへ書き出した後 `os.replace()` で原子的に保存します。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    tmp_path = path.with_name(tmp_name)
    serialized = json.dumps(data, indent=indent, ensure_ascii=False)
    try:
        with open(tmp_path, mode="w", encoding="utf-8") as fp:
            fp.write(serialized + "\n")
            fp.flush()
            try:
                os.fsync(fp.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise


def normalize_service_tier(value: str | None, fallback: str = "flex") -> str:
    """サービスティア指定文字列を `'flex'` または `'standard'` に正規化します。"""
    cleaned = (value or "").strip().lower()
    if cleaned in VALID_SERVICE_TIERS:
        return cleaned
    fb = (fallback or "flex").strip().lower()
    return fb if fb in VALID_SERVICE_TIERS else "flex"


class RuntimeSettings:
    """
    実行中にトレイメニュー等から変更可能な設定（Flex / 通常ティア切替など）を
    `runtime_settings.json` でスレッドセーフに永続管理します。
    """

    def __init__(
        self,
        settings_path: Path = config.RUNTIME_SETTINGS_FILE,
        default_tier: str = config.GEMINI_SERVICE_TIER,
        override_tier: str | None = None,
    ) -> None:
        self.settings_path: Path = settings_path
        self._lock = threading.Lock()
        initial_tier = normalize_service_tier(default_tier, fallback="flex")

        loaded = self._load_file_locked()
        if "service_tier_mode" in loaded:
            initial_tier = normalize_service_tier(
                str(loaded.get("service_tier_mode") or ""),
                fallback=initial_tier,
            )

        self._service_tier_mode: str = (
            normalize_service_tier(override_tier, fallback=initial_tier)
            if override_tier
            else initial_tier
        )

    def _load_file_locked(self) -> dict[str, Any]:
        if not self.settings_path.exists():
            return {}
        try:
            raw = self.settings_path.read_text(encoding="utf-8").strip()
            parsed = json.loads(raw) if raw else {}
            return parsed if isinstance(parsed, dict) else {}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("runtime_settings.json の読み込みに失敗しました: %s", exc)
            return {}

    def get_service_tier_mode(self) -> str:
        """現在有効なデフォルト・サービスティア (`'flex'` または `'standard'`) を返します。"""
        with self._lock:
            return self._service_tier_mode

    def set_service_tier_mode(self, mode: str, persist: bool = True) -> str:
        """
        サービスティア設定を変更します。`persist=True` の場合は `runtime_settings.json` に保存し、
        再起動後も設定を維持します。
        """
        normalized = normalize_service_tier(mode, fallback="flex")
        with self._lock:
            self._service_tier_mode = normalized
            if persist:
                payload = self._load_file_locked()
                payload["service_tier_mode"] = normalized
                payload["updated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
                try:
                    atomic_write_json(self.settings_path, payload)
                except OSError as exc:
                    logger.warning("runtime_settings.json の保存に失敗しました: %s", exc)
        return normalized


class SingleInstanceMutex:
    """
    Windows 名前付きミューテックス (`CreateMutexW`) を用いて、
    常駐エージェントの多重起動（`checkpoint.json` 競合や API 二重課金）を防止します。
    """

    def __init__(self, mutex_name: str = config.SINGLE_INSTANCE_MUTEX_NAME) -> None:
        self.mutex_name: str = mutex_name
        self._handle: int | None = None

    def acquire(self) -> bool:
        """
        ミューテックスを取得します。新規取得できれば True、既に別インスタンスが取得済みなら False。
        Windows 以外の環境では常に True を返します。
        """
        if os.name != "nt":
            return True
        if self._handle is not None:
            return True

        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.CreateMutexW(None, False, self.mutex_name)
            last_error = ctypes.get_last_error()
            if not handle:
                logger.warning("単一インスタンス用ミューテックスの作成に失敗しました (err=%d)。", last_error)
                return True
            if last_error == _ERROR_ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                return False
            self._handle = int(handle)
            return True
        except Exception as exc:
            logger.warning("単一インスタンスミューテックス確認中に例外が発生しました: %s", exc)
            return True

    def release(self) -> None:
        """取得済みのミューテックスハンドルを解放します。"""
        if os.name != "nt" or self._handle is None:
            self._handle = None
            return
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle(self._handle)
        except Exception:
            pass
        finally:
            self._handle = None

    def __enter__(self) -> SingleInstanceMutex:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()
