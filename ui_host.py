"""
単一スレッド Tkinter UI ホストモジュール (ui_host.py)

複数スレッドから個別に `tk.Tk()` と `mainloop()` を起動すると Tcl/Tk 内部状態の競合により
フリーズやランタイム例外が発生するため、専用の単一デーモンスレッドで非表示のルート
`tk.Tk()` を1つだけ保持し、すべてのダイアログを `tk.Toplevel(root)` として安全に生成します。
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Callable

logger = logging.getLogger("sysmon_gemini_agent.ui_host")

_SHUTDOWN_SENTINEL = object()


class TkinterUIHost:
    """単一スレッド上の Tkinter ルートウィンドウとコマンドキューを管理します。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue: queue.Queue[Any] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._ready_event = threading.Event()
        self._init_error: Exception | None = None

    def _ensure_started_locked(self) -> bool:
        if self._thread is not None and self._thread.is_alive():
            return True

        self._ready_event.clear()
        self._init_error = None
        self._thread = threading.Thread(
            target=self._ui_loop,
            name="TkinterUIHostThread",
            daemon=True,
        )
        self._thread.start()
        self._ready_event.wait(timeout=5.0)
        if self._init_error is not None:
            logger.error("Tkinter UI ホストの初期化に失敗しました: %s", self._init_error)
            return False
        return True

    def _ui_loop(self) -> None:
        try:
            import tkinter as tk

            root = tk.Tk()
            root.withdraw()
        except Exception as exc:
            self._init_error = exc
            self._ready_event.set()
            return

        self._ready_event.set()

        def _drain() -> None:
            should_quit = False
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is _SHUTDOWN_SENTINEL:
                    should_quit = True
                    break
                try:
                    item(root)
                except Exception as exc:
                    logger.error("Tkinter UI コールバック実行中にエラーが発生しました: %s", exc)

            if should_quit:
                try:
                    root.quit()
                    root.destroy()
                except Exception:
                    pass
                return

            try:
                root.after(100, _drain)
            except Exception:
                pass

        try:
            root.after(50, _drain)
            root.mainloop()
        except Exception as exc:
            logger.error("Tkinter UI メインループが異常終了しました: %s", exc)

    def dispatch(self, callback: Callable[[Any], Any]) -> bool:
        """UI スレッドに `callback(root)` の実行をキュー投入します。"""
        with self._lock:
            if not self._ensure_started_locked():
                return False
            self._queue.put(callback)
            return True

    def shutdown(self, timeout: float = 2.0) -> None:
        """UI ホストを安全に終了します。"""
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._thread = None
                return
            self._queue.put(_SHUTDOWN_SENTINEL)

        thread.join(timeout=timeout)
        with self._lock:
            if self._thread is thread and not thread.is_alive():
                self._thread = None


_DEFAULT_HOST = TkinterUIHost()


def dispatch_to_ui(callback: Callable[[Any], Any]) -> bool:
    """単一 Tkinter UI スレッド上で `callback(root)` を実行します。"""
    return _DEFAULT_HOST.dispatch(callback)


def shutdown_ui_host(timeout: float = 2.0) -> None:
    """単一 Tkinter UI ホストを安全に停止します。"""
    _DEFAULT_HOST.shutdown(timeout=timeout)
