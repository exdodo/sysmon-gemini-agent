"""
システムトレイ（タスクバー通知領域）常駐モジュール (tray_app.py)

pystray と Pillow (PIL) を使用してタスクバー（システムトレイ）にアイコンを表示し、
バックグラウンドスレッドで Windows イベントログ監視ループを実行します。

ステータスに応じたアイコン色の自動切り替え:
- 緑色 (GREEN)  : 正常監視中 / [CLEAN]
- 黄色 (YELLOW) : [SUSPICIOUS]（要注意イベント検知）
- 赤色 (RED)    : [CRITICAL]（深刻な脅威検知）または重大な実行エラー発生時
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
import ctypes
import logging
import os
import threading
import time
from typing import Any

from agent import GeminiTriageAgent
import allowlist
import config
from daily_reviewer import (
    AllowlistCandidateStore,
    DailyReviewer,
    open_allowlist_review_dialog_async,
)
from event_reader import CheckpointManager, NormalizedEvent, WindowsEventReader
from posture_check import open_posture_check_dialog_async
from process_guard import show_critical_response_dialog, verify_target_process
from triage_cache import compute_event_fingerprint
from ui_host import shutdown_ui_host

logger = logging.getLogger("sysmon_gemini_agent.tray")

try:
    from PIL import Image, ImageDraw
    import pystray

    HAS_TRAY_DEPS = True
except ImportError:
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
    pystray = None  # type: ignore[assignment]
    HAS_TRAY_DEPS = False


# アイコンの状態定義
STATE_NORMAL = "NORMAL"          # 緑: 正常監視中
STATE_SUSPICIOUS = "SUSPICIOUS"  # 黄: 要注意検知
STATE_CRITICAL = "CRITICAL"      # 赤: 深刻な脅威 ([CRITICAL]) または重大なエラー


def create_status_icon_image(state: str = STATE_NORMAL, size: int = 64) -> Any:
    """
    指定された状態（緑・黄・赤）のシステムトレイ用アイコン画像をメモリ上で動的生成します。
    外部画像ファイルへの書き込みや削除を一切行いません。
    """
    if Image is None or ImageDraw is None:
        raise ImportError("Pillow (PIL) がインストールされていません。")

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    if state == STATE_CRITICAL:
        fill_color = (220, 38, 38, 255)      # 鮮やかな赤 (#DC2626)
        border_color = (254, 202, 202, 255)  # 明るい赤枠
    elif state == STATE_SUSPICIOUS:
        fill_color = (217, 119, 6, 255)      # アンバー/黄色 (#D97706)
        border_color = (253, 230, 138, 255)  # 明るい黄枠
    else:
        fill_color = (16, 185, 129, 255)     # エメラルドグリーン (#10B981)
        border_color = (167, 243, 208, 255)  # 明るい緑枠

    # 円形バッジの描画
    margin = 4
    draw.ellipse(
        [margin, margin, size - margin, size - margin],
        fill=fill_color,
        outline=border_color,
        width=3,
    )

    center = size // 2
    if state in (STATE_CRITICAL, STATE_SUSPICIOUS):
        # 警告・深刻時は白い「！」マークを描画
        bar_w = 4
        draw.rectangle(
            [center - bar_w, 16, center + bar_w, 38],
            fill=(255, 255, 255, 255),
        )
        draw.ellipse(
            [center - bar_w, 44, center + bar_w, 44 + bar_w * 2],
            fill=(255, 255, 255, 255),
        )
    else:
        # 正常時は白いチェックマークを描画
        draw.line(
            [(18, 33), (28, 43), (46, 22)],
            fill=(255, 255, 255, 255),
            width=5,
        )

    return img


class FlexTriageQueue:
    """
    [SUSPICIOUS] イベントを 15 秒巡回ループから切り離して非同期処理するための
    フィンガープリント重複統合付き・上限付きワーカキュー。
    """

    def __init__(self, max_size: int = config.FLEX_QUEUE_MAX_SIZE) -> None:
        self.max_size: int = max(int(max_size), 1)
        self._cond = threading.Condition()
        self._queue: deque[tuple[str, NormalizedEvent]] = deque()
        self._pending_fps: set[str] = set()
        self._deduplicated_count: int = 0
        self._overflow_count: int = 0

    def enqueue(self, event: NormalizedEvent) -> tuple[str, int]:
        """
        イベントをキューへ追加します。
        戻り値: (状態: 'enqueued' | 'deduplicated' | 'overflow', 現在の待機件数)
        """
        fp = compute_event_fingerprint(event)
        with self._cond:
            if fp in self._pending_fps:
                self._deduplicated_count += 1
                return ("deduplicated", len(self._queue))
            if len(self._queue) >= self.max_size:
                self._overflow_count += 1
                return ("overflow", len(self._queue))
            self._queue.append((fp, event))
            self._pending_fps.add(fp)
            self._cond.notify_all()
            return ("enqueued", len(self._queue))

    def dequeue(
        self,
        timeout: float = 1.0,
        stop_event: threading.Event | None = None,
    ) -> NormalizedEvent | None:
        """次の処理対象イベントを取り出します（待機キューが空なら timeout まで待機）。"""
        deadline = time.monotonic() + max(timeout, 0.0)
        with self._cond:
            while not self._queue:
                if stop_event is not None and stop_event.is_set():
                    return None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(timeout=remaining)
                if not self._queue and stop_event is not None and stop_event.is_set():
                    return None
                if not self._queue and time.monotonic() >= deadline:
                    return None
            fp, event = self._queue.popleft()
            self._pending_fps.discard(fp)
            return event

    def size(self) -> int:
        with self._cond:
            return len(self._queue)

    def wake(self) -> None:
        with self._cond:
            self._cond.notify_all()

    def get_stats(self) -> dict[str, int]:
        with self._cond:
            return {
                "pending": len(self._queue),
                "deduplicated": self._deduplicated_count,
                "overflow": self._overflow_count,
            }


class SysmonTrayApp:
    """
    タスクバー（通知領域）に常駐し、深刻なアラートやエラー発生時に
    アイコンを赤色へ変更＋デスクトップ通知を行う常駐アプリケーションクラス。
    """

    def __init__(
        self,
        poll_interval: int = config.POLL_INTERVAL_SECONDS,
        offline_only: bool = False,
        service_tier_override: str | None = None,
    ) -> None:
        if not HAS_TRAY_DEPS or pystray is None:
            raise ImportError(
                "タスクバー常駐機能には 'pystray' と 'Pillow' が必要です。"
                "`uv pip install pystray Pillow` または `uv pip install -r requirements.txt` を実行してください。"
            )

        self.poll_interval: int = poll_interval
        self.offline_only: bool = offline_only
        self.service_tier_override: str | None = service_tier_override
        self.current_state: str = STATE_NORMAL
        self.status_message: str = "初期化中..."
        self.last_report_path: str = ""
        self.last_critical_incident: tuple[NormalizedEvent, str, str] | None = None
        self._active_confirmed_alert: bool = False
        self._pending_offline_alerts: list[tuple[NormalizedEvent, str]] = []
        self._critical_dialog_last_shown: dict[int, float] = {}
        self._stop_event = threading.Event()
        self._scan_now_event = threading.Event()
        self._daily_review_now_event = threading.Event()
        self._agent_ready_event = threading.Event()
        self._lock = threading.Lock()

        self.checkpoint_mgr = CheckpointManager(config.CHECKPOINT_FILE)
        self.event_reader = WindowsEventReader(self.checkpoint_mgr)
        self.triage_agent: GeminiTriageAgent | None = None
        self.flex_queue = FlexTriageQueue(max_size=config.FLEX_QUEUE_MAX_SIZE)
        self.candidate_store = AllowlistCandidateStore()
        self.daily_reviewer = DailyReviewer(
            alerts_dir=config.ALERTS_DIR,
            candidate_store=self.candidate_store,
        )

        self.icon = pystray.Icon(
            name="sysmon_gemini_agent",
            icon=create_status_icon_image(STATE_NORMAL),
            title=f"Sysmon Gemini 監視エージェント v{config.APP_VERSION}: 起動中",
            menu=self._build_menu(),
        )

    def _get_tier_menu_status(self) -> str:
        agent = self.triage_agent
        q_size = self.flex_queue.size()
        if agent is None:
            return f"初期化中 | 待機: {q_size}件"
        return f"{agent.get_tier_status_label()} | 待機: {q_size}件"

    def _is_tier_mode(self, mode: str) -> bool:
        agent = self.triage_agent
        if agent is None:
            return (self.service_tier_override or config.GEMINI_SERVICE_TIER) == mode
        return agent.get_configured_service_tier() == mode

    def _is_flex_in_cooldown(self) -> bool:
        agent = self.triage_agent
        return bool(agent is not None and agent.is_flex_in_cooldown())

    def _build_menu(self) -> Any:
        """タスクバーアイコンを右クリックした際のメニューを構築します。"""
        tier_submenu = pystray.Menu(
            pystray.MenuItem(
                "Flex優先 (50%オフ・503/504時30分自動退避)",
                self._on_set_tier_flex,
                checked=lambda item: self._is_tier_mode("flex"),
                enabled=lambda item: not self.offline_only,
            ),
            pystray.MenuItem(
                "通常処理固定 (standard・503/504回避/安定応答)",
                self._on_set_tier_standard,
                checked=lambda item: self._is_tier_mode("standard"),
                enabled=lambda item: not self.offline_only,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Flex 503/504 クールダウンを今すぐ解除",
                self._on_reset_flex_cooldown,
                enabled=lambda item: (not self.offline_only) and self._is_flex_in_cooldown(),
            ),
        )
        return pystray.Menu(
            pystray.MenuItem(
                f"Sysmon Gemini 監視 v{config.APP_VERSION}",
                action=None,
                enabled=False,
            ),
            pystray.MenuItem(
                lambda item: f"状態: {self.status_message}",
                action=None,
                enabled=False,
            ),
            pystray.MenuItem(
                lambda item: f"ティア: {self._get_tier_menu_status()}",
                action=None,
                enabled=False,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("今すぐ巡回を実行", self._on_scan_now),
            pystray.MenuItem("サービスティア切替 (Flex / 通常)", tier_submenu),
            pystray.MenuItem("直近のCRITICAL迎撃パネル (Suspend/Kill) を開く", self._on_open_critical_dialog),
            pystray.MenuItem(
                lambda item: f"ホワイトリスト候補を確認・登録 ({self.candidate_store.pending_count()}件)",
                self._on_review_allowlist_candidates,
            ),
            pystray.MenuItem("前日ログの日次レビューを今すぐ実行", self._on_run_daily_review_now),
            pystray.MenuItem("OS防御設定を確認 (LSA / メモリ整合性 / ASR)", self._on_open_posture_check),
            pystray.MenuItem("許可リスト (allowlist.json) を開く", self._on_open_allowlist),
            pystray.MenuItem("アラート出力フォルダ (alerts) を開く", self._on_open_alerts_dir),
            pystray.MenuItem("実行ログ (agent_runtime.log) を開く", self._on_open_runtime_log),
            pystray.MenuItem("アイコンを正常色（緑）にリセット", self._on_reset_status),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("安全に終了 (Exit)", self._on_exit),
        )

    def _on_set_tier_flex(self, icon: Any, item: Any) -> None:
        if self.triage_agent is None or self.offline_only:
            return
        self.triage_agent.set_configured_service_tier("flex", persist=True)
        self._refresh_tray_menu()
        try:
            self.icon.notify(
                "通常イベントのサービスティアを「Flex優先 (コスト50%オフ)」へ切り替えました。",
                "Sysmon Gemini ティア設定変更",
            )
        except Exception:
            pass

    def _on_set_tier_standard(self, icon: Any, item: Any) -> None:
        if self.triage_agent is None or self.offline_only:
            return
        self.triage_agent.set_configured_service_tier("standard", persist=True)
        self._refresh_tray_menu()
        try:
            self.icon.notify(
                "Flex を停止し、「通常処理固定 (standard)」へ切り替えました（即時適用）。",
                "Sysmon Gemini ティア設定変更",
            )
        except Exception:
            pass

    def _on_reset_flex_cooldown(self, icon: Any, item: Any) -> None:
        if self.triage_agent is None or self.offline_only:
            return
        self.triage_agent.reset_flex_cooldown()
        self._refresh_tray_menu()
        try:
            self.icon.notify(
                "Flex 503/504 回避クールダウンを解除し、Flex ティア利用を再開しました。",
                "Sysmon Gemini ティア設定変更",
            )
        except Exception:
            pass

    def set_status(self, new_state: str, message: str, notify_title: str | None = None) -> None:
        """
        アイコンの色（緑 / 黄 / 赤）とツールチップ文字列を更新します。
        深刻な状態（RED）になった場合は一度赤色を維持し、見逃しを防ぎます。
        """
        with self._lock:
            self.current_state = new_state
            self.status_message = message
            self.icon.icon = create_status_icon_image(new_state)
            self.icon.title = f"Sysmon Gemini v{config.APP_VERSION}: {message}"[:120]
            try:
                self.icon.update_menu()
            except Exception:
                pass

            if notify_title:
                try:
                    self.icon.notify(message, notify_title)
                except Exception as notify_exc:
                    logger.debug("デスクトップ通知の表示に失敗しました: %s", notify_exc)

    def _on_scan_now(self, icon: Any, item: Any) -> None:
        """メニューから即時巡回をトリガーします。"""
        logger.info("ユーザー操作により即時巡回がリクエストされました。")
        self._scan_now_event.set()

    def _on_open_critical_dialog(self, icon: Any, item: Any) -> None:
        """直近の [CRITICAL] イベントに対するワンクリック迎撃パネルを再表示します。"""
        if self.last_critical_incident is None:
            try:
                self.icon.notify(
                    "現在までに [CRITICAL] 判定されたイベントはありません。",
                    "Sysmon Gemini 監視エージェント",
                )
            except Exception:
                pass
            return
        ev, rep_text, rep_file = self.last_critical_incident
        show_critical_response_dialog(ev, rep_text, rep_file)

    def _refresh_tray_menu(self) -> None:
        try:
            self.icon.update_menu()
        except Exception:
            pass

    def _on_review_allowlist_candidates(self, icon: Any, item: Any) -> None:
        """保留中のホワイトリスト候補を 1 件ずつ確認して登録するダイアログを開きます。"""
        opened = open_allowlist_review_dialog_async(
            candidate_store=self.candidate_store,
            on_updated=self._refresh_tray_menu,
        )
        if not opened:
            try:
                self.icon.notify(
                    "ホワイトリスト候補の確認ウィンドウは既に開いています。",
                    "Sysmon Gemini 監視エージェント",
                )
            except Exception:
                pass

    def _on_run_daily_review_now(self, icon: Any, item: Any) -> None:
        """前日ログの Gemini 日次レビューを手動トリガーします。"""
        logger.info("ユーザー操作により前日ログの日次レビューがリクエストされました。")
        self._daily_review_now_event.set()
        self.flex_queue.wake()
        self._scan_now_event.set()

    def _on_open_posture_check(self, icon: Any, item: Any) -> None:
        """LSA 保護・メモリ整合性・ASR 状態を確認する診断ウィンドウを開きます。"""
        opened = open_posture_check_dialog_async()
        if not opened:
            try:
                self.icon.notify(
                    "OS 防御設定診断ウィンドウは既に開いています。",
                    "Sysmon Gemini 監視エージェント",
                )
            except Exception:
                pass

    def _on_open_alerts_dir(self, icon: Any, item: Any) -> None:
        """エクスプローラーで alerts フォルダを開きます（Read-Only表示）。"""
        config.ALERTS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(config.ALERTS_DIR))
        except Exception as exc:
            logger.warning("alerts フォルダを開けませんでした: %s", exc)

    def _on_open_allowlist(self, icon: Any, item: Any) -> None:
        """許可リストファイル (allowlist.json) を生成（未作成時）して既定のエディタで開きます。"""
        try:
            path = allowlist.ensure_allowlist_file()
            os.startfile(str(path))
        except Exception as exc:
            logger.warning("許可リスト (allowlist.json) を開けませんでした: %s", exc)

    def _on_open_runtime_log(self, icon: Any, item: Any) -> None:
        """実行ログファイル (alerts/agent_runtime.log) を既定のエディタで開きます（Read-Only表示）。"""
        config.ALERTS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            if config.AGENT_LOG_FILE.exists():
                os.startfile(str(config.AGENT_LOG_FILE))
            else:
                os.startfile(str(config.ALERTS_DIR))
        except Exception as exc:
            logger.warning("実行ログを開けませんでした: %s", exc)

    def _on_reset_status(self, icon: Any, item: Any) -> None:
        """赤色・黄色になったアイコンを確認後に緑色（正常監視中）へ戻します。"""
        logger.info("ユーザー操作によりアイコン状態を正常（緑）にリセットしました。")
        self._active_confirmed_alert = False
        self._pending_offline_alerts.clear()
        self.set_status(STATE_NORMAL, "正常監視中 (リセット済)")

    def _on_exit(self, icon: Any, item: Any) -> None:
        """バックグラウンド監視スレッドを停止し、チェックポイントを保存して終了します。"""
        logger.info("タスクバーメニューから終了が選択されました。安全に停止処理を行います...")
        self._stop_event.set()
        self._daily_review_now_event.set()
        self._scan_now_event.set()
        self.flex_queue.wake()
        self.checkpoint_mgr.save()
        shutdown_ui_host()
        self.icon.stop()

    @staticmethod
    def _is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def _event_identity(event: NormalizedEvent) -> tuple[str, int, int, str]:
        """オフライン保留イベントの重複管理・照合用キーを返します。"""
        return (event.channel, event.event_id, event.event_record_id, event.utc_time)

    def _record_pending_offline_alert(self, event: NormalizedEvent, severity: str) -> None:
        """オフラインフォールバックで発報されたアラートをオンライン復帰後の再判定キューへ登録します。"""
        ev_id = self._event_identity(event)
        if any(self._event_identity(existing) == ev_id for existing, _ in self._pending_offline_alerts):
            return
        self._pending_offline_alerts.append((event, severity))
        if len(self._pending_offline_alerts) > 50:
            self._pending_offline_alerts.pop(0)

    def _apply_triage_result(
        self,
        candidate: NormalizedEvent,
        result: dict[str, Any],
        from_reconciliation: bool = False,
        previous_offline_severity: str = "",
    ) -> None:
        """トリアージ結果をトレイ状態・アラート原因フラグ・通知・迎撃パネルへ反映します。"""
        severity = result.get("severity", config.SEVERITY_SUSPICIOUS)
        is_offline = bool(result.get("offline_fallback", False))
        offline_tag = "・オフライン判定" if is_offline else ("・再判定確定" if from_reconciliation else "")
        self.last_report_path = result.get("report_file", "") or self.last_report_path

        if is_offline and not self.offline_only:
            if severity in (config.SEVERITY_CRITICAL, config.SEVERITY_SUSPICIOUS):
                self._record_pending_offline_alert(candidate, severity)
        else:
            if severity in (config.SEVERITY_CRITICAL, config.SEVERITY_SUSPICIOUS):
                self._active_confirmed_alert = True
            elif severity == config.SEVERITY_CLEAN and from_reconciliation:
                if (
                    self.last_critical_incident is not None
                    and self._event_identity(self.last_critical_incident[0]) == self._event_identity(candidate)
                ):
                    self.last_critical_incident = None
                return

        if severity == config.SEVERITY_CRITICAL:
            rep_text = result.get("report_text", "")
            self.last_critical_incident = (
                candidate,
                rep_text,
                self.last_report_path,
            )
            proc_check = verify_target_process(
                candidate.process_id,
                candidate.image,
                candidate.utc_time,
                expected_command_line=candidate.command_line if candidate.event_id == 1 else "",
            )
            alive_tag = (
                "稼働中・迎撃可"
                if (proc_check.is_alive and proc_check.is_verified_same_process)
                else "終了済/保護"
            )
            self.set_status(
                STATE_CRITICAL,
                f"[CRITICAL{offline_tag}] 脅威検知 ({alive_tag}: PID={candidate.process_id})",
                notify_title=f"【緊急{offline_tag}】CRITICAL アラート検知",
            )
            already_shown_critical = (
                from_reconciliation and previous_offline_severity == config.SEVERITY_CRITICAL
            )
            pid_key = candidate.process_id if candidate.process_id is not None else -candidate.event_id
            now_mono = time.monotonic()
            last_popup = self._critical_dialog_last_shown.get(pid_key, 0.0)
            in_cooldown = last_popup > 0.0 and (now_mono - last_popup) < 120.0

            if not already_shown_critical and not in_cooldown:
                self._critical_dialog_last_shown[pid_key] = now_mono
                show_critical_response_dialog(
                    candidate,
                    rep_text,
                    self.last_report_path,
                )
            elif in_cooldown:
                logger.info(
                    "同一対象 (PID=%s) の迎撃パネルは120秒以内に表示済みのため自動ポップアップを抑止しました。",
                    candidate.process_id,
                )
        elif severity == config.SEVERITY_SUSPICIOUS and self.current_state != STATE_CRITICAL:
            self.set_status(
                STATE_SUSPICIOUS,
                f"[SUSPICIOUS{offline_tag}] 要注意イベント検知 (EventID={candidate.event_id})",
                notify_title=f"【警告{offline_tag}】SUSPICIOUS イベント検知",
            )

    def _reconcile_pending_offline_alerts(self) -> None:
        """
        オフラインフォールバックで暫定警告していたイベントをオンライン復旧後に Gemini API で再判定し、
        ほかにアラート原因がなければトレイアイコンを元の緑色（正常監視中）へ自動復帰させます。
        """
        if (
            self.triage_agent is None
            or not self._pending_offline_alerts
            or not self.triage_agent.can_attempt_online_now()
        ):
            return

        resolved_any_clean = False
        pending_snapshot = list(self._pending_offline_alerts)
        for ev, prev_sev in pending_snapshot:
            if self._stop_event.is_set():
                break
            re_res = self.triage_agent.try_reinvestigate_online(ev)
            if re_res is None:
                # まだオフライン状態のため残りは次回以降に持ち越し
                break

            ev_id = self._event_identity(ev)
            self._pending_offline_alerts = [
                item for item in self._pending_offline_alerts if self._event_identity(item[0]) != ev_id
            ]
            self._apply_triage_result(
                ev,
                re_res,
                from_reconciliation=True,
                previous_offline_severity=prev_sev,
            )
            if re_res.get("severity") == config.SEVERITY_CLEAN:
                resolved_any_clean = True
                logger.info(
                    "オフライン保留イベント (EventID=%d, RecordID=%d) は Gemini API 再判定で [CLEAN] と確定しました。",
                    ev.event_id,
                    ev.event_record_id,
                )

        if (
            resolved_any_clean
            and not self._pending_offline_alerts
            and not self._active_confirmed_alert
            and self.current_state != STATE_NORMAL
        ):
            logger.info(
                "オフラインフォールバック判定イベントがすべて Gemini API により [CLEAN] と確認されたため、"
                "アイコン状態を正常（緑）へ自動復帰します。"
            )
            self.set_status(
                STATE_NORMAL,
                f"正常監視中 ({self.triage_agent.model_name}・オフライン保留分[CLEAN]復帰)",
                notify_title="Sysmon Gemini 監視エージェント [正常復帰]",
            )

    def _maybe_run_daily_review(self) -> None:
        manual = self._daily_review_now_event.is_set()
        if manual:
            self._daily_review_now_event.clear()

        if self.triage_agent is None or self.offline_only:
            if manual:
                try:
                    self.icon.notify(
                        "オフラインモード中は日次AIレビューを実行できません。",
                        "Sysmon Gemini 日次レビュー",
                    )
                except Exception:
                    pass
            return

        if manual:
            yesterday = (datetime.now().astimezone() - timedelta(days=1)).date()
            review_res = self.daily_reviewer.run_review_for_date(
                target_date=yesterday,
                triage_agent=self.triage_agent,
                force=True,
            )
        else:
            q_size = self.flex_queue.size()
            if q_size >= config.FLEX_DAILY_REVIEW_DEFER_THRESHOLD:
                logger.info(
                    "Flex 待機キュー混雑中のため自動日次レビューを延期します (待機=%d件 >= 閾値%d件)。",
                    q_size,
                    config.FLEX_DAILY_REVIEW_DEFER_THRESHOLD,
                )
                return
            review_res = self.daily_reviewer.run_if_due(self.triage_agent)

        if not review_res:
            return

        self._refresh_tray_menu()
        status = review_res.get("status")
        if status == "ok":
            added = review_res.get("candidate_stats", {}).get("added", 0)
            pending = review_res.get("pending_candidates", 0)
            assessment = review_res.get("overall_assessment", "SAFE")
            if added > 0 or assessment in ("ATTENTION", "INCIDENT_SUSPECTED") or manual:
                try:
                    self.icon.notify(
                        f"対象日 {review_res['target_date']}: 総合={assessment} / "
                        f"新規候補 {added}件 (待機計 {pending}件)",
                        "Sysmon Gemini 日次レビュー完了",
                    )
                except Exception:
                    pass
        elif manual:
            try:
                self.icon.notify(
                    str(review_res.get("message") or "日次レビューを実行できませんでした。"),
                    "Sysmon Gemini 日次レビュー",
                )
            except Exception:
                pass

    def _process_single_candidate(self, candidate: NormalizedEvent) -> None:
        assert self.triage_agent is not None
        try:
            result = self.triage_agent.investigate_event(candidate)
        except Exception as cand_exc:
            logger.error(
                "EventRecordID=%d の調査中に予期しない例外が発生したため、オフラインフォールバックを実行します: %s",
                candidate.event_record_id,
                cand_exc,
            )
            result = self.triage_agent.investigate_offline(
                candidate, error_reason=str(cand_exc)
            )
        self._apply_triage_result(candidate, result, from_reconciliation=False)

    def _monitoring_worker(self) -> None:
        """バックグラウンドで 15 秒ごとのイベントログ定期巡回と CRITICAL 即時処理を行うワーカースレッド。"""
        if not self._is_admin():
            logger.warning("管理者権限なしで起動されました。イベントログの読み取りに失敗する可能性があります。")
            self._active_confirmed_alert = True
            self.set_status(
                STATE_CRITICAL,
                "エラー: 管理者権限で実行してください",
                notify_title="Sysmon Gemini 監視エージェント [権限エラー]",
            )

        try:
            self.triage_agent = GeminiTriageAgent(
                model_name=config.GEMINI_MODEL,
                max_depth=config.MAX_DEPTH,
                alerts_dir=config.ALERTS_DIR,
                offline_only=self.offline_only,
                service_tier_override=self.service_tier_override,
            )
            logger.info(
                "Windows Event Log & Sysmon 監視エージェント (トレイ常駐) v%s 起動 | モデル=%s | ティア=%s | 巡回間隔=%d秒 | オフライン専用=%s",
                config.APP_VERSION,
                self.triage_agent.model_name,
                self.triage_agent.get_tier_status_label(),
                self.poll_interval,
                self.offline_only,
            )
            self._agent_ready_event.set()
            if self.current_state != STATE_CRITICAL:
                mode_label = "オフラインルール監視" if self.offline_only else self.triage_agent.model_name
                self.set_status(STATE_NORMAL, f"正常監視中 ({mode_label})")
        except Exception as init_exc:
            logger.error("Gemini エージェントの初期化エラー: %s", init_exc)
            self._active_confirmed_alert = True
            self._agent_ready_event.set()
            self.set_status(
                STATE_CRITICAL,
                f"初期化エラー: {init_exc}",
                notify_title="Sysmon Gemini 監視エージェント [初期化エラー]",
            )
            return

        while not self._stop_event.is_set():
            try:
                candidates = self.event_reader.poll_suspicious_candidates()
                if candidates:
                    logger.warning("不審候補を %d 件検出。トリアージへ振り分けます。", len(candidates))
                    for candidate in candidates:
                        if self._stop_event.is_set():
                            break
                        if self.offline_only:
                            self._process_single_candidate(candidate)
                            continue

                        pre_severity = self.triage_agent.classify_offline_severity(candidate)
                        if pre_severity == config.SEVERITY_CRITICAL:
                            # CRITICAL 候補は Flex 待機列をバイパスし即時 standard ティアで調査
                            self._process_single_candidate(candidate)
                        else:
                            q_status, q_len = self.flex_queue.enqueue(candidate)
                            if q_status == "overflow":
                                logger.warning(
                                    "Flex 待機キュー上限 (%d件) 超過のため EventRecordID=%d を即時オフライン判定します。",
                                    self.flex_queue.max_size,
                                    candidate.event_record_id,
                                )
                                res = self.triage_agent.investigate_offline(
                                    candidate,
                                    error_reason="Flex待機キュー上限超過のためローカル即時判定",
                                )
                                self._apply_triage_result(candidate, res, from_reconciliation=False)
                            elif q_status == "deduplicated":
                                logger.debug(
                                    "同一フィンガープリントの待機中イベントを重複統合しました (RecordID=%d, 待機=%d件)",
                                    candidate.event_record_id,
                                    q_len,
                                )

                    self._refresh_tray_menu()

                self.checkpoint_mgr.save()

            except Exception as loop_exc:
                logger.error("巡回ループ内で深刻なエラーが発生しました: %s", loop_exc)
                self._active_confirmed_alert = True
                self.set_status(
                    STATE_CRITICAL,
                    f"実行エラー: {loop_exc}",
                    notify_title="Sysmon Gemini 監視エージェント [エラー発生]",
                )

            # 次の巡回まで待機（または「今すぐ巡回」/「終了」シグナルで即時復帰）
            self._scan_now_event.wait(timeout=float(self.poll_interval))
            self._scan_now_event.clear()

        self.checkpoint_mgr.save()
        logger.info("バックグラウンド監視スレッドが正常に終了しました。")

    def _flex_triage_worker(self) -> None:
        """
        [SUSPICIOUS] イベントの待機キュー・オフライン保留分のオンライン再判定・日次レビューを
        15 秒巡回スレッドから分離して順次実行するワーカースレッド。
        """
        while not self._stop_event.is_set():
            if self._agent_ready_event.wait(timeout=1.0):
                break
        if self._stop_event.is_set() or self.triage_agent is None:
            return

        while not self._stop_event.is_set():
            try:
                queued_event = self.flex_queue.dequeue(timeout=2.0, stop_event=self._stop_event)
                if self._stop_event.is_set():
                    break
                if queued_event is not None:
                    self._process_single_candidate(queued_event)
                    self._refresh_tray_menu()
                    continue

                # キューが空のタイミングでオフライン再判定・日次レビューを実行
                self._reconcile_pending_offline_alerts()
                self._maybe_run_daily_review()
            except Exception as exc:
                logger.error("非同期トリアージスレッド内でエラーが発生しました: %s", exc)
                time.sleep(2.0)

        logger.info("非同期 Flex トリアージスレッドが正常に終了しました。")

    def run(self) -> int:
        """監視スレッドと非同期トリアージスレッドを開始し、タスクバーアイコンのイベントループを実行します。"""
        monitor_worker = threading.Thread(
            target=self._monitoring_worker,
            name="SysmonGeminiMonitorThread",
            daemon=True,
        )
        triage_worker = threading.Thread(
            target=self._flex_triage_worker,
            name="SysmonGeminiFlexTriageThread",
            daemon=True,
        )
        monitor_worker.start()
        triage_worker.start()
        self.icon.run()
        self._stop_event.set()
        self._daily_review_now_event.set()
        self._scan_now_event.set()
        self.flex_queue.wake()
        shutdown_ui_host()
        monitor_worker.join(timeout=5.0)
        triage_worker.join(timeout=5.0)
        return 0
