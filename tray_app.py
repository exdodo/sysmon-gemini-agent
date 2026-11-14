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

import ctypes
import logging
import os
import threading
import time
from typing import Any

from agent import GeminiTriageAgent
import allowlist
import config
from event_reader import CheckpointManager, NormalizedEvent, WindowsEventReader
from process_guard import show_critical_response_dialog, verify_target_process

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


class SysmonTrayApp:
    """
    タスクバー（通知領域）に常駐し、深刻なアラートやエラー発生時に
    アイコンを赤色へ変更＋デスクトップ通知を行う常駐アプリケーションクラス。
    """

    def __init__(
        self,
        poll_interval: int = config.POLL_INTERVAL_SECONDS,
        offline_only: bool = False,
    ) -> None:
        if not HAS_TRAY_DEPS or pystray is None:
            raise ImportError(
                "タスクバー常駐機能には 'pystray' と 'Pillow' が必要です。"
                "`uv pip install pystray Pillow` または `uv pip install -r requirements.txt` を実行してください。"
            )

        self.poll_interval: int = poll_interval
        self.offline_only: bool = offline_only
        self.current_state: str = STATE_NORMAL
        self.status_message: str = "初期化中..."
        self.last_report_path: str = ""
        self.last_critical_incident: tuple[NormalizedEvent, str, str] | None = None
        self._active_confirmed_alert: bool = False
        self._pending_offline_alerts: list[tuple[NormalizedEvent, str]] = []
        self._stop_event = threading.Event()
        self._scan_now_event = threading.Event()
        self._lock = threading.Lock()

        self.checkpoint_mgr = CheckpointManager(config.CHECKPOINT_FILE)
        self.event_reader = WindowsEventReader(self.checkpoint_mgr)
        self.triage_agent: GeminiTriageAgent | None = None

        self.icon = pystray.Icon(
            name="sysmon_gemini_agent",
            icon=create_status_icon_image(STATE_NORMAL),
            title=f"Sysmon Gemini 監視エージェント v{config.APP_VERSION}: 起動中",
            menu=self._build_menu(),
        )

    def _build_menu(self) -> Any:
        """タスクバーアイコンを右クリックした際のメニューを構築します。"""
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
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("今すぐ巡回を実行", self._on_scan_now),
            pystray.MenuItem("直近のCRITICAL迎撃パネル (Suspend/Kill) を開く", self._on_open_critical_dialog),
            pystray.MenuItem("許可リスト (allowlist.json) を開く", self._on_open_allowlist),
            pystray.MenuItem("アラート出力フォルダ (alerts) を開く", self._on_open_alerts_dir),
            pystray.MenuItem("実行ログ (agent_runtime.log) を開く", self._on_open_runtime_log),
            pystray.MenuItem("アイコンを正常色（緑）にリセット", self._on_reset_status),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("安全に終了 (Exit)", self._on_exit),
        )

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
        self._scan_now_event.set()
        self.checkpoint_mgr.save()
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
            if not already_shown_critical:
                show_critical_response_dialog(
                    candidate,
                    rep_text,
                    self.last_report_path,
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

    def _monitoring_worker(self) -> None:
        """バックグラウンドで定期巡回とトリアージを行うワーカースレッド。"""
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
            )
            if self.current_state != STATE_CRITICAL:
                mode_label = "オフラインルール監視" if self.offline_only else self.triage_agent.model_name
                self.set_status(STATE_NORMAL, f"正常監視中 ({mode_label})")
        except Exception as init_exc:
            logger.error("Gemini エージェントの初期化エラー: %s", init_exc)
            self._active_confirmed_alert = True
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
                    logger.warning("不審候補を %d 件検出。トリアージを実行します。", len(candidates))
                    for candidate in candidates:
                        if self._stop_event.is_set():
                            break
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

                # オフラインフォールバック保留分があればオンライン復旧後に再判定し、条件を満たせば緑色へ自動復帰
                self._reconcile_pending_offline_alerts()

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

    def run(self) -> int:
        """ワーカースレッドを開始し、タスクバーアイコンのイベントループを実行します。"""
        worker = threading.Thread(
            target=self._monitoring_worker,
            name="SysmonGeminiMonitorThread",
            daemon=True,
        )
        worker.start()
        self.icon.run()
        self._stop_event.set()
        self._scan_now_event.set()
        worker.join(timeout=5.0)
        return 0
