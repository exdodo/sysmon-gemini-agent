"""
Windows Event Log & Sysmon 監視エージェント メインエントリーポイント (main.py)

定期巡回ループ (`time.sleep(60)`) により Windows イベントログ (Sysmon / Security) を監視し、
ルールベースの一次スクリーニングと Google Gemini の自律調査ループ (Function Calling) を組み合わせて
不審イベントのトリアージレポートを `alerts/incident_YYYYMMDD.md` に追記出力します。
"""

from __future__ import annotations

from datetime import datetime, timedelta
import argparse
import ctypes
import logging
from logging.handlers import RotatingFileHandler
import sys
import time

from agent import GeminiTriageAgent
import config
from daily_reviewer import DailyReviewer, show_allowlist_review_dialog
from event_reader import CheckpointManager, NormalizedEvent, WindowsEventReader
from process_guard import show_critical_response_dialog
from runtime_settings import SingleInstanceMutex


def setup_logging() -> logging.Logger:
    """
    コンソール出力および `alerts/agent_runtime.log` への追記専用（mode='a'）ロガーを構成します。
    """
    config.ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("sysmon_gemini_agent")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # コンソールハンドラ (pythonw.exe 等のウィンドウ非表示実行時は sys.stdout が None のためスキップ)
        if sys.stdout is not None:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # ファイルハンドラ（自動ローテーション付き追記: 5 MB × 5 世代）
        file_handler = RotatingFileHandler(
            config.AGENT_LOG_FILE,
            mode="a",
            maxBytes=config.RUNTIME_LOG_MAX_BYTES,
            backupCount=config.RUNTIME_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def is_running_as_admin() -> bool:
    """現在のプロセスがWindowsの管理者権限で実行されているかを確認します（Read-Only判定）。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_monitoring_loop(
    poll_interval: int = config.POLL_INTERVAL_SECONDS,
    run_once: bool = False,
    offline_only: bool = False,
    service_tier_override: str | None = None,
) -> int:
    """
    定期巡回デーモンのメインループを実行します。
    """
    logger = setup_logging()
    logger.info("============================================================")
    logger.info("Windows Event Log & Sysmon 監視エージェント (Google Gemini版) v%s 起動", config.APP_VERSION)
    logger.info(
        "使用モデル: %s | 最大調査ループ上限 (max_depth): %d | オフライン専用: %s",
        "offline-rule-engine" if offline_only else config.GEMINI_MODEL,
        config.MAX_DEPTH,
        offline_only,
    )
    logger.info("巡回間隔: %d 秒 | チェックポイント: %s", poll_interval, config.CHECKPOINT_FILE)
    logger.info("============================================================")

    if not is_running_as_admin():
        logger.warning(
            "[注意] 現在、管理者権限なしで実行されています。"
            "Security チャネルや Sysmon チャネルの読み取り時にアクセス拒否 (WinError 5) が発生する場合は、"
            "PowerShell または コマンドプロンプトを『管理者として実行』して起動してください。"
        )

    try:
        triage_agent = GeminiTriageAgent(
            model_name=config.GEMINI_MODEL,
            max_depth=config.MAX_DEPTH,
            alerts_dir=config.ALERTS_DIR,
            offline_only=offline_only,
            service_tier_override=service_tier_override,
        )
        logger.info(
            "有効化された実使用モデル: %s | ティア方針: %s",
            triage_agent.model_name,
            triage_agent.get_tier_status_label(),
        )
    except EnvironmentError as env_err:
        logger.error("初期化エラー: %s", env_err)
        return 1
    except Exception as init_exc:
        logger.error("Gemini エージェントの初期化に失敗しました: %s", init_exc)
        return 1

    checkpoint_mgr = CheckpointManager(config.CHECKPOINT_FILE)
    event_reader = WindowsEventReader(checkpoint_mgr)
    daily_reviewer = DailyReviewer(alerts_dir=config.ALERTS_DIR)
    pending_offline_events: list[NormalizedEvent] = []

    try:
        while True:
            cycle_start = time.monotonic()
            logger.info("イベントログの定期巡回サイクルを開始します...")

            candidates = event_reader.poll_suspicious_candidates()
            if not candidates:
                logger.info("今回の巡回では一次スクリーニングに合致する不審候補イベントはありませんでした。")
            else:
                logger.warning(
                    "一次スクリーニングにより %d 件の不審候補イベントを抽出しました。トリアージを開始します。",
                    len(candidates),
                )
                for idx, candidate in enumerate(candidates, start=1):
                    logger.info(
                        "[%d/%d] 不審候補の調査中: Channel=%s, EventID=%d, RecordID=%d, Image=%s",
                        idx,
                        len(candidates),
                        candidate.channel,
                        candidate.event_id,
                        candidate.event_record_id,
                        candidate.image,
                    )
                    try:
                        result = triage_agent.investigate_event(candidate)
                    except Exception as inv_exc:
                        logger.error(
                            "EventRecordID=%d の Gemini 調査中に例外が発生したため、オフラインフォールバックを実行します: %s",
                            candidate.event_record_id,
                            inv_exc,
                        )
                        result = triage_agent.investigate_offline(
                            candidate, error_reason=str(inv_exc)
                        )

                    is_offline = bool(result.get("offline_fallback", False))
                    if is_offline and not offline_only and len(pending_offline_events) < 50:
                        pending_offline_events.append(candidate)

                    mode_note = (
                        " [オフライン/フォールバック]"
                        if is_offline
                        else (" [キャッシュ一致]" if result.get("cache_hit") else "")
                    )
                    logger.info(
                        "[%d/%d] 調査完了%s: 判定=%s, ツール往復回数=%d/%d, 出力先=%s",
                        idx,
                        len(candidates),
                        mode_note,
                        result["severity"],
                        result["depth_used"],
                        config.MAX_DEPTH,
                        result.get("report_file") or "(キャッシュ一致・追記省略)",
                    )
                    if result["severity"] == config.SEVERITY_CRITICAL:
                        show_critical_response_dialog(
                            candidate,
                            result.get("report_text", ""),
                            result.get("report_file", ""),
                        )

            if pending_offline_events and triage_agent.can_attempt_online_now():
                remaining_offline: list[Any] = []
                stopped_early = False
                for idx_p, pending_ev in enumerate(pending_offline_events):
                    re_res = triage_agent.try_reinvestigate_online(pending_ev)
                    if re_res is None:
                        remaining_offline.extend(pending_offline_events[idx_p:])
                        stopped_early = True
                        break
                    logger.info(
                        "[オフライン保留分 再判定完了] RecordID=%d -> %s (出力先=%s)",
                        pending_ev.event_record_id,
                        re_res["severity"],
                        re_res["report_file"],
                    )
                    if re_res["severity"] == config.SEVERITY_CRITICAL:
                        show_critical_response_dialog(
                            pending_ev,
                            re_res.get("report_text", ""),
                            re_res.get("report_file", ""),
                        )
                pending_offline_events = remaining_offline if stopped_early else []

            checkpoint_mgr.save()

            if not offline_only:
                daily_reviewer.run_if_due(triage_agent)

            if run_once:
                logger.info("--once オプションが指定されたため、1サイクル完了後に終了します。")
                break

            logger.info("次の巡回まで %d 秒待機します (Ctrl+C で安全に停止)...", poll_interval)
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        logger.info("停止シグナル (Ctrl+C) を受信しました。チェックポイントを保存して安全に終了します。")
        checkpoint_mgr.save()
        return 0

    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """コマンドライン引数を解析します。"""
    parser = argparse.ArgumentParser(
        description="Windows Event Log & Sysmon 監視エージェント (Google Gemini版)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=config.POLL_INTERVAL_SECONDS,
        help=f"イベントログ巡回間隔（秒）。デフォルト: {config.POLL_INTERVAL_SECONDS}秒",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="1回だけ巡回・トリアージを実行して終了します（動作確認用）。",
    )
    parser.add_argument(
        "--tray",
        action="store_true",
        help="タスクバー（システムトレイ）にアイコンを表示して常駐監視します（深刻なエラーや [CRITICAL] 検知時に赤色へ変化）。",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Gemini API を呼び出さず、ルールベースの一次検知・オフライン判定のみで監視します。",
    )
    parser.add_argument(
        "--standard-tier",
        action="store_true",
        help="Flex ティアを使用せず、通常ティア (standard) のみで Gemini API を呼び出します（503/504 回避）。",
    )
    parser.add_argument(
        "--service-tier",
        choices=("flex", "standard"),
        default=None,
        help="通常イベント向けの Gemini API サービスティアを明示指定します ('flex' または 'standard')。",
    )
    parser.add_argument(
        "--daily-review",
        action="store_true",
        help="前日のインシデントログに対する Gemini 日次総合レビューと候補抽出を1回実行して終了します。",
    )
    parser.add_argument(
        "--review-candidates",
        action="store_true",
        help="保留中のホワイトリスト候補を1件ずつ確認して登録するGUIを開きます。",
    )
    parser.add_argument(
        "--posture-check",
        action="store_true",
        help="OS の LSA 保護・メモリ整合性・ASR ルール状態を Read-Only で診断表示して終了します。",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s v{config.APP_VERSION}",
    )
    return parser.parse_args(argv)


def _resolve_service_tier_override(args: argparse.Namespace) -> str | None:
    if getattr(args, "standard_tier", False):
        return "standard"
    return getattr(args, "service_tier", None)


if __name__ == "__main__":
    args = parse_args()
    tier_override = _resolve_service_tier_override(args)
    if args.posture_check:
        from posture_check import collect_endpoint_posture, format_posture_report

        print(format_posture_report(collect_endpoint_posture()))
        sys.exit(0)
    if args.review_candidates:
        show_allowlist_review_dialog()
        sys.exit(0)
    if args.daily_review:
        logger = setup_logging()
        triage = GeminiTriageAgent(
            model_name=config.GEMINI_MODEL,
            max_depth=config.MAX_DEPTH,
            alerts_dir=config.ALERTS_DIR,
            offline_only=args.offline,
            service_tier_override=tier_override,
        )
        yesterday = (datetime.now().astimezone() - timedelta(days=1)).date()
        res = DailyReviewer(alerts_dir=config.ALERTS_DIR).run_review_for_date(
            target_date=yesterday,
            triage_agent=triage,
            force=True,
        )
        print(res)
        sys.exit(0 if res.get("status") in ("ok", "empty", "no_log", "already_reviewed") else 1)

    if args.tray or not args.once:
        logger = setup_logging()
        with SingleInstanceMutex(config.SINGLE_INSTANCE_MUTEX_NAME) as mutex:
            if not mutex.acquire():
                logger.warning("Sysmon Gemini 監視エージェントは既に起動中のため、重複起動を終了します。")
                sys.exit(0)
            if args.tray:
                from tray_app import SysmonTrayApp

                app = SysmonTrayApp(
                    poll_interval=args.interval,
                    offline_only=args.offline,
                    service_tier_override=tier_override,
                )
                sys.exit(app.run())
            sys.exit(
                run_monitoring_loop(
                    poll_interval=args.interval,
                    run_once=args.once,
                    offline_only=args.offline,
                    service_tier_override=tier_override,
                )
            )
    else:
        sys.exit(
            run_monitoring_loop(
                poll_interval=args.interval,
                run_once=args.once,
                offline_only=args.offline,
                service_tier_override=tier_override,
            )
        )
