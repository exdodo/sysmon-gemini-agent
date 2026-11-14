"""
Windows Event Log & Sysmon 監視エージェント メインエントリーポイント (main.py)

定期巡回ループ (`time.sleep(60)`) により Windows イベントログ (Sysmon / Security) を監視し、
ルールベースの一次スクリーニングと Google Gemini の自律調査ループ (Function Calling) を組み合わせて
不審イベントのトリアージレポートを `alerts/incident_YYYYMMDD.md` に追記出力します。
"""

from __future__ import annotations

import argparse
import ctypes
import logging
import sys
import time

from agent import GeminiTriageAgent
import config
from event_reader import CheckpointManager, WindowsEventReader
from process_guard import show_critical_response_dialog


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

        # ファイルハンドラ（安全制約に従い追記 mode="a" のみ）
        file_handler = logging.FileHandler(
            config.AGENT_LOG_FILE, mode="a", encoding="utf-8"
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
        )
        logger.info("有効化された実使用モデル: %s", triage_agent.model_name)
    except EnvironmentError as env_err:
        logger.error("初期化エラー: %s", env_err)
        return 1
    except Exception as init_exc:
        logger.error("Gemini エージェントの初期化に失敗しました: %s", init_exc)
        return 1

    checkpoint_mgr = CheckpointManager(config.CHECKPOINT_FILE)
    event_reader = WindowsEventReader(checkpoint_mgr)

    try:
        while True:
            cycle_start = time.monotonic()
            logger.info("イベントログの定期巡回サイクルを開始します...")

            candidates = event_reader.poll_suspicious_candidates()
            if not candidates:
                logger.info("今回の巡回では一次スクリーニングに合致する不審候補イベントはありませんでした。")
            else:
                logger.warning(
                    "一次スクリーニングにより %d 件の不審候補イベントを抽出しました。Gemini トリアージを開始します。",
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

                    mode_note = " [オフライン/フォールバック]" if result.get("offline_fallback") else ""
                    logger.info(
                        "[%d/%d] 調査完了%s: 判定=%s, ツール往復回数=%d/%d, 出力先=%s",
                        idx,
                        len(candidates),
                        mode_note,
                        result["severity"],
                        result["depth_used"],
                        config.MAX_DEPTH,
                        result["report_file"],
                    )
                    if result["severity"] == config.SEVERITY_CRITICAL:
                        show_critical_response_dialog(
                            candidate,
                            result.get("report_text", ""),
                            result.get("report_file", ""),
                        )

            checkpoint_mgr.save()

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
        "--version",
        action="version",
        version=f"%(prog)s v{config.APP_VERSION}",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    if args.tray:
        setup_logging()
        from tray_app import SysmonTrayApp

        app = SysmonTrayApp(poll_interval=args.interval, offline_only=args.offline)
        sys.exit(app.run())
    sys.exit(
        run_monitoring_loop(
            poll_interval=args.interval,
            run_once=args.once,
            offline_only=args.offline,
        )
    )
