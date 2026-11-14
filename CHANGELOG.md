# Changelog

本プロジェクトの変更履歴およびバージョン管理記録です（`config.py` の `APP_VERSION` および Git タグと連動）。

## [1.00] - 2026-11-14
初期ベースラインリリース（現在までの実装・改善内容を統合）。

### 主な機能
- **3層監視アーキテクチャ**:
  - 第1層 (`event_reader.py`): Windows イベントログ（Sysmon / Security / System）の Read-Only 収集、15秒間隔巡回、`checkpoint.json` 管理、ルールベース一次スクリーニング。
  - 第2層 (`agent.py`, `tools.py`): 公式 `google-genai` SDK を用いた自律調査ループ（`max_depth = 3`、`get_parent_process` / `get_process_network_activity`）。
  - 第3層 (`agent.py`): `alerts/incident_YYYYMMDD.md` への追記専用トリアージレポート出力（`[CLEAN]` / `[SUSPICIOUS]` / `[CRITICAL]`）。
- **モデル自動追従・自己修復**:
  - デフォルト `GEMINI_MODEL="auto"` による起動時および6時間ごとの `client.models.list()` 照会（安定版優先・数値バージョン降順・軽量ティア優先、現在 `gemini-4-hydrogen` を自動選択）。
  - `404` / `deprecated` 検知時の自動モデル切替＆リトライ。
- **タスクバー常駐 & ワンクリック迎撃・Defender 連携 (`tray_app.py`, `process_guard.py`)**:
  - 状態別のアイコン色変化（緑 / 黄 / 赤）と右クリックメニュー。
  - `[CRITICAL]` 時の 3点厳密照合（PID + 実行ファイル名 + 起動時刻）付きワンクリック迎撃パネル（Suspend / Resume / Kill）および OS中枢プロセス保護。
  - Microsoft Defender (`MpCmdRun.exe`) への非同期・クールダウン付き自動緊急スキャン通報。
- **Sysmon 改ざん・ログ消去検知 & 自己復旧 (`event_reader.py`, `config.py`)**:
  - Sysmon `4`/`16`/`255`、Security `1102`/`4719`、System `104`/`7036`/`7040` および CLI 無効化コマンドの検知。
  - ログ消去に伴う `EventRecordID` 巻き戻り検知とチェックポイント自動リセット・監視再開。
  - `Sysmon64` / `Sysmon` / `EventLog` サービス死活監視（Heartbeat）および停止時の `Security 4688` 自動補完。
- **ランチャー (`start_agent.ps1`)**:
  - 自動管理者昇格（UAC）、`uv` による `.venv` 自動準備、PowerShell ウィンドウ非表示でのトレイ常駐、UTF-8 (BOM付き) 対応。
- **バージョン管理基盤**:
  - `config.APP_VERSION = "1.00"`、`--version` CLIオプション、トレイ表示、`CHANGELOG.md`、Git 初期ベースラインタグ `v1.00`。
