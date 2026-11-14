# Changelog

本プロジェクトの変更履歴およびバージョン管理記録です（`config.py` の `APP_VERSION` および Git タグと連動）。

## [1.11] - 2026-11-14
オフラインフォールバック判定イベントのオンライン復旧後再判定およびトレイアイコン自動正常復帰を実装。

### 追加・改善
- **オフライン保留イベントのオンライン再トリアージ (`agent.py`, `tray_app.py`, `main.py`)**:
  - 通信障害・API障害によりオフラインフォールバック判定（`[SUSPICIOUS]` / `[CRITICAL]`）となったイベントを保留キューに保持し、クールダウン経過・オンライン復旧後に `try_reinvestigate_online()` で Gemini API による再評価を実行します。
- **トレイアイコンの自動正常（緑）復帰 (`tray_app.py`)**:
  - オフラインフォールバックのみが原因で黄色/赤色に変化していた場合、保留イベントがすべて Gemini API によって `[CLEAN]`（問題なし）と判定され、かつ他に確定済みアラート・エラー原因が残っていないときに限り、トレイアイコンを元の緑色（正常監視中）へ自動復帰させ通知します。
  - 確定済みのオンライン `[SUSPICIOUS]` / `[CRITICAL]`、再判定で脅威確定したイベント、権限不足や実行エラーが残っている場合は誤って緑に戻さず警告表示を維持します。

## [1.10] - 2026-11-14
監視対象の攻撃ベクトル拡張（Sysmon ID `8, 10, 11, 12, 13, 22` 対応）およびオフライン・API障害時の通知フォールバックを実装。

### 追加・改善
- **監視イベント・攻撃ベクトル拡張 (`config.py`, `event_reader.py`, `tools.py`, `sysmon_config.xml`)**:
  - Sysmon Event ID `8` (`CreateRemoteThread`: スレッド/シェルコード注入)、`10` (`ProcessAccess`: LSASSメモリ読取・高権限アクセス)、`11` (`FileCreate`: スタートアップ/タスク投下・LOLBin/Officeドロップ・ランサムノート検知)、`12`/`13` (`RegistryEvent`: Runキー永続化・IFEO・Winlogon・UACバイパス・Sysmon/Defender無効化)、`22` (`DNSEvent`: LOLBin/Temp名前解決・ダイナミックDNS・DNSトンネリング) のXMLパースおよび専用一次スクリーニングルールを追加。
  - 収集・インメモリキャッシュ上限を拡張 (`MAX_EVENTS_PER_POLL = 1000`, `RECENT_EVENT_CACHE_SIZE = 4000`)。
  - Gemini Read-Only ツール `get_process_related_events(process_id)` を追加し、`get_process_network_activity` も DNS (`ID 22`) を参照可能に拡張。
  - 低ノイズで拡張イベントを収集できる Sysmon 設定テンプレート [sysmon_config.xml](file:///C:/Users/Yusuke/.gemini/antigravity/scratch/sysmon-gemini-agent/sysmon_config.xml) を同梱。
- **オフライン・API障害時の一次検知フォールバック (`agent.py`, `tray_app.py`, `main.py`, `config.py`)**:
  - Gemini API 通信障害・レート制限超過・タイムアウト時にローカルルール判定（`[CRITICAL]` / `[SUSPICIOUS]`）へ自動切替する `classify_offline_severity()` / `investigate_offline()` および 60秒サーキットブレーカー (`API_OFFLINE_COOLDOWN_SECONDS = 60`) を実装。
  - オフラインフォールバック時も `alerts/incident_YYYYMMDD.md` への追記、トレイアイコンの赤/黄変化・デスクトップ通知、Microsoft Defender 緊急スキャン通報、`[CRITICAL]` 迎撃パネル表示が途切れず動作。
  - Gemini API キー不要のオフライン専用起動オプション `--offline` を追加。

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
