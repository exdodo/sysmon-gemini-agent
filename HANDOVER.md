# HANDOVER.md — `sysmon-gemini-agent` 引き継ぎドキュメント

> **最終更新日**: 2026-11-25  
> **対象ワークスペース**: `<repo-root>\sysmon-gemini-agent`  
> **リモートリポジトリ**: `https://github.com/exdodo/sysmon-gemini-agent.git`（`main` / `origin/main`）  
> **現在のリポジトリ最新状態**: `v1.20`（セキュリティ修正・機微情報マスキング・テスト常設化・公開ドキュメント汎用化）

---

## 1. プロジェクトの目的と基本アーキテクチャ

Windows イベントログ（`Microsoft-Windows-Sysmon/Operational`, `Security`, `System`）を定期巡回し、**ルールベースの一次スクリーニング** と **Google Gemini (`google-genai` SDK) の自律調査ループ（Function Calling）**、および **オフライン/API障害時のローカルフォールバック** を組み合わせて、不審プロセス・インジェクション・永続化・外部通信・改ざん兆候を安全かつ低コストにトリアージする監視エージェント。

### 3層構造
1. **第1層: 収集・一次スクリーニング (`event_reader.py`, `allowlist.py`, `config.py`)**
   - `POLL_INTERVAL_SECONDS = 15` 秒間隔で `pywin32` (`win32evtlog`) により **完全 Read-Only** 収集（`MAX_EVENTS_PER_POLL = 1000`, `RECENT_EVENT_CACHE_SIZE = 4000`）。
   - `checkpoint.json` でチャネルごとの最新 `EventRecordID` を記録し、重複処理を防止。
   - 不審候補のみを抽出して第2層へ渡すため、平常時の Gemini API 消費はゼロ。
2. **第2層: Gemini 自律調査ループ (`agent.py`, `tools.py`, `triage_cache.py`)**
   - `google-genai` SDK を使用し、`GEMINI_MODEL="auto"` で最新・軽量高速モデル（例: `gemini-4-hydrogen`）を自動選択。
   - Read-Only ツール 3 種（`get_parent_process`, `get_process_network_activity`, `get_process_related_events`）を `MAX_DEPTH = 3` 往復上限で呼び出し。
   - API 障害・オフライン時は `API_OFFLINE_COOLDOWN_SECONDS = 60` のサーキットブレーカー付きローカル判定へ自動切替。
3. **第3層: トリアージ出力・UI・迎撃 (`tray_app.py`, `process_guard.py`, `log_retention.py`)**
   - 判定レベル `[CLEAN]` / `[SUSPICIOUS]` / `[CRITICAL]` を `alerts/incident_YYYYMMDD.md` へ **追記（append）** 出力。
   - システムトレイ常駐アイコン（緑 / 黄 / 赤）と右クリックメニュー、デスクトップ通知。
   - `[CRITICAL]` 時の Microsoft Defender (`MpCmdRun.exe`) 自動緊急スキャン通報（クールダウン 600 秒）および **3点厳密照合（PID + 実行ファイル名 + 起動時刻）付きワンクリック迎撃パネル**（`Suspend` / `Resume` / `Kill` / `許可リスト追加`）。

---

## 2. 絶対に遵守すべき安全・開発規約

### セキュリティ / 安全制約（最優先）
- **完全 Read-Only 監視・破壊的操作禁止**: `os.remove` / `shutil.rmtree` 等のファイル破棄処理、イベントログ改変・削除、サービス停止、プロセス自動終了は禁止（プロセス停止は `[CRITICAL]` 時にユーザーが GUI ボタンを明示クリックした場合のみ、かつ `PROTECTED_PROCESS_NAMES` で OS 中枢・監視基盤・エディタを保護）。
- **ファイル書き込み範囲の限定**: `checkpoint.json`, `triage_cache.json`, `allowlist.json`, `alerts/` 配下のみ（インシデントレポートは追記のみ。`log_retention.py` による過去ログ整理も厳密一致の古い日付ファイルのみ対象で当日分は保護）。

### 環境・開発ルール (`%USERPROFILE%\.gemini\GEMINI.md` / `GEMINI.md` / `.agent/RULE.md`)
- **Python / `uv`**: `pip` 単体や Windows Store エイリアス `python.exe` は使用禁止。必ず `uv`（Python 3.13）で `.venv` を管理し、実行は `.\.venv\Scripts\python.exe` または `.\.venv\Scripts\pythonw.exe` を使用する。
- **PowerShell (`.ps1`)**: Windows PowerShell 5.1 の文字化け・構文エラー防止のため、日本語を含む `.ps1` は必ず **UTF-8 (BOM付き: `EF BB BF`)** で保存する。
- **Gemini SDK・モデル自動追従**:
  - 旧 `google-generativeai` は禁止。必ず `google-genai`（`from google import genai`）＋ Windows 資格情報マネージャー（`keyring`: `sysmon-gemini-agent` / `gemini_api_key`）またはプロジェクト固有環境変数 `SYSMON_GEMINI_API_KEY` を使用（ハードコード・汎用 `GEMINI_API_KEY` の常用禁止）。
  - デフォルト `auto` による起動時＆6時間ごとの `client.models.list()` 照会、安定版優先 → 数値バージョン降順 → 軽量ティア優先の順位付け、404/廃止検知時の即時切替リトライ、実使用モデルのログ・レポート明記を維持する。
- **バージョン管理規約 (`GEMINI.md`)**:
  - 機能追加・仕様変更・重要修正時は必ず `config.py` の `APP_VERSION` を更新し（小規模 `+0.01` / 大規模 `+0.10`）、① `config.py` 更新、② `CHANGELOG.md` 追記、③ Git コミット＆タグ付与（`vX.XX`）を 3 点セットで実施する（`git push` はユーザーの明示指示時のみ）。
- **ハンドオーバー運用 (`.agent/RULE.md`)**:
  - セッション開始時に本ファイル `HANDOVER.md` を読んで文脈を把握し、機能実装・バグ修正・重要意思決定の完了時に `HANDOVER.md` を自動更新する。

---

## 3. 引き継ぎ元会話での実装・意思決定サマリ (`v1.00` 〜 `v1.13` + `v1.14` 現況)

| バージョン / コミット | 日付 | 主な実装・決定内容 |
| :--- | :--- | :--- |
| 移行〜初期強化 (`v1.00` / `e32ff89`) | 2026-11-11 〜 11-14 | ・別スレッド（`3eac2caf-...`）からワークスペース引き継ぎ。<br>・`gemini-3.8-flash` → `gemini-4-hydrogen` 変更に伴い、**`auto` モデル自動追従・ランキング・自己修復**を実装し、グローバル/ローカル `GEMINI.md` に標準ルール化。<br>・**Sysmon 改ざん・ログ消去対策（Defense Evasion）**: Sysmon `4/16/255`・Security `1102/4719`・System `104/7036/7040` 追加、`UserData` パース、`EventRecordID` 巻き戻り検知＋チェックポイント自動復旧、`Sysmon64`/`Sysmon`/`EventLog` サービス Heartbeat 監視と停止時の `Security 4688` 自動切替、CLI 無効化コマンド検知を追加。<br>・`APP_VERSION`・`CHANGELOG.md`・`.gitignore`・`GEMINI.md` によるバージョン管理基盤を構築。 |
| `v1.10` (`7940058`) | 2026-11-14 | ・**監視イベント拡張**: Sysmon ID `8` (スレッド注入), `10` (LSASS 等 ProcessAccess), `11` (不審 FileCreate / ランサムノート), `12/13` (Run/IFEO/Winlogon/UAC/Defender 無効化レジストリ), `22` (DNS/トンネリング) 対応と `sysmon_config.xml` 同梱。<br>・**オフライン/API障害フォールバック**: `classify_offline_severity()`, `investigate_offline()`, 60秒サーキットブレーカー、`--offline` オプションを追加し、`origin/main` へ初回 `git push`。 |
| `v1.11` (`90ed672`) | 2026-11-14 | ・**オンライン復旧時の再トリアージ＆緑復帰**: オフラインフォールバックで保留されたイベントを復旧後に `try_reinvestigate_online()` で再判定し、オフラインのみが原因で黄/赤になっていた場合は自動で緑アイコンへ復帰させるよう実装。 |
| `v1.12` (`3295cb4`)<br>& `allowlist.json` (`f4f6cb7`) | 2026-11-14 | ・**ホットリロード対応ホワイトリスト (`allowlist.py`)**: `allowlist.json` による除外、迎撃パネル「許可リスト追加」ボタン、トレイメニュー連携（改ざん・ID `8`/ID `10`・危険キーワードはバイパス禁止ガード付き）。<br>・`uv` 管理 Python ランタイム誤検知抑制、自己 PID 除外、`psutil` による ID `3`/親プロセス補完、`_extract_severity()` 否定文脈誤拾い修正。<br>・ローカル開発用常駐スクリプト群を環境内の `allowlist.json` に登録。 |
| `v1.13` (`6513baa`) | 2026-11-14 | ・**複数行見出し・バッククォート抽出バグ修正**: `### 判定レベル\n\`[SUSPICIOUS]\`` 形式の応答で本文中の `[CRITICAL]` 否定表現を誤認識して迎撃パネルが開く不具合を修正。<br>・オフライン判定時の `uv` Python 過剰 `[CRITICAL]` 昇格抑止、同一 PID 120秒以内の迎撃ダイアログ連続ポップアップ抑止を追加。 |
| `v1.14` (`3025b4d`)<br>*(別ターンで反映済)* | 2026-11-15 | ・`triage_cache.py` による `[CLEAN]` 24時間 SHA-256 キャッシュ（高リスク/改ざんイベントはキャッシュ除外）。<br>・`[CLEAN]` 時 AI 回答の短文化、`log_retention.py` ＆ `RotatingFileHandler`（5 MB × 5 世代 / 30 日 / 100 MB 上限）を実装。 |
| `v1.15` (`7e32a7c`) | 2026-11-18 | ・事前リスク別サービスティア振り分け（`[SUSPICIOUS]` 候補はコスト半額の `service_tier="flex"` / 300秒タイムアウト、`[CRITICAL]` 候補は `standard` 即時優先）および混雑時 `standard` 自動フォールバックを実装。 |
| `v1.16` (`8bff320`) | 2026-11-19 | ・Gemini 入出力のプレーンテキスト統一（Markdown 装飾 `#`, `**`, `*`, `---` や挨拶の抑止、`_build_initial_prompt` のコンパクト JSON＋プレーンテキスト化）、オフライン/空応答出力の統一、`summarize_clean_report()` の `・` 除去対応を実装。 |
| `v1.17` (`b563554`) | 2026-11-19 | ・`keyword_matcher.py` による一次スクリーニング精密化（`iex` / `bypass` / `hidden` / `-enc` / System32 `rundll32`/`regsvr32` 誤検知解消）。 |
| `v1.18` (`18fc52e`) | 2026-11-22 | ・`GEMINI_API_KEY` 依存を廃止し、Windows 資格情報マネージャー (`keyring`) 優先＋`SYSMON_GEMINI_API_KEY` フォールバック・`start_agent.ps1` の `-AsSecureString`＋stdin 登録へ移行。 |
| `v1.19` (`0a83a76`) | 2026-11-24 | ・`daily_reviewer.py` による前日ログの Gemini Flex 日次レビュー、`allowlist_candidates.json` 保留キュー蓄積、および 1 件ずつ確認登録できるステップ UI を追加。 |
| `v1.20` | 2026-11-25 | ・`allowlist.py` の `trusted_image_prefixes` 部分一致バイパス修正、`process_guard.py` の System32 判定バグ修正、`sanitizer.py` による機微情報マスキング、Sysmon ID 255 権限エラーの過剰 CRITICAL 抑止、`tests/` 常設化・公開ドキュメント汎用化を実施。 |

---

## 4. ファイル構成（現状）

| ファイル | 役割 |
| :--- | :--- |
| `config.py` | `APP_VERSION = "1.18"`、監視対象チャネル/ID、一次スクリーニング条件、Gemini モデル・資格情報設定、`MAX_DEPTH = 3`、キャッシュ/ログ保持設定、保護プロセス一覧 |
| `event_reader.py` | `win32evtlog` Read-Only 収集、XML パース（`EventData`/`UserData`）、一次スクリーニング、`EventRecordID` 巻き戻り復旧、サービス死活監視、`checkpoint.json` 管理 |
| `allowlist.py` | ホットリロード対応 `allowlist.json` 判定、高リスクイベントバイパス禁止ガード、GUI 登録候補抽出 |
| `triage_cache.py` | `[CLEAN]` 判定パターンの正規化 SHA-256 フィンガープリント生成・24時間永続キャッシュ（`triage_cache.json`） |
| `tools.py` | Gemini Function Calling 用 Read-Only ツール（`get_parent_process`, `get_process_network_activity`, `get_process_related_events`）＋ `psutil` 補完 |
| `agent.py` | `google-genai` 自律調査ループ（`auto` モデル自動選択・404時切替）、指数バックオフ、オフライン/障害フォールバック、レポート出力 |
| `process_guard.py` | 3点厳密照合（PID+実行ファイル名+起動時刻）、Microsoft Defender (`MpCmdRun.exe`) 連携、ワンクリック迎撃ダイアログ |
| `tray_app.py` | システムトレイ常駐（緑/黄/赤アイコン、右クリックメニュー、オフライン復旧後再トリアージ、120秒ダイアログ抑止） |
| `log_retention.py` | `alerts/incident_YYYYMMDD.md` の保持期間（30日）・`alerts/` 合計容量（100 MB）に基づく安全クリーンアップ |
| `main.py` | CLI エントリーポイント（`--interval`, `--once`, `--tray`, `--offline`, `--version`）、管理者権限チェック、ローテーションログ設定 |
| `start_agent.ps1` | UTF-8 (BOM付き) PowerShell ランチャー（UAC 自動昇格、`uv`/`.venv` 確認、`keyring` 安全入力保存、トレイ起動） |
| `sysmon_config.xml` | 拡張イベント ID (`1, 3, 8, 10, 11, 12, 13, 14, 22`) を低ノイズで収集する Sysmon 設定テンプレート |
| `CHANGELOG.md` / `README.md` | バージョン履歴（`1.00`〜`1.14`）およびセットアップ・運用ドキュメント |
| *(Git 管理外)* | `allowlist.json`, `checkpoint.json`, `triage_cache.json`, `alerts/`, `.venv/` |

---

## 5. 運用上の注意点・既知のハマりどころ

1. **コード更新後のトレイプロセス再起動必須**:
   - バックグラウンドで古い `pythonw.exe main.py --tray` が稼働し続けると、新しいコードや自己 PID 除外・修正ロジックが適用されない。改修後は必ずタスクバーアイコン右クリック →「安全に終了 (Exit)」のうえ、`start_agent.ps1` で再起動する。
2. **Sysmon 拡張設定の適用**:
   - Sysmon ID `8, 10, 11, 12, 13, 22` を実機で有効活用するには、管理者 PowerShell で `sysmon64.exe -c .\sysmon_config.xml` の適用が必要。
3. **サンドボックス内での Git / API 実行制限**:
   - 本環境では標準サンドボックス内で `.git/index.lock` / タグ作成や外部通信（`git push`, Gemini API 呼び出し）が権限/ネットワーク制限で失敗することがあるため、必要な Git 書き込み・外部 API 検証コマンドのみ `BypassSandbox: true` を使用する。
4. **テスト資産と検証状況**:
   - リポジトリ直下の `tests/` ディレクトリに単体テストスイートを常設しており、`.\.venv\Scripts\python.exe -m unittest discover -s tests -v` で一括実行できます。GUI ウィンドウ操作および実機イベントログでの長時間稼働確認は実環境側の起動で確認する運用となっています。
5. **起動コマンド（クイックリファレンス）**:
   ```powershell
   # 推奨ランチャー（自動管理者昇格・トレイ常駐）
   powershell -ExecutionPolicy Bypass -File .\start_agent.ps1

   # 構文チェック（全主要モジュール）
   .\.venv\Scripts\python.exe -m py_compile allowlist.py config.py event_reader.py log_retention.py main.py process_guard.py tools.py tray_app.py triage_cache.py agent.py

   # バージョン・CLI確認
   .\.venv\Scripts\python.exe main.py --version
   .\.venv\Scripts\python.exe main.py --once --offline
   ```
