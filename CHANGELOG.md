# Changelog

本プロジェクトの変更履歴およびバージョン管理記録です（`config.py` の `APP_VERSION` および Git タグと連動）。

## [1.31] - 2026-11-25
OS レベルの予防的ハードニング（LSA 保護・メモリ整合性 HVCI・Microsoft Defender ASR 推奨12ルール）の確認＆段階的有効化ツールを追加。

### 追加・改善
- **OS 防御姿勢チェック機能 (`posture_check.py`, `main.py`, `tray_app.py`)**:
  - `winreg` により LSA 保護 (`RunAsPPL`/`RunAsPPLBoot`)・メモリ整合性 (`HVCI Enabled`)・Defender 改ざん防止・ASR 推奨 12 ルールの状態を完全 Read-Only で収集・整形。
  - CLI `main.py --posture-check` およびトレイメニュー「**OS防御設定を確認 (LSA / メモリ整合性 / ASR)**」からの診断ウィンドウ表示に対応。
- **ASR / LSA / HVCI 確認＆安全有効化ランチャー (`harden_endpoint.ps1`)**:
  - Windows PowerShell 5.1 (`powershell.exe`) 専用の UTF-8 (BOM付き) スクリプトとして実装（`-Mode Audit` / `ApplyAudit` / `CheckAsrLogs` / `ApplyBlock` / `Rollback`）。
  - 既存の `Block`/`Warn` ルールを維持したまま推奨 12 ルールを監査モード (`AuditMode`) で導入し、`Event ID 1122/1121` の競合有無を確認してからブロックモードへ昇格可能。

## [1.30] - 2026-11-25
セキュリティ・検知精度・耐障害性の包括的強化、15秒巡回と非同期 Flex トリアージの分離、503/504 多発時の自動クールダウン、および Flex ⇔ 通常 (`standard`) 処理のトレイ／CLI 切替を実装。

### 追加・改善（運用・耐障害性）
- **503/504 多発時の自動 Flex クールダウン＆通常処理切替 (`agent.py`, `runtime_settings.py`, `tray_app.py`, `main.py`, `start_agent.ps1`, `config.py`)**:
  - Flex ティアで 503/504/429/タイムアウト等のリトライ超過が連続 `FLEX_CONSECUTIVE_ERROR_THRESHOLD` (2) 回発生すると、自動的に `FLEX_COOLDOWN_SECONDS` (1800秒 = 30分) のクールダウンに入り、その間の通常イベントも即座に `standard` ティアへ退避するように改善。
  - 503/504/429 時の指数バックオフ初動待機を引き上げ (`CONGESTION_INITIAL_BACKOFF_SECONDS = 5.0` 秒、上限 `MAX_BACKOFF_SECONDS = 60.0` 秒)、オフライン再試行クールダウンも `180` 秒へ拡張。
  - タスクトレイに「**サービスティア切替 (Flex / 通常)**」サブメニューと現在ティア・待機件数表示を追加し、実行中でも再起動なしで Flex 停止 ⇔ 通常処理固定 (`standard`) を永続切替（`runtime_settings.json`）・クールダウン手動解除可能に。
  - CLI に `--standard-tier` / `--service-tier`、`start_agent.ps1` に `-StandardTier` および `-SyncDeps`（依存パッケージ同期を初回構築時または明示指定時のみに限定）を追加。
- **監視ループと Flex キューの分離・バックプレッシャ制御 (`tray_app.py`)**:
  - 15秒ごとのログ巡回＋`[CRITICAL]` 即時 (`standard`) 処理を担う `_monitoring_worker` と、`[SUSPICIOUS]` イベントを重複排除付き上限キュー（`FlexTriageQueue`, 上限100件）で順次処理する `_flex_triage_worker` に分離し、Flex 待機による監視停止を解消。キュー飽和時はオフライン即時判定へ逃がし、混雑時は自動日次レビューを後回しにする制御を追加。
- **構造化コンパニオンログ (`events_YYYYMMDD.jsonl`) 出力＆日次レビュー高速化 (`agent.py`, `daily_reviewer.py`, `log_retention.py`)**:
  - `alerts/incident_YYYYMMDD.md` への追記と同時に `alerts/events_YYYYMMDD.jsonl` を出力し、`DailyReviewer` が JSON Schema (`DAILY_REVIEW_RESPONSE_SCHEMA`) 強制付きで構造化 JSONL を優先解析（過去 `.md` へのフォールバック維持）し、`log_retention.py` の30日・100MBクリーンアップ対象にも統合。

### 修正・セキュリティ強化
- **プロンプトインジェクション耐性強化 (`agent.py`, `daily_reviewer.py`)**:
  - イベントログ／日次サマリー入力を `<UNTRUSTED_EVENT_DATA>` / `<UNTRUSTED_LOG_SUMMARY>` タグで隔離・閉じタグエスケープし、システム指示内でデータ内命令の無視を厳命。
- **検知回避ギャップ修正 (`config.py`, `event_reader.py`, `tools.py`, `keyword_matcher.py`)**:
  - Sysmon Event ID `14`（Registry Rename）を `config.SYSMON_EVENT_IDS` および `tools.py` の調査 XPath に追加。
  - `CreateRemoteThread` (ID 8) における別パス同名バイナリ（例: `C:\Temp\explorer.exe` → `C:\Windows\explorer.exe`）や偽 `svchost.exe` の除外バイパスを解消（同一パス・同一PIDのみ除外、`System32` / 正規 Windows Defender パス前方一致を必須化）。
  - `ProcessAccess` (ID 10) の `"\\windows defender\\"` 部分一致を厳密な正規 Defender ディレクトリ前方一致へ強化。
  - `keyword_matcher.py` から LOLBAS 悪用可能な `ieframe.dll` / `shdocvw.dll` の安全除外を削除し、`-ec` / `irm` / バッククォート・キャレット難読化（``i`ex``, `^b^y^p^a^s^s`, `w^e^v^t^u^t^i^l` 等）を検出。
- **ホワイトリストバイパス防止 (`allowlist.py`)**:
  - `trusted_image_prefixes` における汎用インタプリタの末尾コメント追記（`powershell.exe -c "evil; # C:\Trusted\a.ps1"`）や複数スクリプト混入を遮断するため `all()`＋連結記号・インライン実行拒否へ厳格化し、`trusted_command_line_contains` へのコマンド連結便乗もブロック。
- **信頼性・UIスレッド安全性・二重起動防止 (`runtime_settings.py`, `ui_host.py`, `process_guard.py`, `daily_reviewer.py`, `event_reader.py`, `agent.py`, `main.py`)**:
  - 単一インスタンス Windows 名前付きミューテックス (`SingleInstanceMutex`) 導入、全 JSON 設定/状態保存の原子的置換 (`atomic_write_json`) 統一。
  - 専用単一 UI スレッド (`ui_host.py`) を新設し、`CRITICAL` 迎撃パネルとホワイトリスト確認 UI の `tk.Toplevel` 一元生成化、スレッド間競合解消（`_state_lock` / `_report_lock` 導入と実使用モデル・ティアの明示返却）、および `[CLEAN]` 時の不要な `psutil` プロセス照合スキップ＆15秒以内 PID 再利用対策（`expected_command_line` 照合）を実施。

## [1.20] - 2026-11-25
公開リポジトリ向けセキュリティ・プライバシー監査に基づくバグ修正、機微情報マスキング、システム改善、および恒久テストスイート (`tests/`) の整備を実施。

### 修正・セキュリティ強化
- **`trusted_image_prefixes` の許可リスト回避リスク解消 (`allowlist.py`)**:
  - 従来の部分一致 (`p in img or p in cmd`) を廃止し、実行ファイルパスの厳密前方一致 (`img_norm.startswith(p_norm)`) または汎用インタプリタ実行時のスクリプトフルパス前方一致へ修正。
- **`process_guard.py` の System32 判定バグ修正**:
  - raw 文字列内の二重バックスラッシュ（`r"c:\windows\system32\\"`）により常に `False` となっていた判定を修正。
- **Gemini 送信前・ログ保存前の機微情報マスキング (`sanitizer.py`, `event_reader.py`, `agent.py`, `tools.py`)**:
  - `AIza...` / `ghp_...` / `sk-...` / `Bearer ...` / `--token=...` / `password=...` 等を自動的に伏せ字（`<REDACTED>` 等）へ置換し、API 外部送信および `alerts/incident_*.md` への誤記録を防止。
- **Sysmon Event ID 255 (`GetConfigurationOptions` 権限エラー) の過剰 `[CRITICAL候補]` 抑止 (`event_reader.py`)**:
  - `error 5` 等の非管理者設定照会エラーを `[CRITICAL候補]` から除外し、Flex ティアで適切に処理されるよう調整。
- **ポータブル起動・公開ドキュメント汎用化・テスト常設化 (`start_agent.ps1`, `README.md`, `GEMINI.md`, `HANDOVER.md`, `tests/`)**:
  - `start_agent.ps1` の `uv.exe` 検出を `Get-Command uv` / `$env:USERPROFILE\.local\bin\uv.exe` へ変更し、個人ユーザー名を含むハードコードパスを解消。
  - `tests/` 配下に単体テストスイートを常設整備。

## [1.19] - 2026-11-24
前日アラートログの日次総合レビュー（Gemini Flex ティア）および保留ホワイトリスト候補の 1 件ずつ確認・登録機能を実装。

### 追加・改善
- **日次ログ総合レビュー＆ホワイトリスト候補キュー (`daily_reviewer.py`, `agent.py`, `config.py`)**:
  - 毎日1回（`DAILY_REVIEW_HOUR = 9` 時以降の初回巡回時、またはトレイ/CLI `--daily-review` による手動実行時）、前日分の `alerts/incident_YYYYMMDD.md` を Python でパターン集約した上で Gemini（`service_tier="flex"`）へ送信。
  - 単発イベント間の時系列相関・多段階攻撃の有無を評価し、`alerts/daily_review_YYYYMMDD.md` へ出力。
  - `[CLEAN]` の頻出パターンから安全なホワイトリスト候補を抽出し、`allowlist_candidates.json` に保留キューとして蓄積（自動直接登録はせず、すべて `allowlist.validate_rule_entry()` で汎用インタプリタや広範ディレクトリをブロック）。
- **1件ずつ確認しながら登録できるステップ確認 UI (`daily_reviewer.py`, `tray_app.py`, `main.py`, `allowlist.py`)**:
  - タスクトレイメニュー「**ホワイトリスト候補を確認・登録 (N件)**」（および `main.py --review-candidates`）から、蓄積された候補を 1 件ずつ（対象プロセス・代表コマンドライン・Gemini 推奨理由・リスク評価を確認し、必要なら登録値を編集した上で）「**登録して次へ**」「**却下して次へ**」「**保留して次へ**」で順次処理できるダイアログを追加。
  - `log_retention.py` で `daily_review_YYYYMMDD.md` も 30 日保持対象に統合。

## [1.18] - 2026-11-22
汎用環境変数 `GEMINI_API_KEY` による他プロセスからの参照・悪用リスクを防ぐため、Windows 資格情報マネージャー (`keyring`) 優先＋プロジェクト固有環境変数 (`SYSMON_GEMINI_API_KEY`) フォールバックへ移行。

### 変更・セキュリティ強化
- **API キー管理の分離 (`config.py`, `agent.py`, `requirements.txt`)**:
  - `GEMINI_API_KEY` の暗黙参照を廃止し、`SYSMON_GEMINI_API_KEY`（テスト用の一時上書き）→ Windows 資格情報マネージャー (`sysmon-gemini-agent` / `gemini_api_key`) の順で取得し、`genai.Client(api_key=...)` へ明示渡しするよう変更。
- **ランチャーの安全な登録フロー (`start_agent.ps1`)**:
  - 未登録時のキー入力を `-AsSecureString` による非表示入力へ変更し、コマンドライン引数に残らないよう標準入力経由で Windows 資格情報マネージャーへ保存するよう刷新。

## [1.17] - 2026-11-19
一次スクリーニングの不審キーワード判定を単純な部分一致から精密ルール（単語境界・PowerShell 引数パターン・正規 System32 `rundll32`/`regsvr32` 除外）へ刷新し、`msiexec.exe`（`iex` 部分一致）や Windows 標準 `rundll32.exe` による誤検知を解消。

### 修正・改善
- **精密キーワードマッチングモジュール新設 (`keyword_matcher.py`)**:
  - `iex`: `msiexec.exe`・`iexplore.exe`・16進数/GUID 等に誤爆しないよう区切り条件（`(?:^|[\s"'(|;&`])iex(?=$|[\s("'`;|&])`）へ変更し、`iex (...)` / `| iex` / `invoke-expression` のみを正確に検知。
  - `bypass` / `hidden` / `-enc`: `--proxy-bypass-list`・`--window-state=hidden`・`--encoding=utf-8` 等に誤爆しないよう PowerShell フラグ構文（`-ExecutionPolicy Bypass`, `-ep bypass`, `-WindowStyle Hidden`, `-w hidden`, `-enc` / `-EncodedCommand` / 長文 Base64 等）へ厳格化。
  - `rundll32` / `regsvr32`: `C:\Windows\System32` / `SysWOW64` の正規実行ファイルが安全領域の標準 DLL/CPL（例: `AppXDeploymentExtensions.OneCore.dll,ShellRefresh`, `PcaSvc.dll`, `sysdm.cpl`, `shell32.dll`）を呼び出す場合は除外しつつ、一時/公開パス・UNC/URL・悪用実績のある LOLBin エントリポイント（`comsvcs.dll,MiniDump`, `mshtml,RunHTMLApplication`, `ShellExec_RunDLL`, `scrobj.dll` 等）は引き続き検知。
- **重複ロジックの共通化 (`event_reader.py`, `agent.py`, `allowlist.py`)**:
  - `screen_event()`・`_screen_registry_event()`・`classify_offline_severity()`・`is_high_risk_protected_event()` がすべて `keyword_matcher` を共通利用するよう統合し、誤って `msiexec.exe` 等が `[CRITICAL]` に昇格する問題もあわせて解消。

## [1.16] - 2026-11-19
Gemini 入出力双方のプレーンテキスト化・簡素化による入出力トークン削減を実装。

### 追加・改善
- **出力側のプレーンテキスト統一＆装飾・挨拶抑止 (`agent.py`)**:
  - `SYSTEM_INSTRUCTION` を更新し、Markdown 装飾（`#`, `**`, `*`, `---`, バッククォート、コードブロック）・前置き・結びの挨拶を禁止し、プレーンテキストのみで簡潔に出力するよう変更（`[CLEAN]` 時の2行短文化は継続）。
  - オフラインフォールバック出力（`investigate_offline`）、空応答フォールバック、オンライン再判定見出しもプレーンテキスト形式へ統一し、GUI 迎撃パネル（`ScrolledText`）での視認性も向上。
- **入力側プロンプトのプレーンテキスト＆コンパクト JSON 化 (`agent.py`)**:
  - `SYSTEM_INSTRUCTION` 自体から Markdown 装飾と冗長な記述を削減。
  - `_build_initial_prompt()` で `###` 見出し・コードフェンス・`- ` 箇条書き・冗長前置き・JSON インデント空白を除去し、プレーンテキスト＋コンパクト JSON (`separators=(",", ":")`) で送信するよう最適化。
- **キャッシュサマリ抽出の堅牢化 (`triage_cache.py`)**:
  - `summarize_clean_report()` で中黒（`・`）箇条書き記号も安全に除去できるよう対応。

## [1.15] - 2026-11-18
`[SUSPICIOUS]` 候補への Gemini Flex ティア（`service_tier="flex"`）適用による API コスト50%削減、`[CRITICAL]` 候補の通常ティア即時優先、長時間タイムアウト（`HttpOptions(timeout=300000)`）、および混雑・上限到達時の `standard` 自動フォールバックを実装。

### 追加・改善
- **事前リスク別サービスティア自動振り分け (`agent.py`, `config.py`)**:
  - `_select_initial_service_tier()` により、第1層の事前リスク評価が `[SUSPICIOUS]` 相当のイベントにはコスト半額の `service_tier="flex"`（`FLEX_HTTP_TIMEOUT_MS = 300_000` ms = 5分）、`[CRITICAL]` 相当（`[CRITICAL候補]`・改ざん・注入・LSASSアクセス・高危険キーワード等）のイベントには即時応答優先の `service_tier="standard"`（`STANDARD_HTTP_TIMEOUT_MS = 60_000` ms）を自動選択。
  - `_build_generate_config()` を共通化し、初期ターンおよび `max_depth` 到達時の最終ターン双方へ `service_tier` と `HttpOptions(timeout=...)` を確実に適用。
- **Flex 向けリトライ強化＆標準ティア自動フォールバック (`agent.py`, `config.py`)**:
  - `genai.Client(http_options=types.HttpOptions(timeout=300000))` でクライアントを初期化し、`_is_retryable_api_error()` で `408 / 429 / 500 / 502 / 503 / 504`・`unavailable`・`overloaded`・`deadline_exceeded`・`timeout` に対する指数バックオフリトライを拡充。
  - Flex ティアでリトライ上限に達した場合は自動で `service_tier="standard"` へフォールバックし、標準ティアも到達不能な場合はローカルフォールバック＋次回巡回再判定キューへ繰り越し。
  - レポート内の「使用AIモデル」行および返却結果へ実際に使用されたティア（`(tier: flex)` / `(tier: standard)`）を明記。

## [1.14] - 2026-11-15
`[CLEAN]` 判定キャッシュによる重複 API 問い合わせ抑止、`[CLEAN]` 回答の短文出力化によるトークン削減、および過去ログ・レポートの容量/期間ローテーションを実装。

### 追加・改善
- **`[CLEAN]` 判定永続キャッシュによる重複問い合わせ抑止 (`triage_cache.py`, `agent.py`, `config.py`)**:
  - `UtcTime` / `PID` / `EventRecordID` / `--csrf_token` 等の動的引数を除外・正規化した SHA-256 フィンガープリントにより、`[CLEAN]` と判定された安全なイベントパターンを `triage_cache.json` に24時間キャッシュ（`CLEAN_CACHE_TTL_SECONDS = 86400`）。
  - 同一パターン再検出時は Gemini API 問い合わせと `incident_YYYYMMDD.md` への重複追記をスキップし、`agent_runtime.log` にのみ記録。
  - **安全ガード (`allowlist.is_high_risk_protected_event`)**: 改ざん検知（Sysmon `4/16/255`, Security `1102/4719`, System `104/7036/7040`）、注入（ID `8`）、LSASSアクセス（ID `10`）、危険キーワード、リモートログオン失敗（ID `4625`）、および `[SUSPICIOUS]` / `[CRITICAL]` 判定はキャッシュ対象外として毎回検査。
- **`[CLEAN]` 時の AI 回答短文化 (`agent.py`)**:
  - `SYSTEM_INSTRUCTION` を最適化し、`[CLEAN]` 判定時は「判定レベル＋1行の簡潔な根拠のみ」出力するよう変更して出力トークンコストとレポート肥大化を削減（`[SUSPICIOUS]` / `[CRITICAL]` 時は従来の詳細フォーマットを維持）。
- **ログ・レポートの容量/期間制限 (`main.py`, `log_retention.py`, `agent.py`, `config.py`)**:
  - `alerts/agent_runtime.log` を `RotatingFileHandler`（5 MB × 5 世代）へ移行。
  - `alerts/incident_YYYYMMDD.md` に対し保持期間 30 日・`alerts/` 合計 100 MB 上限の安全クリーンアップ（当日分保護・対象ファイル名厳密一致）を実装。

## [1.13] - 2026-11-14
複数行見出し・バッククォート形式の判定レベル抽出バグ修正（`pythonw.exe` `[SUSPICIOUS]` 時の誤った迎撃パネル表示を防止）および連続ダイアログ抑止クールダウンを実装。

### 修正・改善
- **`_extract_severity()` の見出し＋次行・バッククォート抽出対応 (`agent.py`)**:
  - Gemini 応答が `### 判定レベル` の次行に `` `[SUSPICIOUS]` `` / `` `[CLEAN]` `` を出力した際、本文中の否定文脈（「直ちに侵害（`[CRITICAL]`）と断定する悪性挙動はない」等）を誤って `[CRITICAL]` と誤認する不具合を修正。
  - これにより `pythonw.exe` 等が `[SUSPICIOUS]` と判定された際は黄色アイコン／通知のみに留まり、迎撃パネルや Microsoft Defender 緊急スキャンが作動しなくなりました。
- **オフライン判定時の `uv` Python 過剰昇格防止 (`agent.py`)**:
  - `classify_offline_severity()` で `\appdata\roaming\uv\python\` 配下の `python.exe` / `pythonw.exe` を一律 `[CRITICAL]` に昇格させず `[SUSPICIOUS]` として扱うよう調整（高危険キーワード・`[CRITICAL候補]` 時は引き続き `[CRITICAL]`）。
- **迎撃パネルの連続ポップアップ抑制 (`tray_app.py`)**:
  - 同一 PID に対して短時間（120秒以内）に複数イベントが `[CRITICAL]` 判定となった場合、迎撃ウィンドウの多重表示を自動抑止するよう改善（アイコン赤表示および右クリックからの手動再表示は維持）。

## [1.12] - 2026-11-14
誤検知抑制・`uv` 管理 Python ランタイム対応・ホットリロード対応ホワイトリスト（`allowlist.json`）およびトリアージ評価レベル抽出バグ修正を実装。

### 追加・改善
- **ホットリロード対応ホワイトリスト (`allowlist.py`, `config.py`, `event_reader.py`)**:
  - プロジェクトローカルの許可リスト `allowlist.json`（再起動不要・変更時即反映）を新設し、`trusted_image_prefixes`, `trusted_images`, `trusted_command_line_contains`, `trusted_dns_domains` による除外ルールに対応。
  - **改ざん・高リスク攻撃のバイパス禁止ガード**: 改ざん検知イベント（Sysmon `4/16/255`, Security `1102/4719`, System `104/7036/7040`）、プロセス注入（`ID 8`）、LSASS/高リスクプロセスアクセス（`ID 10`）、高リスクキーワード（`mimikatz`, `wevtutil` 等）は許可リスト登録があってもスキップせず必ず検査します。
- **GUI・トレイ連携による簡単登録 (`process_guard.py`, `tray_app.py`)**:
  - `[CRITICAL]` 迎撃ダイアログに **`✅ 許可リスト追加`** ボタンを追加し、スクリプトパスまたは安全な実行ファイルパスをワンクリックで `allowlist.json` に登録可能にしました（汎用インタプリタ単体の誤登録をブロックする安全装置付き）。
  - システムトレイ右クリックメニューに **`許可リスト (allowlist.json) を開く`** を追加。
- **`uv` Python・`pythonw` 誤検知対策と情報補完 (`event_reader.py`, `tools.py`)**:
  - `AppData\Roaming\uv\python\...` 配下の公式 `uv` 管理 Python を「不審ディレクトリ実行」として無条件警告しないよう改善しつつ、スクリプト本体が Temp/公開フォルダにある場合や難読化・高リスクコマンドライン・不審外部IP通信を行う場合は引き続き検知。
  - エージェント自身の PID (`os.getpid()`, `os.getppid()`) による自己イベントの無限再調査を除外。
  - Sysmon Event ID `3`（ネットワーク通信）で `CommandLine` が空の場合や、`ID 1` がログローテーションで遡れない親プロセスについて、生存プロセスから Read-Only で `psutil.Process` によるコマンドライン・イメージ補完を行うフォールバックを追加。
- **評価レベル抽出バグの修正 (`agent.py`)**:
  - Gemini 応答本文中に「現時点で `[CRITICAL]` と断定する悪性挙動は確認されていない」のような否定文脈の `[CRITICAL]` が含まれた際、見出しの `**判定レベル**: [SUSPICIOUS]` を上書きして誤って `[CRITICAL]` 扱いになる不具合を修正。

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
  - 低ノイズで拡張イベントを収集できる Sysmon 設定テンプレート [sysmon_config.xml](file:///./sysmon_config.xml) を同梱。
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
