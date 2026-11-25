# Windows Event Log & Sysmon 監視エージェント (Google Gemini版)

> **Version**: `1.31`（変更履歴は [CHANGELOG.md](file:///./CHANGELOG.md) を参照）

Windowsイベントログ（`Microsoft-Windows-Sysmon/Operational`, `Security`, `System`）を定期巡回し、**ルールベースの一次スクリーニング**と **Google Gemini (`google-genai` SDK) の自律調査ループ（Function Calling）**、および **オフライン・API障害時のローカル即時フォールバック判定** を組み合わせて、不審なプロセス・インジェクション・永続化・外部通信の兆候を安全かつ低コストにトリアージする監視エージェントです。

---

## 1. アーキテクチャ概要（3層構造）

1. **【第1層: 収集 & ルールベース一次スクリーニング (`event_reader.py`)】**
   - デフォルト15秒間隔（`POLL_INTERVAL_SECONDS = 15`）の定期巡回ループでイベントログを取得します。
   - `checkpoint.json` に各チャネルの最新処理済み `EventRecordID` を保存し、重複処理を防止します（ログ消去による `EventRecordID` 巻き戻りを検知した場合は自動リセットして即時監視復旧＋改ざんアラートを発報します）。
   - **監視対象ログ**:
     - `Microsoft-Windows-Sysmon/Operational`:
       - Event ID `1`: プロセス生成
       - Event ID `3`: ネットワーク接続
       - Event ID `8`: CreateRemoteThread（スレッド注入 / DLL・シェルコードインジェクション）
       - Event ID `10`: ProcessAccess（LSASSメモリ読取・認証情報ダンプ・高権限メモリ書込）
       - Event ID `11`: FileCreate（スタートアップ/タスク領域投下、LOLBin/Officeによる不審ファイル作成、ランサムノート検知）
       - Event ID `12` / `13`: RegistryEvent（Runキー永続化、IFEO、Winlogon、UACバイパス、Sysmon/Defender無効化改ざん）
       - Event ID `22`: DNSEvent（LOLBin/Tempプロセス名前解決、ダイナミックDNS、DNSトンネリング）
       - Event ID `4` / `16` / `255`: Sysmon サービス停止・設定変更・エラー報告（改ざん検知）
     - `Security`（Event ID `1102`: 監査ログ消去, `4624`/`4625`: ログオン成否, `4688`: プロセス作成 ※Sysmon未導入/停止時の自動フォールバック, `4719`: 監査ポリシー変更）
     - `System`（Event ID `104`: イベントログ消去, `7036`/`7040`: Sysmon・EventLogサービス停止/無効化）
   - **サービス死活監視（Heartbeat）**: `Sysmon64`/`Sysmon` および `EventLog` サービスの停止・消失を巡回ごとに監視し、Sysmon 停止中は自動で `Security 4688` 監視へ切り替えます。
   - **一次フィルタ（APIコスト最適化） & ホワイトリスト (`allowlist.py`, `allowlist.json`)**:
     - すべてのイベントをGeminiに送信せず、難読化・LOLBin悪用・Sysmon/ログ改ざんキーワード・一時ディレクトリ起動・拡張Sysmon検知（ID 8/10/11/12/13/22）に合致する「不審候補」のみを抽出します。
     - 自作ツールや開発スクリプト等の明らかな誤検知は `allowlist.json`（再起動不要・ホットリロード対応）へ登録して除外できます（ただし改ざん検知・CreateRemoteThread・LSASSアクセス等の重大脅威は安全ガードによりバイパス不可）。
     - `AppData\Roaming\uv\python\` 配下の `uv` 管理 Python ランタイムは、Temp/公開フォルダ上のスクリプト実行や不審コマンドライン・C2通信を伴わない限り安全側としてノイズを抑制します。

2. **【第2層: Gemini 自律調査ループ & `[CLEAN]` キャッシュ / オフラインフォールバック (`agent.py`, `triage_cache.py`, `tools.py`)】**
   - 最新の公式 `google-genai` SDK (`from google import genai` / `client = genai.Client()`) を使用し、デフォルト（`GEMINI_MODEL="auto"`）で起動時および6時間ごとに `client.models.list()` から**その時点で利用可能な最新の軽量・高速モデル（例: `gemini-4-hydrogen` 等）を自動選択**します（404/廃止検知時も自動で後継モデルへ切り替えます）。
   - **`[CLEAN]` 判定キャッシュ & 短文出力によるAPIコスト最適化**:
     - Gemini により `[CLEAN]` と判定された安全なイベントパターンを正規化フィンガープリントで `triage_cache.json` に保存（有効期限 24 時間）し、期間内の同一パターン再検出時は Gemini API 問い合わせおよび `incident_YYYYMMDD.md` への重複追記をスキップします（`agent_runtime.log` にのみ記録）。
     - 改ざん検知・注入（ID 8）・LSASSアクセス（ID 10）・危険キーワード・ログオン失敗（ID 4625）・`[SUSPICIOUS]`/`[CRITICAL]` 判定は安全ガードによりキャッシュ対象外とし、毎回必ず検査します。
     - 新規パターンの問い合わせ時も、入出力双方で Markdown 装飾・冗長な挨拶・JSON インデント空白を省いたプレーンテキスト形式でやり取りしてトークンを削減します（`[CLEAN]` 判定時は「判定レベル＋1行の簡潔な根拠のみ」の2行出力）。
   - **オフライン / API障害フォールバック**: Gemini API への接続失敗・レート制限超過・タイムアウト時は、ローカルルールによる緊急判定（`[CRITICAL]` / `[SUSPICIOUS]`）へ自動切替し、`alerts/incident_YYYYMMDD.md` への記録、トレイ通知・色変化、Microsoft Defender 緊急スキャン通報、CRITICAL迎撃ダイアログ表示を途切れさせません（`--offline` オプションによる完全オフライン監視も可能）。
   - **トークン最適化（Trimming）**: 生のイベントXML全体は送信せず、重要8フィールド（`UtcTime`, `ProcessId`, `Image`, `CommandLine`, `ParentProcessId`, `ParentCommandLine`, `DestinationIp`, `DestinationPort`）のみをコンパクト JSON 形式のプレーンテキストプロンプトで渡します。
   - **自律調査ツール（完全Read-Only）**:
     - `get_parent_process(parent_process_id: int) -> dict`: 親プロセスの実行イメージとコマンドラインを取得。
     - `get_process_network_activity(process_id: int) -> list[dict]`: 対象プロセスが行った外部通信（Sysmon ID 3）およびDNSクエリ（ID 22）を取得。
     - `get_process_related_events(process_id: int) -> list[dict]`: 対象プロセスに関連する注入（ID 8）、LSASSアクセス（ID 10）、ファイル作成（ID 11）、レジストリ変更（ID 12/13）、DNS（ID 22）を一括取得。
   - **ループ上限（`max_depth = 3`）**: 最大3往復で強制的にツール呼び出しを打ち切り、無限ループやAPIトークン浪費を防止します。

3. **【第3層: トリアージ・レポート出力 (`alerts/incident_YYYYMMDD.md`)】**
   - 調査結果を `[CLEAN]`, `[SUSPICIOUS]`, `[CRITICAL]` の3段階で評価し、判定理由・推奨確認事項を箇条書きにしたMarkdownレポートとしてローカルの `alerts/incident_YYYYMMDD.md` に**追記（append）**します。

---

## 2. 前提条件・セットアップ

### 動作環境
- **OS**: Windows 10 / Windows 11 / Windows Server
- **Python**: Python 3.10 以上
- **Sysmon (推奨・拡張設定テンプレート同梱)**:
  - Sysinternals Sysmon が導入され、`Microsoft-Windows-Sysmon/Operational` チャネルにイベントが記録されていることを推奨します。
  - 拡張イベント（ID `8`, `10`, `11`, `12`, `13`, `22`）を有効化しつつ通常時のノイズを抑えるため、同梱の [sysmon_config.xml](file:///./sysmon_config.xml) を管理者権限の PowerShell から適用できます：
    ```powershell
    sysmon64.exe -c .\sysmon_config.xml
    ```
  - **Sysmon未導入時のフォールバック**: Sysmonが導入されていない環境でもエラー終了せず、自動的に Windows `Security` ログ（Event ID `4688` プロセス作成、および `4624`/`4625`）へフォールバックして動作します。
  - ※ `Security` Event ID `4688` にコマンドライン引数（`CommandLine`）を記録させるには、Windowsのグループポリシー（`監査プロセス作成にコマンド ラインを含める`）を有効化しておくことを推奨します。

### 依存ライブラリのインストール（`uv` を使用）

Python (3.13) のパッケージマネージャ **`uv`** を使用して仮想環境（`.venv`）を作成・インストールすることを推奨します（単体の `pip` コマンドより高速に同期できます）。

```powershell
cd C:\path\to\sysmon-gemini-agent

# 1. 仮想環境 (.venv) の作成
uv venv --python 3.13

# 2. 依存パッケージのインストール
uv pip install -r requirements.txt
```
（※ もし管理者権限の PowerShell で `uv` にパスが通っていない場合は、`& "$env:USERPROFILE\.local\bin\uv.exe"` のようにフルパスで指定してください）

---

## 3. 実行手順

### かんたん起動（`start_agent.ps1` を使用 — 推奨）
[start_agent.ps1](file:///./start_agent.ps1) を実行すると、**①管理者権限への自動昇格（UAC）**、**②`.venv` と依存パッケージの自動確認**、**③Windows 資格情報マネージャーへの API キー未登録時の安全入力・保存**、**④タスクバー常駐（`--tray`）起動** をワンコマンドで行います。

```powershell
cd C:\path\to\sysmon-gemini-agent

# タスクバー常駐モードで起動（デフォルト）
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1

# コンソール画面を閉じてタスクバーアイコンのみでバックグラウンド常駐する場合
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1 -Mode TraySilent

# 1サイクルのみ動作確認する場合
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1 -Mode Once

# Flex ティアの 503/504 を避けて最初から通常処理 (standard) 固定で起動する場合
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1 -StandardTier

# 依存パッケージ (requirements.txt) を明示的に再同期して起動する場合
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1 -SyncDeps
```

---

### 手動でコマンドを実行する場合

#### 手順1: PowerShell を「管理者として実行」で開く
`Security` チャネルおよび `Microsoft-Windows-Sysmon/Operational` チャネルの読み取りには **Windows 管理者権限** が必要です。
スタートメニューから PowerShell を右クリックし、**「管理者として実行」** を選択してください。

### 手順2: Windows 資格情報マネージャーへの API キー登録（推奨）
汎用環境変数 `GEMINI_API_KEY` による他ツールとの競合・露出を防ぐため、通常運用時は **Windows 資格情報マネージャー**（サービス名 `sysmon-gemini-agent` / ユーザー名 `gemini_api_key`）に保存します：

```powershell
.\.venv\Scripts\python.exe -m keyring set sysmon-gemini-agent gemini_api_key
```

一時的なテスト用途で環境変数から上書きしたい場合のみ、プロジェクト固有の環境変数 `SYSMON_GEMINI_API_KEY` を使用できます：

```powershell
$env:SYSMON_GEMINI_API_KEY = "AIzaSy..."
```

使用するモデルを明示的に固定したい場合（デフォルトは `auto` で最新モデルを自動選択）は、環境変数 `GEMINI_MODEL` で切り替え可能です：

```powershell
$env:GEMINI_MODEL = "gemini-4-hydrogen"
```

### 手順3: エージェントの起動

#### 常駐監視モード（デフォルト: 60秒間隔で巡回）
```powershell
cd C:\path\to\sysmon-gemini-agent
.\.venv\Scripts\python.exe main.py
```

#### 1サイクルのみ実行して動作確認する場合（`--once`）
```powershell
.\.venv\Scripts\python.exe main.py --once
```

#### タスクバー（システムトレイ）にアイコンを表示して常駐する場合（`--tray`）
```powershell
.\.venv\Scripts\python.exe main.py --tray
```

#### オフラインルール監視 / 通常ティア固定モード
```powershell
# 完全オフラインルール監視（API不使用）
.\.venv\Scripts\python.exe main.py --tray --offline

# Flex ティアを使用せず通常ティア (standard) のみで実行（503/504回避）
.\.venv\Scripts\python.exe main.py --tray --standard-tier
```
（※ 通常起動時でも、Flex ティアで 503/504 等が連続すると自動的に30分間通常ティアへ退避します。タスクトレイメニュー「サービスティア切替 (Flex / 通常)」からいつでも手動切替・永続化も可能です）
（黒いコンソールウィンドウを出さずにバックグラウンド常駐させたい場合は `.\.venv\Scripts\pythonw.exe main.py --tray` を使用できます）

- **タスクバーアイコンの色変化**:
  - **緑色（チェックマーク）**: 正常監視中（または `[CLEAN]`）
  - **黄色（！マーク）**: `[SUSPICIOUS]`（要注意イベント検知）
  - **赤色（！マーク）**: **`[CRITICAL]`（深刻な脅威検知）** または **重大なエラー（管理者権限不足・APIキー未設定・通信障害等）発生時**（デスクトップ通知も同時に表示されます）
- **右クリックメニュー**:
  - 「今すぐ巡回を実行」
  - 「直近のCRITICAL迎撃パネル (Suspend/Kill) を開く」
  - 「許可リスト (`allowlist.json`) を開く」
  - 「アラート出力フォルダ (`alerts`) を開く」
  - 「実行ログ (`agent_runtime.log`) を開く」
  - 「アイコンを正常色（緑）にリセット」
  - 「安全に終了 (`Exit`)」（チェックポイントを保存して停止）

### OS 標準防御設定（LSA 保護・メモリ整合性・ASR ルール）の確認と段階的有効化
```powershell
# 現在の LSA 保護 / メモリ整合性 (HVCI) / ASR 12ルールの状態を確認 (Read-Only)
.\.venv\Scripts\python.exe main.py --posture-check
powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode Audit

# ASR 推奨12ルールを「監査モード (AuditMode)」で安全に有効化（UAC昇格して実行）
powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode ApplyAudit

# 過去7日間の ASR 監査/ブロックログ (Event ID 1122/1121) で開発ツール等との競合を確認
powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode CheckAsrLogs -Days 7

# 問題なければブロックモードへ昇格（戻す場合は -Mode Rollback）
powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode ApplyBlock
```

---

## 4. 安全上の注意（Safety Constraints）

本エージェントはセキュリティ監視の安全性を最優先し、以下の制約を厳密に遵守して実装されています。

1. **完全読み取り専用（Read-Only）の監視・調査**:
   - Windowsイベントログの消去・変更、OS設定の変更、サービスの停止、プロセスの強制終了（kill）、ファイアウォール遮断などのアクティブな介入は一切行いません。
2. **安全なファイル管理とログ保持制限 (`log_retention.py`)**:
   - OS中枢や作業ディレクトリ外への削除・書換処理は一切含まれていません。
   - ファイル書き込みは `checkpoint.json`、`triage_cache.json`、および `alerts/` 配下への追記に限定されています。
   - ディスク枯渇を防ぐため、`alerts/agent_runtime.log` は `RotatingFileHandler`（5 MB × 最大 5 世代）で自動ローテーションし、`alerts/incident_YYYYMMDD.md` は保持期間 30 日・`alerts/` 合計 100 MB 上限で古い日付の過去ファイルのみを自動整理します（当日分は保護）。
3. **API浪費・無限ループ防止**:
   - 一次スクリーニングを通過した不審イベントのみをGeminiに送信し、Function Calling の最大往復回数を `max_depth = 3` にハードリミットしています。
   - APIレート制限（HTTP 429 / `ResourceExhausted`）発生時は指数バックオフ（Exponential Backoff）により自動待機・リトライを行います。

---

## 5. ファイル構成

| ファイル名 | 役割 |
| :--- | :--- |
| `config.py` | 監視対象チャネル・イベントID、一次フィルタ用キーワード、Geminiモデル、`MAX_DEPTH = 3`、キャッシュ/ログ保持制限等の設定定義 |
| `allowlist.py` | ホットリロード対応の許可リスト (`allowlist.json`) 判定・高危険イベント安全ガード・GUI登録ロジック |
| `triage_cache.py` | `[CLEAN]` 判定パターンの正規化フィンガープリント生成・24時間永続キャッシュ (`triage_cache.json`) 管理 |
| `log_retention.py` | `alerts/incident_YYYYMMDD.md` の保持期間（30日）・合計容量上限（100 MB）に基づく安全な自動整理 |
| `event_reader.py` | `pywin32` (`win32evtlog`) によるイベント取得、`xml.etree.ElementTree` によるXMLパース、一次スクリーニング、`checkpoint.json` 管理 |
| `tools.py` | Gemini Function Calling 用 Read-Only ツール関数（`get_parent_process`, `get_process_network_activity`, `get_process_related_events`） |
| `agent.py` | 公式 `google-genai` SDK による自律調査ループ（`max_depth = 3` 制御、指数バックオフ、オフライン/API障害フォールバック、`alerts/incident_YYYYMMDD.md` 追記出力） |
| `main.py` | 定期巡回デーモン（デフォルト15秒間隔）のメインエントリーポイント・管理者権限チェック・`--tray` / `--offline` / `--version` 起動対応 |
| `tray_app.py` | タスクバー（システムトレイ）常駐アイコン表示・状態別の色変化（緑／黄／赤）・右クリックメニュー制御 |
| `process_guard.py` | `[CRITICAL]` 時のプロセス生存確認・同一性照合（PID＋実行ファイル名＋起動時刻）・Defender連携・ワンクリック迎撃パネル（Suspend / Resume / Kill） |
| `sysmon_config.xml` | 拡張イベント ID (`1, 3, 8, 10, 11, 12, 13, 14, 22`) を低ノイズで収集する Sysmon 設定テンプレート |
| `start_agent.ps1` | 自動管理者昇格（UAC）・仮想環境確認・APIキー設定・起動モード切替を行う PowerShell ランチャー |
| `CHANGELOG.md` | バージョン履歴（`1.00`〜）管理ファイル |
| `README.md` | 実行手順・前提条件・安全設計ドキュメント |
