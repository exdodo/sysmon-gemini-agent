# Windows Event Log & Sysmon 監視エージェント (Google Gemini版)

> **Version**: `1.00`（変更履歴は [CHANGELOG.md](file:///C:/Users/Yusuke/.gemini/antigravity/scratch/sysmon-gemini-agent/CHANGELOG.md) を参照）

Windowsイベントログ（`Microsoft-Windows-Sysmon/Operational` および `Security`）を定期巡回し、**ルールベースの一次スクリーニング**と **Google Gemini (`google-genai` SDK) の自律調査ループ（Function Calling）** を組み合わせて、不審なプロセス起動や外部通信の兆候を安全かつ低コストにトリアージする監視エージェントです。

---

## 1. アーキテクチャ概要（3層構造）

1. **【第1層: 収集 & ルールベース一次スクリーニング (`event_reader.py`)】**
   - デフォルト15秒間隔（`POLL_INTERVAL_SECONDS = 15`）の定期巡回ループでイベントログを取得します。
   - `checkpoint.json` に各チャネルの最新処理済み `EventRecordID` を保存し、重複処理を防止します（ログ消去による `EventRecordID` 巻き戻りを検知した場合は自動リセットして即時監視復旧＋改ざんアラートを発報します）。
   - **監視対象ログ**:
     - `Microsoft-Windows-Sysmon/Operational`（Event ID `1`: プロセス生成, `3`: ネットワーク接続, `4`: Sysmonサービス状態変化, `16`: Sysmon設定変更, `255`: エラー）
     - `Security`（Event ID `1102`: 監査ログ消去, `4624`/`4625`: ログオン成否, `4688`: プロセス作成 ※Sysmon未導入/停止時の自動フォールバック, `4719`: 監査ポリシー変更）
     - `System`（Event ID `104`: イベントログ消去, `7036`/`7040`: Sysmon・EventLogサービス停止/無効化）
   - **サービス死活監視（Heartbeat）**: `Sysmon64`/`Sysmon` および `EventLog` サービスの停止・消失を巡回ごとに監視し、Sysmon 停止中は自動で `Security 4688` 監視へ切り替えます。
   - **一次フィルタ（APIコスト最適化）**:
     - すべてのイベントをGeminiに送信せず、難読化・LOLBin悪用・Sysmon/ログ改ざんキーワード（`-enc`, `encodedcommand`, `bypass`, `hidden`, `downloadstring`, `iex`, `certutil -urlcache`, `rundll32`, `fltmc`, `wevtutil`, `sysmon -u/-c`, `sc stop`, `clear-winevent` 等）や一時ディレクトリ（`AppData\Local\Temp` 等）からの起動に合致する「不審候補」のみを抽出します。

2. **【第2層: Gemini 自律調査ループ (`agent.py`, `tools.py`)】**
   - 最新の公式 `google-genai` SDK (`from google import genai` / `client = genai.Client()`) を使用し、デフォルト（`GEMINI_MODEL="auto"`）で起動時および6時間ごとに `client.models.list()` から**その時点で利用可能な最新の軽量・高速モデル（例: `gemini-4-hydrogen` 等）を自動選択**します（404/廃止検知時も自動で後継モデルへ切り替えます）。
   - **トークン最適化（Trimming）**: 生のイベントXML全体は送信せず、重要8フィールド（`UtcTime`, `ProcessId`, `Image`, `CommandLine`, `ParentProcessId`, `ParentCommandLine`, `DestinationIp`, `DestinationPort`）のみを辞書形式でプロンプトに渡します。
   - **自律調査ツール（完全Read-Only）**:
     - `get_parent_process(parent_process_id: int) -> dict`: 親プロセスの実行イメージとコマンドラインを取得。
     - `get_process_network_activity(process_id: int) -> list[dict]`: 対象プロセスが行った外部通信ログ（Sysmon Event ID 3）を取得。
   - **ループ上限（`max_depth = 3`）**: 最大3往復で強制的にツール呼び出しを打ち切り、無限ループやAPIトークン浪費を防止します。

3. **【第3層: トリアージ・レポート出力 (`alerts/incident_YYYYMMDD.md`)】**
   - 調査結果を `[CLEAN]`, `[SUSPICIOUS]`, `[CRITICAL]` の3段階で評価し、判定理由・推奨確認事項を箇条書きにしたMarkdownレポートとしてローカルの `alerts/incident_YYYYMMDD.md` に**追記（append）**します。

---

## 2. 前提条件・セットアップ

### 動作環境
- **OS**: Windows 10 / Windows 11 / Windows Server
- **Python**: Python 3.10 以上
- **Sysmon (推奨)**:
  - Sysinternals Sysmon が導入され、`Microsoft-Windows-Sysmon/Operational` チャネルに Event ID 1（プロセス生成）および Event ID 3（ネットワーク接続）が記録されていることを推奨します。
  - **Sysmon未導入時のフォールバック**: Sysmonが導入されていない環境でもエラー終了せず、自動的に Windows `Security` ログ（Event ID `4688` プロセス作成、および `4624`/`4625`）へフォールバックして動作します。
  - ※ `Security` Event ID `4688` にコマンドライン引数（`CommandLine`）を記録させるには、Windowsのグループポリシー（`監査プロセス作成にコマンド ラインを含める`）を有効化しておくことを推奨します。

### 依存ライブラリのインストール（`uv` を使用）

お使いの環境では Python (3.13) がパッケージマネージャ **`uv`** (`C:\Users\Yusuke\.local\bin\uv.exe`) で管理されているため、単体の `pip` コマンドではなく **`uv`** を使用して仮想環境（`.venv`）を作成・インストールします。

```powershell
cd C:\Users\Yusuke\.gemini\antigravity\scratch\sysmon-gemini-agent

# 1. 仮想環境 (.venv) の作成
uv venv --python 3.13

# 2. 依存パッケージのインストール
uv pip install -r requirements.txt
```
（※ もし管理者権限の PowerShell で `uv` にパスが通っていない場合は、`C:\Users\Yusuke\.local\bin\uv.exe` とフルパスで指定してください）

---

## 3. 実行手順

### かんたん起動（`start_agent.ps1` を使用 — 推奨）
[start_agent.ps1](file:///C:/Users/Yusuke/.gemini/antigravity/scratch/sysmon-gemini-agent/start_agent.ps1) を実行すると、**①管理者権限への自動昇格（UAC）**、**②`.venv` と依存パッケージの自動確認**、**③`GEMINI_API_KEY` 未設定時の入力・保存**、**④タスクバー常駐（`--tray`）起動** をワンコマンドで行います。

```powershell
cd C:\Users\Yusuke\.gemini\antigravity\scratch\sysmon-gemini-agent

# タスクバー常駐モードで起動（デフォルト）
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1

# コンソール画面を閉じてタスクバーアイコンのみでバックグラウンド常駐する場合
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1 -Mode TraySilent

# 1サイクルのみ動作確認する場合
powershell -ExecutionPolicy Bypass -File .\start_agent.ps1 -Mode Once
```

---

### 手動でコマンドを実行する場合

#### 手順1: PowerShell を「管理者として実行」で開く
`Security` チャネルおよび `Microsoft-Windows-Sysmon/Operational` チャネルの読み取りには **Windows 管理者権限** が必要です。
スタートメニューから PowerShell を右クリックし、**「管理者として実行」** を選択してください。

### 手順2: 環境変数 `GEMINI_API_KEY` の設定
APIキーはコード内にハードコードせず、環境変数から読み込みます。

```powershell
$env:GEMINI_API_KEY = "AIzaSy..."
```

使用するモデルを明示的に固定したい場合（デフォルトは `auto` で最新モデルを自動選択）は、環境変数 `GEMINI_MODEL` で切り替え可能です：

```powershell
$env:GEMINI_MODEL = "gemini-4-hydrogen"
```

### 手順3: エージェントの起動

#### 常駐監視モード（デフォルト: 60秒間隔で巡回）
```powershell
cd C:\Users\Yusuke\.gemini\antigravity\scratch\sysmon-gemini-agent
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
（黒いコンソールウィンドウを出さずにバックグラウンド常駐させたい場合は `.\.venv\Scripts\pythonw.exe main.py --tray` を使用できます）

- **タスクバーアイコンの色変化**:
  - **緑色（チェックマーク）**: 正常監視中（または `[CLEAN]`）
  - **黄色（！マーク）**: `[SUSPICIOUS]`（要注意イベント検知）
  - **赤色（！マーク）**: **`[CRITICAL]`（深刻な脅威検知）** または **重大なエラー（管理者権限不足・APIキー未設定・通信障害等）発生時**（デスクトップ通知も同時に表示されます）
- **右クリックメニュー**:
  - 「今すぐ巡回を実行」
  - 「アラート出力フォルダ (`alerts`) を開く」
  - 「アイコンを正常色（緑）にリセット」
  - 「安全に終了 (`Exit`)」（チェックポイントを保存して停止）

---

## 4. 安全上の注意（Safety Constraints）

本エージェントはセキュリティ監視の安全性を最優先し、以下の制約を厳密に遵守して実装されています。

1. **完全読み取り専用（Read-Only）の監視・調査**:
   - Windowsイベントログの消去・変更、OS設定の変更、サービスの停止、プロセスの強制終了（kill）、ファイアウォール遮断などのアクティブな介入は一切行いません。
2. **ファイル破棄処理の完全排除**:
   - ファイルやディレクトリの削除処理、および既存レポートの上書き初期化処理は一切含まれていません。
   - ファイル書き込みは `checkpoint.json`（最新 `EventRecordID` の保存）および `alerts/` 配下へのログ・レポートの**追記（`mode="a"`）**のみに限定されています。
3. **API浪費・無限ループ防止**:
   - 一次スクリーニングを通過した不審イベントのみをGeminiに送信し、Function Calling の最大往復回数を `max_depth = 3` にハードリミットしています。
   - APIレート制限（HTTP 429 / `ResourceExhausted`）発生時は指数バックオフ（Exponential Backoff）により自動待機・リトライを行います。

---

## 5. ファイル構成

| ファイル名 | 役割 |
| :--- | :--- |
| `config.py` | 監視対象チャネル・イベントID、一次フィルタ用キーワード、Geminiモデル、`MAX_DEPTH = 3` 等の設定定義 |
| `event_reader.py` | `pywin32` (`win32evtlog`) によるイベント取得、`xml.etree.ElementTree` によるXMLパース、一次スクリーニング、`checkpoint.json` 管理 |
| `tools.py` | Gemini Function Calling 用 Read-Only ツール関数（`get_parent_process`, `get_process_network_activity`） |
| `agent.py` | 公式 `google-genai` SDK による自律調査ループ（`max_depth = 3` 制御、指数バックオフ、`alerts/incident_YYYYMMDD.md` 追記出力） |
| `main.py` | 定期巡回デーモン（デフォルト15秒間隔）のメインエントリーポイント・管理者権限チェック・`--tray` 起動対応 |
| `tray_app.py` | タスクバー（システムトレイ）常駐アイコン表示・状態別の色変化（緑／黄／赤）・右クリックメニュー制御 |
| `process_guard.py` | `[CRITICAL]` 時のプロセス生存確認・同一性照合（PID＋実行ファイル名＋起動時刻）・ワンクリック迎撃パネル（Suspend / Resume / Kill） |
| `start_agent.ps1` | 自動管理者昇格（UAC）・仮想環境確認・APIキー設定・起動モード切替を行う PowerShell ランチャー |
| `CHANGELOG.md` | バージョン履歴（`1.00`〜）管理ファイル |
| `README.md` | 実行手順・前提条件・安全設計ドキュメント |
