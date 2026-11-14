# Environment & Development Rules

## 1. Python / パッケージ管理 (`uv` の使用)
- このPC環境では `pip` 単体コマンドやグローバルの `python.exe`（Windows Store エイリアス）は使用しないこと。
- Python パッケージ管理および仮想環境（`.venv`）の作成には、必ず **`uv`**（`C:\Users\Yusuke\.local\bin\uv.exe`、Python 3.13）を使用すること。
  - 仮想環境作成: `C:\Users\Yusuke\.local\bin\uv.exe venv --python 3.13`
  - パッケージ追加・インストール: `C:\Users\Yusuke\.local\bin\uv.exe pip install -r requirements.txt`
  - スクリプト実行: `.\.venv\Scripts\python.exe`（コンソールあり）または `.\.venv\Scripts\pythonw.exe`（コンソール非表示）

## 2. PowerShell スクリプト (`.ps1`) の文字コード規約
- Windows 標準の PowerShell 5.1 (`powershell.exe`) での文字化け・構文エラーを防ぐため、日本語を含む `.ps1` ファイルを作成・編集する際は必ず **UTF-8 (BOM付き: `EF BB BF`)** で保存すること。

## 3. Google Gemini SDK & モデル規約
- 公式の最新 SDK `google-genai` (`from google import genai` / `client = genai.Client()`) を使用すること（旧 `google-generativeai` は使用禁止）。
- モデルは `auto`（起動時・6時間ごとの `client.models.list()` による最新モデル自動選択、既定フォールバック `gemini-4-hydrogen`）を基準とし、今後のバージョンアップや提供終了（`404 NOT_FOUND` 等）で使用できなくなった場合は、APIのエラーメッセージで案内される後継モデルや `client.models.list()` から取得できる**その時点で利用可能な新しいモデルを自動的に選択・使用する**こと。
- APIキーは環境変数 `GEMINI_API_KEY` から読み込むこと（コード内へのハードコード禁止）。
- AIを利用するモジュールでは以下を必ず実装・維持すること：
  1. デフォルト `GEMINI_MODEL="auto"` による起動時・定期的な `client.models.list()` からの最新モデル自動選択（未接続時は既定フォールバック `gemini-4-hydrogen` で継続、環境変数 `GEMINI_MODEL` による明示固定にも対応）。
  2. 画像・Embedding・音声・Live系を除外し、`generateContent` 対応の汎用テキストモデルを「安定版優先 → 数値バージョン降順 → 軽量高速ティア（`hydrogen` / `flash` 等）優先」で順位付けすること（将来の命名変更・世代交代にも対応）。
  3. `404` / `deprecated` / `no longer available` 検知時は、API推奨モデル → `models.list()` 再検索 → 静的フォールバック候補の順で即座に切り替え、試行済み除外付きで自動リトライすること。
  4. 実際に選択・使用されたモデル名をログやレポートに出力すること。

## 4. バージョン管理規約
- 現在の基準バージョンは `1.00` とし、`config.py` の `APP_VERSION` で一元管理する。
- 今後、機能追加・仕様変更・重要な修正を行った場合は、**必ずバージョンを上げる**こと（小規模な機能追加・改善: `+0.01` → `1.01`, `1.02`...、大きな機能追加: `+0.10` → `1.10` 等）。
- バージョン更新時は以下の3点を必ずセットで実施する：
  1. `config.py` の `APP_VERSION` を更新する。
  2. `CHANGELOG.md` に変更内容・日付・新バージョンを追記する。
  3. Git で変更をコミットし、対応するバージョンタグ（例: `v1.01`）を付与する（リモートへの `git push` はユーザーの明示的な指示がある場合のみ行う）。
