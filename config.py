"""
設定・定数定義モジュール (config.py)

Windows Event Log & Sysmon 監視エージェントの監視対象チャネル、イベントID、
一次スクリーニング用キーワード、Gemini モデル設定、および安全制限パラメータを定義します。
"""

from __future__ import annotations

import os
from pathlib import Path

# ============================================================================
# アプリケーションバージョン定義 (機能追加時に更新し、CHANGELOG.md / Gitタグと同期)
# ============================================================================
APP_VERSION: str = "1.11"

# ============================================================================
# パス設定 (ワークスペース内に閉じた設計・親ディレクトリへのアクセス禁止)
# ============================================================================
BASE_DIR: Path = Path(__file__).resolve().parent
CHECKPOINT_FILE: Path = BASE_DIR / "checkpoint.json"
ALERTS_DIR: Path = BASE_DIR / "alerts"
AGENT_LOG_FILE: Path = ALERTS_DIR / "agent_runtime.log"

# ============================================================================
# 定期巡回・収集設定
# ============================================================================
# 早期検知のため 15 秒間隔で巡回（一次フィルタにより通常時のAPI消費はゼロ）
POLL_INTERVAL_SECONDS: int = 15
MAX_EVENTS_PER_POLL: int = 1000
RECENT_EVENT_CACHE_SIZE: int = 4000

# 監視対象チャネルおよび対象 Event ID
SYSMON_CHANNEL: str = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL: str = "Security"
SYSTEM_CHANNEL: str = "System"

SYSMON_EVENT_IDS: set[int] = {
    1,    # Process Creation (プロセス生成)
    3,    # Network Connection (ネットワーク接続)
    4,    # Sysmon Service State Changed (Sysmonサービス停止・状態変化)
    8,    # CreateRemoteThread (スレッド注入 / DLLインジェクション検知)
    10,   # ProcessAccess (LSASSメモリダンプ・他プロセスへの高権限アクセス検知)
    11,   # FileCreate (スタートアップ・不審フォルダへの実行ファイル/スクリプト生成検知)
    12,   # RegistryEvent (Object create/delete: 永続化・セキュリティ設定変更)
    13,   # RegistryEvent (Value Set: 永続化・IFEO・Defender無効化等の値書換)
    16,   # Sysmon Config State Changed (Sysmon設定変更・改ざん検知)
    22,   # DNSEvent (DNSクエリ・C2/LOLBin名前解決・DNSトンネリング検知)
    255,  # Sysmon Error (Sysmonドライバ・エラー報告)
}

SECURITY_EVENT_IDS: set[int] = {
    1102,  # Audit Log Cleared (セキュリティ監査ログ消去)
    4624,  # Logon Success (ログオン成功)
    4625,  # Logon Failure (ログオン失敗)
    4688,  # Process Creation (プロセス作成 ※Sysmon未導入/停止時フォールバック)
    4719,  # System Audit Policy Changed (監査ポリシー変更・無効化)
}

SYSTEM_EVENT_IDS: set[int] = {
    104,   # Event Log Cleared (Sysmon等イベントログ消去)
    7036,  # Service State Changed (Sysmon / EventLog サービス停止検知)
    7040,  # Service Start Type Changed (Sysmon / EventLog サービス無効化検知)
}

# サービス死活・改ざん検知アラートの再通知クールダウン (秒)
SERVICE_HEARTBEAT_COOLDOWN_SECONDS: int = 600

# ============================================================================
# 第1層: ルールベース一次スクリーニング条件 (低コスト化フィルタ)
# ============================================================================
# コマンドラインに含まれる場合に「不審候補」として抽出するキーワード (小文字で比較)
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "-enc",
    "encodedcommand",
    "bypass",
    "hidden",
    "downloadstring",
    "downloadfile",
    "iex",
    "invoke-expression",
    "invoke-webrequest",
    "certutil -urlcache",
    "certutil.exe -urlcache",
    "rundll32",
    "regsvr32",
    "mshta",
    "bitsadmin",
    "frombase64string",
    "wscript",
    "cscript",
    "vssadmin",
    "wevtutil",
    "fltmc",
    "sysmondrv",
    "sc stop",
    "sc delete",
    "sc config",
    "net stop",
    "clear-winevent",
    "clear-eventlog",
    "auditpol",
    "evtclearlog",
    "mimikatz",
    "sekurlsa",
    "net user ",
    "net localgroup administrators",
)

# 一時ディレクトリ等の不審な実行元パスパターン (小文字で比較)
SUSPICIOUS_TEMP_PATHS: tuple[str, ...] = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
)

# 一時ディレクトリから起動された際に警戒する拡張子
SUSPICIOUS_EXTENSIONS: tuple[str, ...] = (
    ".exe",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".dll",
    ".scr",
    ".msi",
)

# 外部通信 (Sysmon Event ID 3 / 22) で一次スクリーニング対象とする不審プロセス名 (小文字)
SUSPICIOUS_NETWORK_IMAGES: tuple[str, ...] = (
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "wscript.exe",
    "cscript.exe",
    "bitsadmin.exe",
    "curl.exe",
    "notepad.exe",
    "calc.exe",
)

# ============================================================================
# 拡張 Sysmon イベント (ID 8, 10, 11, 12, 13, 22) 一次スクリーニング定義
# ============================================================================
# スレッド注入・プロセスアクセス時に特に警戒する標的プロセス名 (小文字)
HIGH_RISK_TARGET_PROCESSES: frozenset[str] = frozenset(
    {
        "lsass.exe",
        "winlogon.exe",
        "services.exe",
        "svchost.exe",
        "explorer.exe",
        "spoolsv.exe",
        "notepad.exe",
        "calc.exe",
    }
)

# CreateRemoteThread (ID 8) 等でOS標準挙動として除外する信頼済みシステムプロセス名 (小文字)
TRUSTED_SYSTEM_INJECTOR_NAMES: frozenset[str] = frozenset(
    {
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "services.exe",
        "svchost.exe",
        "msmpeng.exe",
        "nissrv.exe",
    }
)

# FileCreate (ID 11) でファイル投下元として警戒するLOLBin・Office系プロセス名 (小文字)
DROPPER_SOURCE_IMAGES: frozenset[str] = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "onenote.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "curl.exe",
    }
)

# FileCreate (ID 11) で永続化・ステージング先として強く警戒するディレクトリパターン (小文字)
PERSISTENCE_FILE_PATHS: tuple[str, ...] = (
    "\\microsoft\\windows\\start menu\\programs\\startup\\",
    "\\windows\\system32\\tasks\\",
    "\\windows\\tasks\\",
)

# FileCreate (ID 11) でランサムノートとして検知するファイル名パターン (小文字)
RANSOMWARE_NOTE_PATTERNS: tuple[str, ...] = (
    "readme_for_decrypt",
    "how_to_decrypt",
    "decrypt_instruction",
    "recover_files",
    "_readme.txt",
    "restore_files",
)

# RegistryEvent (ID 12 / 13) で永続化・セキュリティ無効化として警戒するキーパス (小文字)
CRITICAL_REGISTRY_PATHS: tuple[str, ...] = (
    "\\services\\sysmon",
    "\\services\\eventlog",
    "\\services\\windefend",
    "\\policies\\microsoft\\windows defender",
    "\\image file execution options\\",
    "\\appinit_dlls",
    "\\winlogon\\shell",
    "\\winlogon\\userinit",
    "\\winlogon\\notify",
    "\\control\\lsa\\",
    "\\classes\\mscfile\\shell\\open\\command",
    "\\classes\\ms-settings\\shell\\open\\command",
)

PERSISTENCE_REGISTRY_PATHS: tuple[str, ...] = (
    r"\currentversion\run",
    r"\user shell folders\startup",
    r"\shell folders\startup",
)

# DNSEvent (ID 22) で特に警戒する外部ドメイン・ダイナミックDNS・トンネリング関連パターン (小文字)
SUSPICIOUS_DNS_DOMAINS: tuple[str, ...] = (
    ".onion",
    "pastebin.com",
    "raw.githubusercontent.com",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "duckdns.org",
    "no-ip.com",
    "ddns.net",
    "interact.sh",
    "burpcollaborator.net",
)

# DNSトンネリング判定で誤検知を防ぐための既知CDN/クラウド親ドメイン末尾 (小文字)
BENIGN_LONG_DNS_SUFFIXES: tuple[str, ...] = (
    ".amazonaws.com",
    ".cloudfront.net",
    ".akamaiedge.net",
    ".akadns.net",
    ".azureedge.net",
    ".trafficmanager.net",
    ".microsoft.com",
    ".office.com",
    ".windowsupdate.com",
    ".googleapis.com",
    ".google.com",
    ".1e100.net",
)

# ============================================================================
# 第2層: Google Gemini 自律調査ループ設定
# ============================================================================
# デフォルトモデル設定:
# "auto" の場合、起動時および定期的に client.models.list() から
# 利用可能な最新の軽量・高速モデル (例: gemini-4-hydrogen / gemini-*-flash) を自動選択します。
# 特定モデルを固定したい場合は環境変数 GEMINI_MODEL にモデル名を設定してください。
GEMINI_MODEL: str = os.environ.get("GEMINI_MODEL", "").strip() or "auto"

# API未接続時や models.list() 取得失敗時に使用する安全フォールバック既定モデル
DEFAULT_FALLBACK_MODEL: str = "gemini-4-hydrogen"

# 自動モデル更新チェック間隔（秒）: 常駐監視中に新モデルへ自動追従 (6時間 = 21600秒)
MODEL_REFRESH_INTERVAL_SECONDS: int = 21600

# モデル名 404 NOT_FOUND 時の自動フォールバック候補リスト
FALLBACK_GEMINI_MODELS: tuple[str, ...] = (
    "gemini-4-hydrogen",
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-2.5-flash",
)

# ループ上限（必須）: 最大3往復で強制打ち切り（無限ループ・API浪費の防止）
MAX_DEPTH: int = 3

# トークン最適化（Trimming）でGeminiへ渡す抽出フィールド一覧
TRIMMED_EVENT_FIELDS: tuple[str, ...] = (
    "UtcTime",
    "ProcessId",
    "Image",
    "CommandLine",
    "ParentProcessId",
    "ParentCommandLine",
    "DestinationIp",
    "DestinationPort",
)

# API レート制限 (429 / ResourceExhausted) および通信障害時の Exponential Backoff 設定
MAX_API_RETRIES: int = 4
INITIAL_BACKOFF_SECONDS: float = 2.0
BACKOFF_MULTIPLIER: float = 2.0
MAX_BACKOFF_SECONDS: float = 30.0

# オフライン・API障害時に連続リトライ遅延を防ぐサーキットブレーカー再試行クールダウン（秒）
API_OFFLINE_COOLDOWN_SECONDS: int = 60

# ============================================================================
# 第3層: トリアージ評価レベル定義
# ============================================================================
SEVERITY_CLEAN: str = "[CLEAN]"
SEVERITY_SUSPICIOUS: str = "[SUSPICIOUS]"
SEVERITY_CRITICAL: str = "[CRITICAL]"
VALID_SEVERITIES: tuple[str, ...] = (
    SEVERITY_CLEAN,
    SEVERITY_SUSPICIOUS,
    SEVERITY_CRITICAL,
)

# ============================================================================
# Microsoft Defender 自動緊急スキャン通報設定
# ============================================================================
# 同一ファイルに対する多重スキャン負荷を防ぐクールダウン秒数 (10分 = 600秒)
DEFENDER_SCAN_COOLDOWN_SECONDS: int = 600
DEFENDER_SCAN_TIMEOUT_SECONDS: int = 30

# ============================================================================
# ワンクリック迎撃 (Suspend / Kill) 時の絶対保護プロセス一覧 (小文字)

# OS中枢プロセス・監視基盤・開発環境は誤停止によるシステム停止やロックアウトを防ぐため除外
# ============================================================================
PROTECTED_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "winlogon.exe",
        "dwm.exe",
        "explorer.exe",
        "taskmgr.exe",
        "sysmon.exe",
        "sysmon64.exe",
        "msmpeng.exe",
        "securityhealthservice.exe",
        "antigravity.exe",
        "code.exe",
        "conhost.exe",
        "windowsterminal.exe",
    }
)
