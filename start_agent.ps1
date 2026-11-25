<#
.SYNOPSIS
    Windows Event Log & Sysmon 監視エージェント (Google Gemini版) 起動スクリプト (start_agent.ps1)

.DESCRIPTION
    1. 管理者権限でない場合は自動的にUAC昇格（管理者として再起動）を行います。
    2. 仮想環境 (.venv) および依存パッケージ (requirements.txt) を uv で自動確認します。
    3. Windows 資格情報マネージャー (keyring) に API キーが未登録の場合は入力プロンプトを表示し、安全に保存できます。
    4. デフォルトで PowerShell の黒い画面を閉じてタスクバーアイコンのみでバックグラウンド常駐 (pythonw.exe) します。

.PARAMETER Mode
    起動モードを指定します:
    - "Tray"       : PowerShellの黒い画面を消してタスクバーアイコンのみでバックグラウンド常駐（デフォルト）
    - "TrayConsole": タスクバーにアイコンを表示しつつ、PowerShellの黒い画面も残してログを表示
    - "Console"    : PowerShellコンソール上で60秒間隔の常駐監視
    - "Once"       : 1サイクルのみ実行して終了（動作確認用）

.EXAMPLE
    .\start_agent.ps1
    .\start_agent.ps1 -Mode TrayConsole
    .\start_agent.ps1 -Mode Once
#>

param(
    [ValidateSet("Tray", "TraySilent", "TrayConsole", "Console", "Once")]
    [string]$Mode = "Tray",

    [int]$Interval = 15,

    [switch]$SyncDeps,

    [switch]$StandardTier
)

$ErrorActionPreference = "Stop"

# スクリプト配置ディレクトリへ移動
$ProjectDir = $PSScriptRoot
Set-Location -LiteralPath $ProjectDir

$KeyringService = "sysmon-gemini-agent"
$KeyringUsername = "gemini_api_key"
$ApiKeyEnvName = "SYSMON_GEMINI_API_KEY"
$VenvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
$VenvPythonw = Join-Path $ProjectDir ".venv\Scripts\pythonw.exe"

function Test-GeminiApiKeyAvailable {
    if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($ApiKeyEnvName, "Process"))) {
        return $true
    }
    if (Test-Path -LiteralPath $VenvPython) {
        try {
            $prevEA = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & $VenvPython -c "import keyring, sys; v = keyring.get_password('$KeyringService', '$KeyringUsername'); sys.exit(0 if (v and v.strip()) else 1)" 2>$null
            $exitCode = $LASTEXITCODE
            $ErrorActionPreference = $prevEA
            return ($exitCode -eq 0)
        } catch {
            return $false
        }
    }
    return $false
}

# ============================================================================
# 1. APIキー設定の事前確認（昇格前にチェック）
# ============================================================================
$HasApiKeyBeforeElevation = Test-GeminiApiKeyAvailable

# ============================================================================
# 2. 管理者権限チェック & 自動昇格 (UAC)
# ============================================================================
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-Mode", $Mode,
        "-Interval", $Interval
    )
    if ($SyncDeps) {
        $argList += "-SyncDeps"
    }
    if ($StandardTier) {
        $argList += "-StandardTier"
    }

    # APIキーが既に登録されており、ウィンドウ非表示のTrayモードであれば昇格ウィンドウも最小限にする
    if (($Mode -in @("Tray", "TraySilent")) -and $HasApiKeyBeforeElevation) {
        Start-Process -FilePath "powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList $argList
    } else {
        Write-Host "[情報] 管理者権限で PowerShell を起動します..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList
    }
    exit 0
}

# ============================================================================
# 3. uv および 仮想環境 (.venv) の準備
# ============================================================================
$UvPath = $null
$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
if ($uvCmd) {
    $UvPath = $uvCmd.Source
} else {
    $fallbackUv = Join-Path $env:USERPROFILE ".local\bin\uv.exe"
    if (Test-Path -LiteralPath $fallbackUv) {
        $UvPath = $fallbackUv
    }
}
if (-not $UvPath) {
    Write-Error "uv.exe が見つかりません。PATH または `$env:USERPROFILE\.local\bin\uv.exe を確認してください。"
    Read-Host "Enter キーを押して終了します"
    exit 1
}

$NeedVenvCreate = -not (Test-Path -LiteralPath $VenvPython)
if ($NeedVenvCreate) {
    Write-Host "[セットアップ] 仮想環境 (.venv) を作成しています..." -ForegroundColor Green
    & $UvPath venv --python 3.13
}

# 管理者権限での不要な毎回パッケージ同期を避け、初回構築時または -SyncDeps 指定時のみ依存同期
if ($NeedVenvCreate -or $SyncDeps) {
    $prevErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $UvPath pip install -r (Join-Path $ProjectDir "requirements.txt") --quiet
    $ErrorActionPreference = $prevErrorAction
}

# ============================================================================
# 4. APIキー未登録時の対話入力（Windows 資格情報マネージャーへ保存）
# ============================================================================
if (-not (Test-GeminiApiKeyAvailable)) {
    Write-Host ""
    Write-Host "[設定] Windows 資格情報マネージャー ($KeyringService) に API キーが登録されていません。" -ForegroundColor Yellow
    $secureKey = Read-Host "Gemini API キーを入力してください（画面には表示されません）" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    try {
        $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    if ([string]::IsNullOrWhiteSpace($plainKey)) {
        Write-Error "API キーが入力されなかったため終了します。"
        Read-Host "Enter キーを押して終了します"
        exit 1
    }

    $trimmedKey = $plainKey.Trim()
    $plainKey = $null
    # コマンドライン引数に残らないよう標準入力経由で Windows 資格情報マネージャーへ保存
    $trimmedKey | & $VenvPython -c "import keyring, sys; keyring.set_password('$KeyringService', '$KeyringUsername', sys.stdin.read().strip())"
    $trimmedKey = $null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Windows 資格情報マネージャーへの API キー保存に失敗しました。"
        Read-Host "Enter キーを押して終了します"
        exit 1
    }
    Write-Host "[完了] Windows 資格情報マネージャー ($KeyringService) に API キーを保存しました（次回から入力不要です）。" -ForegroundColor Green
}

# ============================================================================
# 5. エージェントの起動
# ============================================================================
$MainPy = Join-Path $ProjectDir "main.py"
$TierArgs = @()
if ($StandardTier) {
    $TierArgs += "--standard-tier"
}

switch ($Mode) {
    { $_ -in @("Tray", "TraySilent") } {
        # pythonw.exe を使い、PowerShell の黒い画面を残さずタスクバーアイコンのみで常駐
        $procArgs = @("`"$MainPy`"", "--tray", "--interval", "$Interval") + $TierArgs
        Start-Process -FilePath $VenvPythonw -ArgumentList $procArgs -WorkingDirectory $ProjectDir -WindowStyle Hidden
        Write-Host "[起動完了] バックグラウンドでタスクバー常駐を開始しました（黒い画面は自動的に閉じます）。" -ForegroundColor Green
        exit 0
    }
    "TrayConsole" {
        Write-Host "[起動] タスクバー常駐 + コンソール表示モードで起動します..." -ForegroundColor Green
        & $VenvPython $MainPy --tray --interval $Interval @TierArgs
    }
    "Console" {
        Write-Host "[起動] コンソール常駐モードで起動します (Ctrl+C で安全に停止)..." -ForegroundColor Green
        & $VenvPython $MainPy --interval $Interval @TierArgs
    }
    "Once" {
        Write-Host "[起動] 1サイクル動作確認モード (--once) で実行します..." -ForegroundColor Green
        & $VenvPython $MainPy --once @TierArgs
        Write-Host ""
        Read-Host "実行が完了しました。Enter キーを押してウィンドウを閉じます"
    }
}
