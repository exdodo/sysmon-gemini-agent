<#
.SYNOPSIS
    Windows Event Log & Sysmon 監視エージェント (Google Gemini版) 起動スクリプト (start_agent.ps1)

.DESCRIPTION
    1. 管理者権限でない場合は自動的にUAC昇格（管理者として再起動）を行います。
    2. 仮想環境 (.venv) および依存パッケージ (requirements.txt) を uv で自動確認します。
    3. 環境変数 GEMINI_API_KEY が未設定の場合は入力プロンプトを表示し、ユーザー環境変数へ保存できます。
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

    [int]$Interval = 15
)

$ErrorActionPreference = "Stop"

# スクリプト配置ディレクトリへ移動
$ProjectDir = $PSScriptRoot
Set-Location -LiteralPath $ProjectDir

# ============================================================================
# 1. GEMINI_API_KEY 環境変数の事前確認（昇格前にチェック）
# ============================================================================
if ([string]::IsNullOrWhiteSpace($env:GEMINI_API_KEY)) {
    $savedUserKey = [Environment]::GetEnvironmentVariable("GEMINI_API_KEY", "User")
    $savedMachineKey = [Environment]::GetEnvironmentVariable("GEMINI_API_KEY", "Machine")

    if (-not [string]::IsNullOrWhiteSpace($savedUserKey)) {
        $env:GEMINI_API_KEY = $savedUserKey
    } elseif (-not [string]::IsNullOrWhiteSpace($savedMachineKey)) {
        $env:GEMINI_API_KEY = $savedMachineKey
    }
}

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

    # APIキーが既に保存されており、ウィンドウ非表示のTrayモードであれば昇格ウィンドウも最小限にする
    if (($Mode -in @("Tray", "TraySilent")) -and (-not [string]::IsNullOrWhiteSpace($env:GEMINI_API_KEY))) {
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
$UvPath = "C:\Users\Yusuke\.local\bin\uv.exe"
if (-not (Test-Path -LiteralPath $UvPath)) {
    $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
    if ($uvCmd) {
        $UvPath = $uvCmd.Source
    } else {
        Write-Error "uv.exe が見つかりません。パスを確認してください: $UvPath"
        Read-Host "Enter キーを押して終了します"
        exit 1
    }
}

$VenvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
$VenvPythonw = Join-Path $ProjectDir ".venv\Scripts\pythonw.exe"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Host "[セットアップ] 仮想環境 (.venv) を作成しています..." -ForegroundColor Green
    & $UvPath venv --python 3.13
}

# 必須パッケージ (pystray, Pillow, psutil, google-genai, pywin32 等) を uv で高速同期
$prevErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $UvPath pip install -r (Join-Path $ProjectDir "requirements.txt") --quiet
$ErrorActionPreference = $prevErrorAction

# ============================================================================
# 4. GEMINI_API_KEY 未設定時の対話入力
# ============================================================================
if ([string]::IsNullOrWhiteSpace($env:GEMINI_API_KEY)) {
    Write-Host ""
    Write-Host "[設定] 環境変数 GEMINI_API_KEY が設定されていません。" -ForegroundColor Yellow
    $inputKey = Read-Host "Gemini API キーを入力してください"
    if ([string]::IsNullOrWhiteSpace($inputKey)) {
        Write-Error "GEMINI_API_KEY が入力されなかったため終了します。"
        Read-Host "Enter キーを押して終了します"
        exit 1
    }
    $env:GEMINI_API_KEY = $inputKey.Trim()

    # バックグラウンドの pythonw.exe からも確実に参照できるようユーザー環境変数へ保存
    [Environment]::SetEnvironmentVariable("GEMINI_API_KEY", $env:GEMINI_API_KEY, "User")
    Write-Host "[完了] ユーザー環境変数に GEMINI_API_KEY を保存しました（次回から入力不要です）。" -ForegroundColor Green
}

# ============================================================================
# 5. エージェントの起動
# ============================================================================
$MainPy = Join-Path $ProjectDir "main.py"

switch ($Mode) {
    { $_ -in @("Tray", "TraySilent") } {
        # pythonw.exe を使い、PowerShell の黒い画面を残さずタスクバーアイコンのみで常駐
        Start-Process -FilePath $VenvPythonw -ArgumentList @("`"$MainPy`"", "--tray", "--interval", "$Interval") -WorkingDirectory $ProjectDir -WindowStyle Hidden
        Write-Host "[起動完了] バックグラウンドでタスクバー常駐を開始しました（黒い画面は自動的に閉じます）。" -ForegroundColor Green
        exit 0
    }
    "TrayConsole" {
        Write-Host "[起動] タスクバー常駐 + コンソール表示モードで起動します..." -ForegroundColor Green
        & $VenvPython $MainPy --tray --interval $Interval
    }
    "Console" {
        Write-Host "[起動] コンソール常駐モードで起動します (Ctrl+C で安全に停止)..." -ForegroundColor Green
        & $VenvPython $MainPy --interval $Interval
    }
    "Once" {
        Write-Host "[起動] 1サイクル動作確認モード (--once) で実行します..." -ForegroundColor Green
        & $VenvPython $MainPy --once
        Write-Host ""
        Read-Host "実行が完了しました。Enter キーを押してウィンドウを閉じます"
    }
}
