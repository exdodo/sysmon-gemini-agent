<#
.SYNOPSIS
    OS エンドポイント防御姿勢確認＆安全ハードニングスクリプト (harden_endpoint.ps1)

.DESCRIPTION
    Windows 標準のエンドポイント防御設定を確認・段階的に有効化します：
    1. LSA 保護 (Local Security Authority / RunAsPPL)
    2. コア分離 - メモリ整合性 (HVCI)
    3. Microsoft Defender 改ざん防止 (Tamper Protection)
    4. 攻撃面の縮小 (ASR) 推奨 12 ルール（安全のため監査モード AuditMode から導入可能）

    ※ PowerShell 7 (pwsh) では ConfigDefender モジュールが WinRM 制約で失敗する場合があるため、
       必ず Windows PowerShell 5.1 (powershell.exe) で実行してください（UAC昇格時も powershell.exe を使用）。

.PARAMETER Mode
    - "Audit"        : 現在の設定状態を Read-Only で確認（デフォルト・管理者不要）
    - "ApplyAudit"   : 推奨 12 ASR ルールを「監査モード (AuditMode)」で有効化（既存 Block/Warn は維持）
    - "CheckAsrLogs" : 過去 N 日間の ASR 監査/ブロックログ (Event ID 1122 / 1121) を集計表示
    - "ApplyBlock"   : 監査ログ確認後、推奨 ASR ルールを「ブロックモード (Enabled)」へ昇格
    - "Rollback"     : 推奨 ASR ルールを無効化 (Disabled) へ戻す

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode Audit
    powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode ApplyAudit
    powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode CheckAsrLogs -Days 7
    powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode ApplyBlock
#>

param(
    [ValidateSet("Audit", "ApplyAudit", "ApplyBlock", "CheckAsrLogs", "Rollback")]
    [string]$Mode = "Audit",

    [int]$Days = 7,

    [switch]$EnableLsa,

    [switch]$EnableHvci,

    [string[]]$ExcludeRuleIds = @(),

    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Microsoft Learn 公式 GUID に基づく推奨 ASR 12 ルール
$RecommendedAsrRules = @(
    @{ Id = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"; Name = "LSASS からの資格情報窃取をブロック" },
    @{ Id = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"; Name = "難読化された可能性のあるスクリプトの実行をブロック" },
    @{ Id = "e6db77e5-3df2-4cf1-b95a-636979351e5b"; Name = "WMI イベントサブスクリプションによる永続化をブロック" },
    @{ Id = "d3e037e1-3eb8-44c8-a917-57927947596d"; Name = "JS / VBScript によるダウンロード済み実行コンテンツの起動をブロック" },
    @{ Id = "c1db55ab-c21a-4637-bb3f-a12568109d35"; Name = "ランサムウェアに対する高度な保護を使用" },
    @{ Id = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"; Name = "メールクライアント / Web メールからの実行可能コンテンツをブロック" },
    @{ Id = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"; Name = "すべての Office アプリによる子プロセスの作成をブロック" },
    @{ Id = "3b576869-a4ec-4529-8536-b80a7769e899"; Name = "Office アプリによる実行可能コンテンツの作成をブロック" },
    @{ Id = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"; Name = "Office アプリによる他プロセスへのコード挿入をブロック" },
    @{ Id = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"; Name = "USB から実行される信頼されていない未署名プロセスをブロック" },
    @{ Id = "26190899-1602-49e8-8b27-eb1d0a1ce869"; Name = "Office 通信アプリによる子プロセスの作成をブロック" },
    @{ Id = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"; Name = "Office マクロからの Win32 API 呼び出しをブロック" }
)

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevate {
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-NoExit",
        "-File", "`"$PSCommandPath`"",
        "-Mode", $Mode,
        "-Days", $Days
    )
    if ($EnableLsa) { $argList += "-EnableLsa" }
    if ($EnableHvci) { $argList += "-EnableHvci" }
    if ($Force) { $argList += "-Force" }
    if ($ExcludeRuleIds -and $ExcludeRuleIds.Count -gt 0) {
        $argList += "-ExcludeRuleIds"
        $argList += ($ExcludeRuleIds -join ",")
    }
    Write-Host "[情報] 設定変更のため管理者権限の Windows PowerShell 5.1 (powershell.exe) で再起動します..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList
    exit 0
}

function Get-RegistryValuesSafe {
    param([string]$Path)
    $dict = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $dict
    }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($name in $item.GetValueNames()) {
            $dict[$name] = $item.GetValue($name)
        }
    } catch {
        # 読み取り不可時は空辞書を返す
    }
    return $dict
}

function Get-MergedAsrStateMap {
    $map = @{}
    $localReg = Get-RegistryValuesSafe "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    foreach ($k in $localReg.Keys) {
        $map[$k.ToLower()] = [int]$localReg[$k]
    }
    $policyReg = Get-RegistryValuesSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    foreach ($k in $policyReg.Keys) {
        $map[$k.ToLower()] = [int]$policyReg[$k]
    }
    return $map
}

function Format-AsrActionLabel {
    param([int]$Action)
    switch ($Action) {
        1 { return "Block (有効)" }
        2 { return "Audit (監査)" }
        6 { return "Warn  (警告)" }
        default { return "未設定/無効" }
    }
}

function Show-PostureAudit {
    $ntVals = Get-RegistryValuesSafe "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $lsaVals = Get-RegistryValuesSafe "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $hvciVals = Get-RegistryValuesSafe "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $featVals = Get-RegistryValuesSafe "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
    $asrMap = Get-MergedAsrStateMap

    $runAsPpl = if ($lsaVals.ContainsKey("RunAsPPL")) { [int]$lsaVals["RunAsPPL"] } else { 0 }
    $runAsPplBoot = if ($lsaVals.ContainsKey("RunAsPPLBoot")) { [int]$lsaVals["RunAsPPLBoot"] } else { 0 }
    $hvciEnabled = if ($hvciVals.ContainsKey("Enabled")) { [int]$hvciVals["Enabled"] } else { 0 }
    $tamperVal = if ($featVals.ContainsKey("TamperProtection")) { [int]$featVals["TamperProtection"] } else { -1 }

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host " Windows エンドポイント防御姿勢チェック (Read-Only)" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host (" OS             : {0} ({1} / {2} / Build {3})" -f $ntVals["ProductName"], $ntVals["EditionID"], $ntVals["DisplayVersion"], $ntVals["CurrentBuild"])

    if ($runAsPpl -in @(1, 2) -and $runAsPplBoot -in @(1, 2)) {
        Write-Host (" LSA保護        : 有効・稼働中 (RunAsPPL={0}, RunAsPPLBoot={1})" -f $runAsPpl, $runAsPplBoot) -ForegroundColor Green
    } elseif ($runAsPpl -in @(1, 2)) {
        Write-Host (" LSA保護        : 設定済み・再起動待ち (RunAsPPL={0}, RunAsPPLBoot={1})" -f $runAsPpl, $runAsPplBoot) -ForegroundColor Yellow
    } else {
        Write-Host (" LSA保護        : 未設定/無効 (RunAsPPL={0})" -f $runAsPpl) -ForegroundColor Red
    }

    if ($hvciEnabled -eq 1) {
        Write-Host " メモリ整合性   : 有効 (HVCI Enabled=1)" -ForegroundColor Green
    } else {
        Write-Host " メモリ整合性   : 未設定/無効 (HVCI Enabled=0)" -ForegroundColor Red
    }

    if ($tamperVal -eq 1) {
        Write-Host " 改ざん防止     : 有効 (TamperProtection=1)" -ForegroundColor Green
    } else {
        Write-Host " 改ざん防止     : 無効または確認不可" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "--- Microsoft Defender ASR 推奨 12 ルール ---" -ForegroundColor Cyan
    $enabledCount = 0
    $i = 1
    foreach ($rule in $RecommendedAsrRules) {
        $gid = $rule.Id.ToLower()
        $act = if ($asrMap.ContainsKey($gid)) { [int]$asrMap[$gid] } else { 0 }
        if ($act -in @(1, 2, 6)) { $enabledCount++ }
        $label = Format-AsrActionLabel -Action $act
        $color = if ($act -eq 1) { "Green" } elseif ($act -in @(2, 6)) { "Yellow" } else { "DarkGray" }
        Write-Host (" {0,2}. [{1,-12}] {2}  {3}" -f $i, $label, $gid, $rule.Name) -ForegroundColor $color
        $i++
    }
    Write-Host ("-----------------------------------------------------------------`n 集計: {0} / {1} ルール有効`n" -f $enabledCount, $RecommendedAsrRules.Count)
}

function Invoke-CheckAsrLogs {
    Write-Host ("[ASRログ確認] 過去 {0} 日間の Event ID 1122 (監査) / 1121 (ブロック) を確認中..." -f $Days) -ForegroundColor Cyan
    $startTime = (Get-Date).AddDays(-[math]::Abs($Days))
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-Windows Defender/Operational"
            Id        = @(1121, 1122)
            StartTime = $startTime
        } -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -match "No events were found") {
            Write-Host "[結果] 過去 $Days 日間に ASR イベント (1121/1122) は記録されていません（競合・誤検知なし）。" -ForegroundColor Green
            return
        }
        Write-Warning "Defender Operational ログの取得に失敗しました（管理者権限が必要な場合があります）: $($_.Exception.Message)"
        return
    }

    Write-Host ("[結果] {0} 件の ASR イベントを検出しました:" -f $events.Count) -ForegroundColor Yellow
    $events | Select-Object -First 25 | ForEach-Object {
        $tag = if ($_.Id -eq 1121) { "BLOCK(1121)" } else { "AUDIT(1122)" }
        $msgOneLine = (($_.Message -replace "\r?\n", " ") -replace "\s+", " ").Trim()
        if ($msgOneLine.Length -gt 140) { $msgOneLine = $msgOneLine.Substring(0, 140) + "..." }
        Write-Host ("  [{0}] {1} : {2}" -f $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $tag, $msgOneLine)
    }
}

function Invoke-ApplyAsrRules {
    param(
        [ValidateSet("AuditMode", "Enabled", "Disabled")]
        [string]$TargetAction
    )
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        Write-Error "ConfigDefender 操作は Windows PowerShell 5.1 (powershell.exe) から実行してください。"
        exit 1
    }

    $excludeSet = @{}
    foreach ($ex in $ExcludeRuleIds) {
        if (-not [string]::IsNullOrWhiteSpace($ex)) {
            $excludeSet[$ex.Trim().ToLower()] = $true
        }
    }

    $asrMap = Get-MergedAsrStateMap
    $needsReboot = $false

    if ($TargetAction -eq "Enabled" -and -not $Force) {
        $ans = Read-Host "推奨 ASR ルールをブロックモード (Enabled) へ昇格します。事前監査は完了していますか？ [y/N]"
        if ($ans -notin @("y", "Y", "yes", "YES")) {
            Write-Host "[中止] ユーザー操作によりキャンセルしました。" -ForegroundColor Yellow
            return
        }
    } elseif ($TargetAction -eq "Disabled" -and -not $Force) {
        $ans = Read-Host "推奨 ASR 12 ルールを無効化 (Disabled) します。よろしいですか？ [y/N]"
        if ($ans -notin @("y", "Y", "yes", "YES")) {
            Write-Host "[中止] ユーザー操作によりキャンセルしました。" -ForegroundColor Yellow
            return
        }
    }

    foreach ($rule in $RecommendedAsrRules) {
        $gid = $rule.Id.ToLower()
        if ($excludeSet.ContainsKey($gid)) {
            Write-Host (" [除外] {0} ({1})" -f $gid, $rule.Name) -ForegroundColor DarkGray
            continue
        }
        $currentAct = if ($asrMap.ContainsKey($gid)) { [int]$asrMap[$gid] } else { 0 }
        if ($TargetAction -eq "AuditMode" -and $currentAct -in @(1, 2, 6)) {
            Write-Host (" [維持] 既に設定済みのためスキップ: {0} ({1})" -f $gid, (Format-AsrActionLabel -Action $currentAct)) -ForegroundColor Cyan
            continue
        }
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $gid -AttackSurfaceReductionRules_Actions $TargetAction -ErrorAction Stop
            Write-Host (" [適用] {0} -> {1} ({2})" -f $gid, $TargetAction, $rule.Name) -ForegroundColor Green
        } catch {
            Write-Warning ("ルール {0} の設定に失敗しました: {1}" -f $gid, $_.Exception.Message)
        }
    }

    if ($EnableLsa) {
        $lsaVals = Get-RegistryValuesSafe "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $curPpl = if ($lsaVals.ContainsKey("RunAsPPL")) { [int]$lsaVals["RunAsPPL"] } else { 0 }
        if ($curPpl -notin @(1, 2)) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Type DWord -Value 2
            Write-Host " [適用] LSA 保護 (RunAsPPL=2) を設定しました（再起動後に有効化されます）。" -ForegroundColor Green
            $needsReboot = $true
        } else {
            Write-Host " [維持] LSA 保護 (RunAsPPL=$curPpl) は既に有効です。" -ForegroundColor Cyan
        }
    }

    if ($EnableHvci) {
        $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $hvciVals = Get-RegistryValuesSafe $hvciPath
        $curHvci = if ($hvciVals.ContainsKey("Enabled")) { [int]$hvciVals["Enabled"] } else { 0 }
        if ($curHvci -ne 1) {
            if (-not (Test-Path -LiteralPath $hvciPath)) {
                New-Item -Path $hvciPath -Force | Out-Null
            }
            Set-ItemProperty -Path $hvciPath -Name "Enabled" -Type DWord -Value 1
            Write-Host " [適用] メモリ整合性 (HVCI Enabled=1) を設定しました（再起動後に有効化されます）。" -ForegroundColor Green
            $needsReboot = $true
        } else {
            Write-Host " [維持] メモリ整合性 (HVCI) は既に有効です。" -ForegroundColor Cyan
        }
    }

    if ($needsReboot) {
        Write-Host "`n[注意] LSA 保護 / メモリ整合性の反映には Windows の再起動が必要です。" -ForegroundColor Yellow
    }

    Show-PostureAudit
}

switch ($Mode) {
    "Audit" {
        Show-PostureAudit
    }
    "CheckAsrLogs" {
        Invoke-CheckAsrLogs
    }
    "ApplyAudit" {
        if (-not (Test-IsAdministrator)) { Invoke-SelfElevate }
        Invoke-ApplyAsrRules -TargetAction "AuditMode"
    }
    "ApplyBlock" {
        if (-not (Test-IsAdministrator)) { Invoke-SelfElevate }
        Invoke-ApplyAsrRules -TargetAction "Enabled"
    }
    "Rollback" {
        if (-not (Test-IsAdministrator)) { Invoke-SelfElevate }
        Invoke-ApplyAsrRules -TargetAction "Disabled"
    }
}
