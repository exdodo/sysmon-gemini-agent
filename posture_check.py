"""
OS 防御姿勢チェックモジュール (posture_check.py)

Windows の以下のハードニング状態を完全 Read-Only（レジストリ参照）で確認し、
レポート出力および単一 Tkinter UI スレッド上の診断ウィンドウを提供します。
1. LSA 保護 (Local Security Authority / RunAsPPL)
2. コア分離 - メモリ整合性 (HVCI / Hypervisor-Enforced Code Integrity)
3. Microsoft Defender 改ざん防止 (Tamper Protection)
4. 攻撃面の縮小 (ASR: Attack Surface Reduction) 推奨 12 ルール
"""

from __future__ import annotations

from collections.abc import Callable
import logging
import os
from pathlib import Path
import subprocess
import threading
from typing import Any

import config
from ui_host import dispatch_to_ui

logger = logging.getLogger("sysmon_gemini_agent.posture_check")

# Microsoft Learn 公式 GUID に基づく推奨 ASR 12 ルール
# (開発環境での誤検知が多い「普及度フィルタ」「PSExec/WMI子プロセス」等は除外)
RECOMMENDED_ASR_RULES: tuple[tuple[str, str], ...] = (
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "LSASS からの資格情報窃取をブロック"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "難読化された可能性のあるスクリプトの実行をブロック"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "WMI イベントサブスクリプションによる永続化をブロック"),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "JS / VBScript によるダウンロード済み実行コンテンツの起動をブロック"),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", "ランサムウェアに対する高度な保護を使用"),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "メールクライアント / Web メールからの実行可能コンテンツをブロック"),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "すべての Office アプリケーションによる子プロセスの作成をブロック"),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Office アプリケーションによる実行可能コンテンツの作成をブロック"),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Office アプリケーションによる他プロセスへのコード挿入をブロック"),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "USB から実行される信頼されていない未署名プロセスをブロック"),
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Office 通信アプリによる子プロセスの作成をブロック"),
    ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Office マクロからの Win32 API 呼び出しをブロック"),
)

ASR_ACTION_LABELS: dict[int, str] = {
    0: "無効 (Disabled)",
    1: "ブロック (Block)",
    2: "監査モード (Audit)",
    6: "警告 (Warn)",
}

_REG_WIN_NT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_REG_LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
_REG_HVCI = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
_REG_DEFENDER_FEATURES = r"SOFTWARE\Microsoft\Windows Defender\Features"
_REG_ASR_LOCAL = r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
_REG_ASR_POLICY = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"

_UI_OPEN_LOCK = threading.Lock()
_UI_IS_OPEN = False


def _default_reg_reader(subkey_path: str) -> dict[str, Any]:
    """HKLM 配下の指定キーの値を Read-Only で辞書として読み取ります。"""
    if os.name != "nt":
        return {}
    import winreg

    result: dict[str, Any] = {}
    try:
        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, access) as key:
            idx = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, idx)
                    result[str(name)] = value
                    idx += 1
                except OSError:
                    break
    except OSError:
        return {}
    return result


def _to_int(val: Any, default: int | None = None) -> int | None:
    if val is None or isinstance(val, bool):
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def collect_endpoint_posture(
    reg_reader: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Windows の LSA 保護・メモリ整合性 (HVCI)・Defender 改ざん防止・ASR 推奨 12 ルールの
    現在状態を完全 Read-Only で収集します。
    """
    reader = reg_reader or _default_reg_reader

    os_vals = reader(_REG_WIN_NT)
    lsa_vals = reader(_REG_LSA)
    hvci_vals = reader(_REG_HVCI)
    feat_vals = reader(_REG_DEFENDER_FEATURES)
    asr_local_vals = reader(_REG_ASR_LOCAL)
    asr_policy_vals = reader(_REG_ASR_POLICY)

    # 1. OS 情報
    os_info = {
        "product_name": str(os_vals.get("ProductName") or ""),
        "edition_id": str(os_vals.get("EditionID") or ""),
        "display_version": str(os_vals.get("DisplayVersion") or ""),
        "current_build": str(os_vals.get("CurrentBuild") or ""),
    }

    # 2. LSA 保護 (RunAsPPL)
    run_as_ppl = _to_int(lsa_vals.get("RunAsPPL"), default=0) or 0
    run_as_ppl_boot = _to_int(lsa_vals.get("RunAsPPLBoot"), default=0) or 0
    if run_as_ppl in (1, 2) and run_as_ppl_boot in (1, 2):
        lsa_status = "ENABLED"
    elif run_as_ppl in (1, 2):
        lsa_status = "REBOOT_PENDING"
    else:
        lsa_status = "DISABLED"

    # 3. コア分離 - メモリ整合性 (HVCI)
    hvci_enabled = _to_int(hvci_vals.get("Enabled"), default=0) or 0
    hvci_was_enabled_by = _to_int(hvci_vals.get("WasEnabledBy"))
    hvci_locked = _to_int(hvci_vals.get("Locked"), default=0) or 0
    hvci_status = "ENABLED" if hvci_enabled == 1 else "DISABLED"

    # 4. Defender 改ざん防止
    tamper_protection = _to_int(feat_vals.get("TamperProtection"))
    if tamper_protection == 1:
        tamper_status = "ENABLED"
    elif tamper_protection == 0:
        tamper_status = "DISABLED"
    else:
        tamper_status = "UNKNOWN"

    # 5. ASR ルール (Local + Policy を結合、Policy 優先)
    merged_asr: dict[str, tuple[int, str]] = {}
    for guid_key, raw_action in asr_local_vals.items():
        act = _to_int(raw_action)
        if act is not None:
            merged_asr[guid_key.strip().lower()] = (act, "local")
    for guid_key, raw_action in asr_policy_vals.items():
        act = _to_int(raw_action)
        if act is not None:
            merged_asr[guid_key.strip().lower()] = (act, "policy")

    asr_rules: list[dict[str, Any]] = []
    block_count = 0
    audit_count = 0
    warn_count = 0
    disabled_count = 0

    for guid, desc in RECOMMENDED_ASR_RULES:
        guid_lower = guid.lower()
        if guid_lower in merged_asr:
            action_code, source = merged_asr[guid_lower]
        else:
            action_code, source = 0, "unset"

        if action_code == 1:
            block_count += 1
        elif action_code == 2:
            audit_count += 1
        elif action_code == 6:
            warn_count += 1
        else:
            disabled_count += 1

        asr_rules.append(
            {
                "guid": guid_lower,
                "description": desc,
                "action": action_code,
                "action_label": ASR_ACTION_LABELS.get(action_code, f"不明 ({action_code})"),
                "source": source,
            }
        )

    return {
        "os": os_info,
        "lsa": {
            "status": lsa_status,
            "run_as_ppl": run_as_ppl,
            "run_as_ppl_boot": run_as_ppl_boot,
        },
        "hvci": {
            "status": hvci_status,
            "enabled": hvci_enabled,
            "was_enabled_by": hvci_was_enabled_by,
            "locked": hvci_locked,
        },
        "tamper_protection": {
            "status": tamper_status,
            "value": tamper_protection,
        },
        "asr": {
            "total_recommended": len(RECOMMENDED_ASR_RULES),
            "block_count": block_count,
            "audit_count": audit_count,
            "warn_count": warn_count,
            "disabled_count": disabled_count,
            "rules": asr_rules,
        },
    }


def format_posture_report(posture: dict[str, Any]) -> str:
    """収集済みの OS 防御姿勢辞書を日本語の診断レポート文字列へ整形します。"""
    os_info = posture["os"]
    lsa = posture["lsa"]
    hvci = posture["hvci"]
    tamper = posture["tamper_protection"]
    asr = posture["asr"]

    lsa_label = {
        "ENABLED": "有効 (稼働中)",
        "REBOOT_PENDING": "設定済み（再起動待ち）",
        "DISABLED": "無効 (未設定)",
    }.get(lsa["status"], lsa["status"])

    hvci_label = "有効 (レジストリ有効)" if hvci["status"] == "ENABLED" else "無効 (未設定)"
    tamper_label = {
        "ENABLED": "有効",
        "DISABLED": "無効",
        "UNKNOWN": "確認不可",
    }.get(tamper["status"], tamper["status"])

    lines = [
        f"=== OS 防御姿勢診断レポート (Sysmon Gemini v{config.APP_VERSION}) ===",
        (
            f"OS           : {os_info.get('product_name') or 'Windows'} "
            f"({os_info.get('edition_id') or '-'} / {os_info.get('display_version') or '-'} "
            f"/ Build {os_info.get('current_build') or '-'})"
        ),
        (
            f"LSA保護      : {lsa_label} "
            f"(RunAsPPL={lsa['run_as_ppl']}, RunAsPPLBoot={lsa['run_as_ppl_boot']})"
        ),
        f"メモリ整合性 : {hvci_label} (HVCI Enabled={hvci['enabled']})",
        f"改ざん防止   : {tamper_label}",
        (
            f"ASR推奨ルール: {asr['block_count'] + asr['audit_count'] + asr['warn_count']} / "
            f"{asr['total_recommended']} 件有効 "
            f"(Block={asr['block_count']}, Audit={asr['audit_count']}, "
            f"Warn={asr['warn_count']}, 未設定/無効={asr['disabled_count']})"
        ),
        "",
        "--- Microsoft Defender ASR 推奨 12 ルール一覧 ---",
    ]

    for idx, rule in enumerate(asr["rules"], start=1):
        lines.append(
            f"{idx:2d}. [{rule['action_label']}] {rule['guid']} - {rule['description']}"
        )

    lines.append("")
    if asr["disabled_count"] > 0 or lsa["status"] == "DISABLED" or hvci["status"] == "DISABLED":
        lines.append("【推奨アクション】")
        lines.append(
            "・安全に監査モードから有効化するには、PowerShell で以下を実行してください:"
        )
        lines.append(
            r"  powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode ApplyAudit"
        )
    elif asr["audit_count"] > 0:
        lines.append("【推奨アクション】")
        lines.append(
            "・監査モードで数日〜1週間ほど誤検知がないか確認してください:"
        )
        lines.append(
            r"  powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode CheckAsrLogs"
        )
        lines.append(
            "・問題なければブロックモードへ昇格できます:"
        )
        lines.append(
            r"  powershell -ExecutionPolicy Bypass -File .\harden_endpoint.ps1 -Mode ApplyBlock"
        )
    else:
        lines.append("【状態】すべての推奨防御項目が有効化されています。")

    return "\n".join(lines)


def _launch_harden_ps1(mode: str) -> None:
    """Windows PowerShell 5.1 (`powershell.exe`) で `harden_endpoint.ps1` を起動します。"""
    ps1_path = config.BASE_DIR / "harden_endpoint.ps1"
    if not ps1_path.is_file():
        logger.warning("harden_endpoint.ps1 が見つかりません: %s", ps1_path)
        return
    try:
        subprocess.Popen(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-NoExit",
                "-File",
                str(ps1_path),
                "-Mode",
                mode,
            ],
            cwd=str(config.BASE_DIR),
        )
    except Exception as exc:
        logger.warning("harden_endpoint.ps1 の起動に失敗しました: %s", exc)


def open_posture_check_dialog_async() -> bool:
    """単一 Tkinter UI スレッド上に OS 防御姿勢チェックウィンドウを開きます。"""
    global _UI_IS_OPEN
    with _UI_OPEN_LOCK:
        if _UI_IS_OPEN:
            return False
        _UI_IS_OPEN = True

    def _release_flag() -> None:
        global _UI_IS_OPEN
        with _UI_OPEN_LOCK:
            _UI_IS_OPEN = False

    def _build_window(parent_root: Any) -> None:
        import tkinter as tk
        from tkinter import messagebox, scrolledtext

        try:
            win = tk.Toplevel(parent_root)
            win.title(f"Sysmon Gemini v{config.APP_VERSION} - OS 防御設定診断 (LSA / HVCI / ASR)")
            win.geometry("820x560")
            win.attributes("-topmost", True)

            def _close() -> None:
                try:
                    win.destroy()
                except Exception:
                    pass
                _release_flag()

            win.protocol("WM_DELETE_WINDOW", _close)

            text_box = scrolledtext.ScrolledText(
                win,
                wrap=tk.WORD,
                font=("Consolas", 9),
                bg="#0F172A",
                fg="#E2E8F0",
                padx=10,
                pady=10,
            )
            text_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=(12, 8))

            def _refresh() -> None:
                report = format_posture_report(collect_endpoint_posture())
                text_box.configure(state=tk.NORMAL)
                text_box.delete("1.0", tk.END)
                text_box.insert(tk.END, report)
                text_box.configure(state=tk.DISABLED)

            def _on_apply_audit() -> None:
                if not messagebox.askyesno(
                    "ASR 監査モード有効化の確認",
                    "Microsoft Defender ASR 推奨 12 ルールを監査モード (AuditMode) で有効化する\n"
                    "管理者 PowerShell スクリプトを起動しますか？\n\n"
                    "※既に Block / Warn に設定済みのルールは変更されません。",
                    parent=win,
                ):
                    return
                _launch_harden_ps1("ApplyAudit")

            btn_frame = tk.Frame(win, padx=12, pady=10)
            btn_frame.pack(fill=tk.X)

            tk.Button(
                btn_frame,
                text="🛡️ ASR を監査モードで有効化",
                bg="#059669",
                fg="#FFFFFF",
                font=("Meiryo UI", 9, "bold"),
                padx=10,
                pady=6,
                command=_on_apply_audit,
            ).pack(side=tk.LEFT, padx=(0, 8))

            tk.Button(
                btn_frame,
                text="📋 ASR 監査ログ確認",
                bg="#2563EB",
                fg="#FFFFFF",
                font=("Meiryo UI", 9, "bold"),
                padx=10,
                pady=6,
                command=lambda: _launch_harden_ps1("CheckAsrLogs"),
            ).pack(side=tk.LEFT, padx=(0, 8))

            tk.Button(
                btn_frame,
                text="🔄 再読込",
                padx=10,
                pady=6,
                command=_refresh,
            ).pack(side=tk.LEFT)

            tk.Button(
                btn_frame,
                text="閉じる",
                padx=12,
                pady=6,
                command=_close,
            ).pack(side=tk.RIGHT)

            _refresh()
        except Exception as exc:
            logger.error("OS 防御設定診断ウィンドウの構築に失敗しました: %s", exc)
            _release_flag()

    if not dispatch_to_ui(_build_window):
        _release_flag()
        return False
    return True
