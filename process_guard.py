"""
プロセス生存確認・同一性照合・Microsoft Defender 自動通報・ワンクリック迎撃モジュール (process_guard.py)

[CRITICAL] 判定時に以下の安全手順を提供します:
1. 対象プロセスが現在も生存しているか確認 (Read-Only)
2. PIDの再利用による誤爆 (TOCTOU) を防ぐため、「PID + 実行ファイル名 + プロセス開始時刻」の3点を厳密照合
3. OS重要プロセスや監視エージェント自身を保護リストで除外
4. Microsoft Defender (MpCmdRun.exe) へ実行ファイルおよびコマンドライン内のスクリプトを非同期で緊急スキャン通報
   (10分間のクールダウン重複排除・30秒タイムアウト付き)
5. 自動ではプロセス停止せず、ユーザーが確認ダイアログ上でボタンを押した時のみ Suspend (凍結) / Resume (再開) / Kill (強制終了) を実行
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import glob
import logging
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext
from typing import Any

import allowlist
import config
from event_reader import NormalizedEvent

logger = logging.getLogger("sysmon_gemini_agent.process_guard")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = False

# Microsoft Defender スキャンのクールダウン管理辞書 {正規化ファイルパス: 最終スキャン時刻(monotonic)}
_DEFENDER_SCAN_HISTORY: dict[str, float] = {}
_DEFENDER_LOCK = threading.Lock()

# コマンドライン文字列からファイルパスを抽出する正規表現
_WIN_PATH_PATTERN = re.compile(
    r'([a-zA-Z]:\\[^"\'\r\n<>|?*]+?\.(?:exe|dll|ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta|scr|msi|jar|py))',
    re.IGNORECASE,
)


@dataclass(slots=True)
class ProcessVerificationResult:
    """プロセスの生存確認および同一性照合の結果を保持するデータクラス。"""

    pid: int | None
    is_alive: bool
    is_verified_same_process: bool
    is_protected: bool
    process_name: str = ""
    exe_path: str = ""
    create_time_utc: str = ""
    status: str = ""
    reason: str = ""


def _parse_event_utc_timestamp(utc_str: str) -> float | None:
    """
    Sysmon (例: '2026-11-10 03:20:15.123') または ISO8601 ('2026-11-10T03:20:15.123456Z') の
    UTC時刻文字列を UNIX エポック秒 (float) に変換します。
    """
    if not utc_str:
        return None
    cleaned = utc_str.strip()
    try:
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        if "T" in cleaned:
            if "." in cleaned and "+" in cleaned:
                main_part, tz_part = cleaned.split("+", 1)
                sec_part, frac_part = main_part.split(".", 1)
                cleaned = f"{sec_part}.{frac_part[:6]}+{tz_part}"
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        else:
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
                    return dt.timestamp()
                except ValueError:
                    continue
    except Exception:
        return None
    return None


def verify_target_process(
    pid: int | None,
    expected_image: str,
    event_utc_time: str = "",
) -> ProcessVerificationResult:
    """
    指定された PID が現在も生存しており、かつイベント発生時のプロセスと同一であるかを
    「PID + 実行ファイル名 + 起動時刻」の3点で厳密に照合します。
    """
    if not pid or pid <= 4:
        return ProcessVerificationResult(
            pid=pid,
            is_alive=False,
            is_verified_same_process=False,
            is_protected=True,
            reason="有効なプロセスIDではないか、システムカーネルプロセスです。",
        )

    if not HAS_PSUTIL or psutil is None:
        return ProcessVerificationResult(
            pid=pid,
            is_alive=False,
            is_verified_same_process=False,
            is_protected=False,
            reason="psutil がインストールされていないため生存確認を実行できません。",
        )

    my_pid = os.getpid()
    my_ppid = os.getppid()
    if pid in (my_pid, my_ppid):
        return ProcessVerificationResult(
            pid=pid,
            is_alive=True,
            is_verified_same_process=True,
            is_protected=True,
            reason="監視エージェント自身のプロセスのため保護されています。",
        )

    try:
        if not psutil.pid_exists(pid):
            return ProcessVerificationResult(
                pid=pid,
                is_alive=False,
                is_verified_same_process=False,
                is_protected=False,
                reason=f"PID {pid} は既に終了しています（現在稼働していません）。",
            )

        proc = psutil.Process(pid)
        proc_name = proc.name() or ""
        try:
            proc_exe = proc.exe() or ""
        except (psutil.AccessDenied, psutil.ZombieProcess):
            proc_exe = proc_name

        proc_status = proc.status()
        create_ts = proc.create_time()
        create_utc_str = datetime.fromtimestamp(create_ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]

    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return ProcessVerificationResult(
            pid=pid,
            is_alive=False,
            is_verified_same_process=False,
            is_protected=False,
            reason=f"PID {pid} は既に終了しています。",
        )
    except psutil.AccessDenied:
        return ProcessVerificationResult(
            pid=pid,
            is_alive=True,
            is_verified_same_process=False,
            is_protected=True,
            reason=f"PID {pid} は生存していますが、OS保護プロセスによりアクセスが拒否されました。",
        )

    # 1. 実行ファイル名 (Image) の一致照合
    expected_basename = (expected_image or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    actual_basename = proc_name.lower()
    actual_exe_basename = proc_exe.replace("/", "\\").rsplit("\\", 1)[-1].lower()

    if expected_basename and expected_basename not in (actual_basename, actual_exe_basename):
        return ProcessVerificationResult(
            pid=pid,
            is_alive=True,
            is_verified_same_process=False,
            is_protected=True,
            process_name=proc_name,
            exe_path=proc_exe,
            create_time_utc=create_utc_str,
            status=proc_status,
            reason=(
                f"【誤爆防止】PID {pid} は現在 '{proc_name}' に再利用されています "
                f"(イベント記録時は '{expected_basename}')。同一プロセスではないため停止対象外です。"
            ),
        )

    # 2. 起動時刻の照合 (イベント発生時刻より後に起動した別プロセスでないか確認)
    event_ts = _parse_event_utc_timestamp(event_utc_time)
    if event_ts is not None:
        if create_ts > (event_ts + 15.0):
            return ProcessVerificationResult(
                pid=pid,
                is_alive=True,
                is_verified_same_process=False,
                is_protected=True,
                process_name=proc_name,
                exe_path=proc_exe,
                create_time_utc=create_utc_str,
                status=proc_status,
                reason=(
                    f"【誤爆防止】PID {pid} ({proc_name}) の起動時刻 ({create_utc_str} UTC) が "
                    f"イベント発生時刻 ({event_utc_time}) より新しいため、再起動された別プロセスと判定しました。"
                ),
            )

    # 3. OS中枢プロセス・開発ツールの保護リスト照合
    if actual_basename in config.PROTECTED_PROCESS_NAMES:
        return ProcessVerificationResult(
            pid=pid,
            is_alive=True,
            is_verified_same_process=True,
            is_protected=True,
            process_name=proc_name,
            exe_path=proc_exe,
            create_time_utc=create_utc_str,
            status=proc_status,
            reason=(
                f"PID {pid} ({proc_name}) は稼働中ですが、OS標準/保護対象プロセスリストに含まれるため "
                f"システム保護により停止操作はロックされています。"
            ),
        )

    return ProcessVerificationResult(
        pid=pid,
        is_alive=True,
        is_verified_same_process=True,
        is_protected=False,
        process_name=proc_name,
        exe_path=proc_exe,
        create_time_utc=create_utc_str,
        status=proc_status,
        reason=(
            f"PID {pid} ({proc_name}) は現在も稼働中であり、実行ファイル名および起動時刻 ({create_utc_str} UTC) の一致を確認しました。"
        ),
    )


def _append_action_audit_log(report_file: str, action_name: str, detail: str) -> None:
    """迎撃操作や Microsoft Defender 通報結果をレポートファイル末尾に追記（mode='a'）します。"""
    logger.warning("[迎撃・防衛ログ] %s: %s", action_name, detail)
    if not report_file:
        return
    try:
        now_str = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        entry = (
            f"\n> **[防衛アクション記録 ({now_str})]** `{action_name}`: {detail}\n"
        )
        with open(report_file, mode="a", encoding="utf-8") as fp:
            fp.write(entry)
    except OSError as exc:
        logger.error("アクション履歴の追記に失敗しました: %s", exc)


# ============================================================================
# Microsoft Defender 自動緊急スキャン通報機能
# ============================================================================
def _find_mpcmdrun_exe() -> str | None:
    """Windows Defender の公式コマンドラインスキャナ (MpCmdRun.exe) のパスを検索します。"""
    platform_pattern = r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
    matches = sorted(glob.glob(platform_pattern), reverse=True)
    for candidate in matches:
        if os.path.isfile(candidate):
            return candidate

    default_path = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    if os.path.isfile(default_path):
        return default_path

    return None


def extract_scan_target_paths(event: NormalizedEvent) -> list[str]:
    """
    イベントの Image (実行ファイル) および CommandLine / ParentCommandLine 内に含まれる
    スクリプト・実行ファイルパスを抽出し、Microsoft Defender で検査すべきファイル一覧を返します。
    """
    candidates: list[str] = []

    # 1. コマンドラインおよび親コマンドラインから参照ファイル (.ps1, .vbs, .dll, .exe 等) を抽出
    for cmd_text in (event.command_line or "", event.parent_command_line or ""):
        expanded_cmd = os.path.expandvars(cmd_text)
        for match in _WIN_PATH_PATTERN.findall(expanded_cmd):
            cleaned = match.strip().strip('"').strip("'")
            if os.path.isfile(cleaned):
                norm = os.path.normcase(os.path.abspath(cleaned))
                if norm not in [os.path.normcase(c) for c in candidates]:
                    candidates.append(os.path.abspath(cleaned))

    # 2. イベント本体の Image パスを確認
    if event.image:
        expanded_img = os.path.expandvars(event.image.strip())
        if os.path.isfile(expanded_img):
            norm_img = os.path.normcase(os.path.abspath(expanded_img))
            # System32 / SysWOW64 配下の正規LOLBin (powershell.exe 等) であり、
            # かつ既にコマンドラインからスクリプトファイルが抽出できている場合はスクリプト検査を優先
            is_system_lolbin = (
                norm_img.startswith(r"c:\windows\system32\\")
                or norm_img.startswith(r"c:\windows\syswow64\\")
            )
            if not is_system_lolbin or not candidates:
                if norm_img not in [os.path.normcase(c) for c in candidates]:
                    candidates.append(os.path.abspath(expanded_img))

    return candidates


def run_defender_scan_sync(
    event: NormalizedEvent,
    report_file: str = "",
    force: bool = False,
) -> str:
    """
    Microsoft Defender (MpCmdRun.exe -Scan -ScanType 3 -File <path>) を実行し、
    検査結果サマリ文字列を返します（10分間のクールダウン重複排除・30秒タイムアウト付き）。
    """
    mpcmdrun = _find_mpcmdrun_exe()
    if not mpcmdrun:
        msg = "MpCmdRun.exe が見つからないため、Defender 緊急スキャンをスキップしました。"
        logger.warning(msg)
        return msg

    targets = extract_scan_target_paths(event)
    if not targets:
        msg = "スキャン対象となるローカルファイルが存在しないためスキップしました。"
        logger.info(msg)
        return msg

    results_summary: list[str] = []
    now_mono = time.monotonic()

    for target_path in targets:
        norm_key = os.path.normcase(target_path)
        with _DEFENDER_LOCK:
            last_scan = _DEFENDER_SCAN_HISTORY.get(norm_key)
            if (
                not force
                and last_scan is not None
                and (now_mono - last_scan) < config.DEFENDER_SCAN_COOLDOWN_SECONDS
            ):
                remain = int(config.DEFENDER_SCAN_COOLDOWN_SECONDS - (now_mono - last_scan))
                skip_msg = f"'{Path(target_path).name}' は直近スキャン済のためクールダウン中 (残り {remain} 秒)"
                logger.info("[Defender 通報スキップ] %s", skip_msg)
                results_summary.append(skip_msg)
                continue
            _DEFENDER_SCAN_HISTORY[norm_key] = now_mono

        logger.info("[Defender 緊急スキャン開始] Target=%s", target_path)
        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            completed = subprocess.run(
                [mpcmdrun, "-Scan", "-ScanType", "3", "-File", target_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=config.DEFENDER_SCAN_TIMEOUT_SECONDS,
                creationflags=creation_flags,
            )
            stdout_text = (completed.stdout or "").strip()
            rc = completed.returncode

            if rc == 0 and "found no threats" in stdout_text.lower():
                res = f"'{Path(target_path).name}': 既知の脅威は検出されませんでした (returncode=0)"
            elif rc == 2 or "threat" in stdout_text.lower():
                res = (
                    f"🚨 '{Path(target_path).name}': Microsoft Defender が脅威を検出し、"
                    f"カーネル検疫・駆除を実行しました! (returncode={rc}, output={stdout_text[:120]})"
                )
            else:
                res = f"'{Path(target_path).name}': スキャン完了 (returncode={rc}, output={stdout_text[:120]})"

            results_summary.append(res)
        except subprocess.TimeoutExpired:
            res = f"'{Path(target_path).name}': Defender スキャンがタイムアウト ({config.DEFENDER_SCAN_TIMEOUT_SECONDS}秒) しました。"
            results_summary.append(res)
        except Exception as scan_exc:
            res = f"'{Path(target_path).name}': Defender スキャン実行エラー ({scan_exc})"
            results_summary.append(res)

    final_summary = " / ".join(results_summary)
    _append_action_audit_log(
        report_file,
        "Microsoft Defender 自動緊急スキャン通報",
        final_summary,
    )
    return final_summary


def trigger_defender_emergency_scan(
    event: NormalizedEvent,
    report_file: str = "",
    force: bool = False,
    on_complete: Callable[[str], None] | None = None,
) -> threading.Thread:
    """
    メインの監視ループやGUIを一切ブロックしないよう、バックグラウンドスレッドで
    Microsoft Defender への緊急カスタムスキャン通報を実行します。
    """

    def _worker() -> None:
        summary = run_defender_scan_sync(event, report_file=report_file, force=force)
        if on_complete is not None:
            try:
                on_complete(summary)
            except Exception:
                pass

    t = threading.Thread(
        target=_worker,
        name=f"DefenderScan-PID-{event.process_id}",
        daemon=True,
    )
    t.start()
    return t


# ============================================================================
# 手動プロセス操作 (Suspend / Resume / Kill)
# ============================================================================
def execute_process_action(
    action: str,
    pid: int | None,
    expected_image: str,
    event_utc_time: str,
    report_file: str = "",
) -> tuple[bool, str]:
    """
    ボタン押下時に再度「PID + 実行ファイル名 + 起動時刻」を厳密照合した上で、
    指定されたアクション ('suspend' / 'resume' / 'kill') を実行します。
    """
    verification = verify_target_process(pid, expected_image, event_utc_time)
    if not verification.is_alive:
        return False, verification.reason
    if not verification.is_verified_same_process:
        return False, verification.reason
    if verification.is_protected:
        return False, verification.reason

    assert pid is not None and psutil is not None
    try:
        proc = psutil.Process(pid)
        if action == "suspend":
            proc.suspend()
            msg = f"PID {pid} ({verification.process_name}) を一時停止（凍結: Suspend）しました。ファイル操作や通信は停止しています。"
            _append_action_audit_log(report_file, "SUSPEND (一時停止/凍結)", msg)
            return True, msg
        elif action == "resume":
            proc.resume()
            msg = f"PID {pid} ({verification.process_name}) の凍結を解除（再開: Resume）しました。"
            _append_action_audit_log(report_file, "RESUME (凍結解除/再開)", msg)
            return True, msg
        elif action == "kill":
            proc.kill()
            msg = f"PID {pid} ({verification.process_name}) を強制終了（Kill）しました。"
            _append_action_audit_log(report_file, "KILL (強制終了)", msg)
            return True, msg
        else:
            return False, f"未定義のアクションです: {action}"
    except Exception as exc:
        err_msg = f"PID {pid} に対する '{action}' 実行中にエラーが発生しました: {exc}"
        logger.error(err_msg)
        return False, err_msg


def show_critical_response_dialog(
    event: NormalizedEvent,
    report_text: str,
    report_file: str,
    auto_defender_scan: bool = True,
) -> None:
    """
    [CRITICAL] 検知時に Microsoft Defender への緊急スキャン通報を非同期で開始するとともに、
    最前面の緊急対応ウィンドウ（ワンクリック迎撃パネル）を別スレッドで表示します。
    """
    thread = threading.Thread(
        target=_run_dialog_window,
        args=(event, report_text, report_file, auto_defender_scan),
        name=f"CriticalDialog-PID-{event.process_id}",
        daemon=True,
    )
    thread.start()


def _run_dialog_window(
    event: NormalizedEvent,
    report_text: str,
    report_file: str,
    auto_defender_scan: bool = True,
) -> None:
    """Tkinter によるワンクリック迎撃ダイアログのメイン処理。"""
    try:
        root = tk.Tk()
        root.title("【緊急】Sysmon Gemini 監視エージェント - CRITICAL 迎撃パネル")
        root.geometry("780x620")
        root.configure(bg="#1E1E2E")
        root.attributes("-topmost", True)

        verification = verify_target_process(
            event.process_id,
            event.image,
            event.utc_time,
        )

        # ヘッダー（赤色警告バー）
        header_frame = tk.Frame(root, bg="#DC2626", padx=14, pady=10)
        header_frame.pack(fill=tk.X)
        header_label = tk.Label(
            header_frame,
            text=f"🚨 [CRITICAL] 深刻な脅威を検知しました (Event ID: {event.event_id} / PID: {event.process_id})",
            fg="#FFFFFF",
            bg="#DC2626",
            font=("Yu Gothic UI", 12, "bold"),
            anchor="w",
        )
        header_label.pack(fill=tk.X)

        # プロセス情報＆照合ステータス枠
        info_frame = tk.Frame(root, bg="#2A2A3C", padx=14, pady=10)
        info_frame.pack(fill=tk.X, padx=12, pady=(10, 6))

        tk.Label(
            info_frame,
            text=f"実行イメージ : {event.image or '(不明)'}   (PID: {event.process_id})",
            fg="#F8FAFC",
            bg="#2A2A3C",
            font=("Consolas", 10, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        cmd_display = (event.command_line or "(なし)")[:120]
        tk.Label(
            info_frame,
            text=f"コマンドライン: {cmd_display}",
            fg="#CBD5E1",
            bg="#2A2A3C",
            font=("Consolas", 9),
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 4))

        status_var = tk.StringVar(value=f"生存・同一性照合: {verification.reason}")
        status_color = (
            "#FBBF24"
            if (verification.is_alive and verification.is_verified_same_process and not verification.is_protected)
            else "#94A3B8"
        )
        status_label = tk.Label(
            info_frame,
            textvariable=status_var,
            fg=status_color,
            bg="#2A2A3C",
            font=("Yu Gothic UI", 9, "bold"),
            anchor="w",
            wraplength=730,
            justify="left",
        )
        status_label.pack(fill=tk.X)

        # Microsoft Defender 緊急スキャン通報ステータス表示
        defender_var = tk.StringVar(
            value="🛡️ Microsoft Defender 緊急スキャン通報: バックグラウンドで精密検査中..."
            if auto_defender_scan
            else "🛡️ Microsoft Defender 緊急スキャン通報: 待機中"
        )
        defender_label = tk.Label(
            info_frame,
            textvariable=defender_var,
            fg="#60A5FA",
            bg="#2A2A3C",
            font=("Yu Gothic UI", 9, "bold"),
            anchor="w",
            wraplength=730,
            justify="left",
        )
        defender_label.pack(fill=tk.X, pady=(4, 0))

        def _update_defender_ui(summary_text: str) -> None:
            try:
                root.after(
                    0,
                    lambda: defender_var.set(f"🛡️ Microsoft Defender 検査結果: {summary_text}"),
                )
            except Exception:
                pass

        if auto_defender_scan:
            trigger_defender_emergency_scan(
                event=event,
                report_file=report_file,
                force=False,
                on_complete=_update_defender_ui,
            )

        # Gemini レポート表示エリア
        report_frame = tk.Frame(root, bg="#1E1E2E", padx=12, pady=4)
        report_frame.pack(fill=tk.BOTH, expand=True)

        text_box = scrolledtext.ScrolledText(
            report_frame,
            wrap=tk.WORD,
            bg="#111827",
            fg="#E5E7EB",
            font=("Yu Gothic UI", 9),
            padx=10,
            pady=8,
        )
        text_box.insert(tk.END, report_text)
        text_box.configure(state=tk.DISABLED)
        text_box.pack(fill=tk.BOTH, expand=True)

        # ボタン操作コールバック
        can_intervene = (
            verification.is_alive
            and verification.is_verified_same_process
            and not verification.is_protected
        )

        def on_suspend() -> None:
            ok, msg = execute_process_action(
                "suspend",
                event.process_id,
                event.image,
                event.utc_time,
                report_file,
            )
            status_var.set(f"ステータス: {msg}")
            if ok:
                status_label.configure(fg="#34D399")
                btn_resume.configure(state=tk.NORMAL)
            else:
                status_label.configure(fg="#F87171")
                messagebox.showwarning("一時停止 (Suspend) 結果", msg, parent=root)

        def on_resume() -> None:
            ok, msg = execute_process_action(
                "resume",
                event.process_id,
                event.image,
                event.utc_time,
                report_file,
            )
            status_var.set(f"ステータス: {msg}")
            if ok:
                status_label.configure(fg="#FBBF24")
            else:
                messagebox.showwarning("再開 (Resume) 結果", msg, parent=root)

        def on_kill() -> None:
            confirm = messagebox.askyesno(
                "強制終了 (Kill) の最終確認",
                f"PID {event.process_id} ({event.image})\n\n"
                "このプロセスを完全に強制終了 (Kill) しますか？\n"
                "（※迷う場合は「いいえ」を選び、「一時停止 (Suspend)」を使用してください）",
                parent=root,
            )
            if not confirm:
                return
            ok, msg = execute_process_action(
                "kill",
                event.process_id,
                event.image,
                event.utc_time,
                report_file,
            )
            status_var.set(f"ステータス: {msg}")
            if ok:
                status_label.configure(fg="#34D399")
                btn_suspend.configure(state=tk.DISABLED)
                btn_resume.configure(state=tk.DISABLED)
                btn_kill.configure(state=tk.DISABLED)
            else:
                status_label.configure(fg="#F87171")
                messagebox.showwarning("強制終了 (Kill) 結果", msg, parent=root)

        def on_manual_defender_scan() -> None:
            defender_var.set("🛡️ Microsoft Defender 緊急スキャン通報: 手動再スキャン中...")
            trigger_defender_emergency_scan(
                event=event,
                report_file=report_file,
                force=True,
                on_complete=_update_defender_ui,
            )

        def on_open_report() -> None:
            try:
                if report_file and Path(report_file).exists():
                    os.startfile(report_file)
                else:
                    os.startfile(str(config.ALERTS_DIR))
            except Exception as exc:
                logger.warning("レポートを開けませんでした: %s", exc)

        def on_add_allowlist() -> None:
            ok, _, rule_val, preview_msg = allowlist.extract_rule_candidate(event)
            if not ok:
                messagebox.showwarning("許可リスト登録不可", preview_msg, parent=root)
                return
            if not messagebox.askyesno(
                "許可リスト (ホワイトリスト) 登録確認",
                f"このプログラムを無害な許可リストに追加しますか？\n\n{preview_msg}\n\n"
                "※登録後、改ざん検知・注入・LSASSアクセス以外の通常監視から除外されます。",
                parent=root,
            ):
                return
            added, _, result_msg = allowlist.add_rule_for_event(event)
            if added:
                status_var.set(f"✅ 許可リスト登録済み: {rule_val}")
                messagebox.showinfo("登録完了", result_msg, parent=root)
            else:
                messagebox.showwarning("登録スキップ", result_msg, parent=root)

        # アクションボタンバー
        btn_frame = tk.Frame(root, bg="#1E1E2E", padx=12, pady=10)
        btn_frame.pack(fill=tk.X)

        btn_suspend = tk.Button(
            btn_frame,
            text="⏸ 一時停止 / 凍結 (Suspend)【推奨】",
            command=on_suspend,
            bg="#D97706",
            fg="#FFFFFF",
            activebackground="#B45309",
            activeforeground="#FFFFFF",
            font=("Yu Gothic UI", 9, "bold"),
            padx=10,
            pady=6,
            state=tk.NORMAL if can_intervene else tk.DISABLED,
        )
        btn_suspend.pack(side=tk.LEFT, padx=(0, 6))

        btn_resume = tk.Button(
            btn_frame,
            text="▶ 凍結解除 (Resume)",
            command=on_resume,
            bg="#059669",
            fg="#FFFFFF",
            activebackground="#047857",
            activeforeground="#FFFFFF",
            font=("Yu Gothic UI", 9, "bold"),
            padx=10,
            pady=6,
            state=tk.NORMAL if can_intervene else tk.DISABLED,
        )
        btn_resume.pack(side=tk.LEFT, padx=6)

        btn_kill = tk.Button(
            btn_frame,
            text="🛑 強制終了 (Kill)",
            command=on_kill,
            bg="#DC2626",
            fg="#FFFFFF",
            activebackground="#B91C1C",
            activeforeground="#FFFFFF",
            font=("Yu Gothic UI", 9, "bold"),
            padx=10,
            pady=6,
            state=tk.NORMAL if can_intervene else tk.DISABLED,
        )
        btn_kill.pack(side=tk.LEFT, padx=6)

        btn_defender = tk.Button(
            btn_frame,
            text="🛡️ Defender再検査",
            command=on_manual_defender_scan,
            bg="#2563EB",
            fg="#FFFFFF",
            activebackground="#1D4ED8",
            activeforeground="#FFFFFF",
            font=("Yu Gothic UI", 9, "bold"),
            padx=10,
            pady=6,
        )
        btn_defender.pack(side=tk.LEFT, padx=6)

        btn_report = tk.Button(
            btn_frame,
            text="📄 レポートを開く",
            command=on_open_report,
            bg="#374151",
            fg="#F9FAFB",
            font=("Yu Gothic UI", 9),
            padx=10,
            pady=6,
        )
        btn_report.pack(side=tk.LEFT, padx=6)

        btn_allowlist = tk.Button(
            btn_frame,
            text="✅ 許可リスト追加",
            command=on_add_allowlist,
            bg="#047857",
            fg="#FFFFFF",
            activebackground="#065F46",
            activeforeground="#FFFFFF",
            font=("Yu Gothic UI", 9, "bold"),
            padx=10,
            pady=6,
        )
        btn_allowlist.pack(side=tk.LEFT, padx=6)

        btn_close = tk.Button(
            btn_frame,
            text="閉じる",
            command=root.destroy,
            bg="#4B5563",
            fg="#F9FAFB",
            font=("Yu Gothic UI", 9),
            padx=10,
            pady=6,
        )
        btn_close.pack(side=tk.RIGHT)

        root.mainloop()
    except Exception as gui_exc:
        logger.error("緊急迎撃ダイアログの表示中にエラーが発生しました: %s", gui_exc)
