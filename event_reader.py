"""
Windowsイベントログ取得・XMLパース・一次スクリーニング・チェックポイント管理モジュール (event_reader.py)

pywin32 (win32evtlog) を用いて完全読み取り専用（Read-Only）でイベントログを取得し、
xml.etree.ElementTree による高速パース、重複処理防止のための checkpoint.json 管理、
およびルールベースの一次スクリーニングを実行します。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any
import xml.etree.ElementTree as ET

import allowlist
import config

logger = logging.getLogger("sysmon_gemini_agent.event_reader")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = False

# Sysmon CLI 無効化・設定改ざんコマンド検出パターン (プロジェクト名 sysmon-gemini-agent 等への誤検知を防ぐ)
_SYSMON_CLI_TAMPER_RE = re.compile(
    r"\bsysmon(?:64)?(?:\.exe)?\s+[-/](?:u|c)\b",
    re.IGNORECASE,
)

# `uv` 管理 Python インタプリタ実行ファイルパス（AppData\Roaming\uv\python\...\python[w].exe）
_UV_PYTHON_EXE_RE = re.compile(
    r"[a-z]:\\[^\"'\r\n]*\\appdata\\roaming\\uv\\python\\[^\"'\r\n]*\\pythonw?\.exe",
    re.IGNORECASE,
)

# pywin32 のインポート（環境に応じた安全なフォールバック付き）
try:
    import pywintypes
    import win32evtlog
    import win32evtlogutil  # noqa: F401 - 要件に基づくインポート

    HAS_PYWIN32 = True
except ImportError:
    pywintypes = None  # type: ignore[assignment]
    win32evtlog = None  # type: ignore[assignment]
    win32evtlogutil = None  # type: ignore[assignment]
    HAS_PYWIN32 = False


@dataclass(slots=True)
class NormalizedEvent:
    """
    正規化されたWindowsイベントログ構造体。
    Geminiに渡す際は to_trimmed_dict() を通じて生XMLを除外し、
    トークン最適化された指定8フィールドのみを提供します。
    """

    channel: str
    event_id: int
    event_record_id: int
    utc_time: str = ""
    process_id: int | None = None
    image: str = ""
    command_line: str = ""
    parent_process_id: int | None = None
    parent_image: str = ""
    parent_command_line: str = ""
    destination_ip: str = ""
    destination_port: int | None = None
    user: str = ""
    logon_type: str = ""
    status_code: str = ""
    screening_reasons: list[str] = field(default_factory=list)
    event_details: dict[str, str] = field(default_factory=dict)

    def to_trimmed_dict(self) -> dict[str, Any]:
        """
        Geminiのプロンプト・コンテキストに投入するトークン最適化済み辞書を返します。
        生XMLを含めず、指示書で定義された8フィールドのみを抽出します。
        """
        return {
            "UtcTime": self.utc_time,
            "ProcessId": self.process_id,
            "Image": self.image,
            "CommandLine": self.command_line,
            "ParentProcessId": self.parent_process_id,
            "ParentCommandLine": self.parent_command_line,
            "DestinationIp": self.destination_ip,
            "DestinationPort": self.destination_port,
        }


# ツール検索用のインメモリキャッシュ（直近イベントをRead-Onlyで保持）
_RECENT_EVENTS: deque[NormalizedEvent] = deque(maxlen=config.RECENT_EVENT_CACHE_SIZE)


def register_event_in_cache(event: NormalizedEvent) -> None:
    """取得・正規化したイベントをインメモリキャッシュへ登録します。"""
    _RECENT_EVENTS.append(event)


def get_cached_events() -> list[NormalizedEvent]:
    """インメモリキャッシュ内のイベント一覧（新しい順）を返します。"""
    return list(reversed(_RECENT_EVENTS))


def _extract_first_ip_from_dns_results(query_results: str) -> str:
    """Sysmon Event ID 22 の QueryResults 文字列から先頭の IP アドレスを抽出します。"""
    if not query_results:
        return ""
    for token in query_results.split(";"):
        part = token.strip()
        if not part or part.startswith("type:"):
            continue
        if part.lower().startswith("::ffff:"):
            part = part[7:]
        # IPv4 または IPv6 形式の簡易検証
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", part) or ":" in part:
            return part
    return ""


def _parse_int(value: str | None) -> int | None:
    """10進数または16進数文字列 ('0x1a4' 等) を安全に int へ変換します。"""
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        return int(raw)
    except ValueError:
        return None


def _strip_ns(tag: str) -> str:
    """XMLタグ名から名前空間プレフィックス `{http://...}` を除去します。"""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_event_xml(xml_text: str, default_channel: str = "") -> NormalizedEvent | None:
    """
    Windows Event Log の XML 文字列を xml.etree.ElementTree で高速パースし、
    Sysmon / Security イベントの差異を吸収して NormalizedEvent に変換します。
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.debug("イベントXMLのパースに失敗しました: %s", exc)
        return None

    channel = default_channel
    event_id = 0
    event_record_id = 0
    utc_time = ""
    event_data: dict[str, str] = {}

    for section in root:
        sec_name = _strip_ns(section.tag)
        if sec_name == "System":
            for child in section:
                cname = _strip_ns(child.tag)
                if cname == "EventID" and child.text:
                    event_id = _parse_int(child.text) or 0
                elif cname == "EventRecordID" and child.text:
                    event_record_id = _parse_int(child.text) or 0
                elif cname == "Channel" and child.text:
                    channel = child.text.strip()
                elif cname == "TimeCreated":
                    utc_time = child.attrib.get("SystemTime", "")
        elif sec_name == "EventData":
            unnamed_idx = 0
            for data_elem in section.iter():
                if _strip_ns(data_elem.tag) == "Data":
                    key = data_elem.attrib.get("Name")
                    val = (data_elem.text or "").strip()
                    if key:
                        event_data[key] = val
                    elif val:
                        event_data[f"_pos_{unnamed_idx}"] = val
                        unnamed_idx += 1
        elif sec_name == "UserData":
            for data_elem in section.iter():
                tag_name = _strip_ns(data_elem.tag)
                if tag_name == "Data":
                    key = data_elem.attrib.get("Name")
                    val = (data_elem.text or "").strip()
                    if key:
                        event_data[key] = val
                elif len(data_elem) == 0:
                    val = (data_elem.text or "").strip()
                    if tag_name and val and tag_name not in event_data:
                        event_data[tag_name] = val

    # UtcTime: EventData 側の UtcTime を優先し、無ければ System.TimeCreated を使用
    utc_time = event_data.get("UtcTime") or utc_time
    extracted_details: dict[str, str] = {}
    parsed_dest_ip = ""

    # Sysmon Event ID 1/3/4/8/10/11/12/13/14/16/22/255 および Security / System 監査イベントの正規化
    if event_id == 4688:
        # Windows Security 4688 では NewProcessId が生成されたプロセス、ProcessId が親プロセス
        process_id = _parse_int(event_data.get("NewProcessId"))
        parent_process_id = _parse_int(event_data.get("ProcessId"))
        image = event_data.get("NewProcessName", "")
        parent_image = event_data.get("ParentProcessName", "")
        command_line = event_data.get("CommandLine", "")
        parent_command_line = parent_image
    elif event_id in (4624, 4625):
        process_id = _parse_int(event_data.get("ProcessId"))
        parent_process_id = None
        image = event_data.get("ProcessName", "")
        parent_image = ""
        target_user = event_data.get("TargetUserName", "")
        workstation = event_data.get("WorkstationName", "")
        logon_type = event_data.get("LogonType", "")
        status = event_data.get("Status", "")
        command_line = (
            f"LogonEvent ID={event_id} User={target_user} "
            f"LogonType={logon_type} Workstation={workstation} Status={status}"
        ).strip()
        parent_command_line = ""
    elif channel == config.SYSMON_CHANNEL and event_id == 4:
        # Sysmon Event ID 4: Sysmon service state changed
        process_id = None
        parent_process_id = None
        state = event_data.get("State", "")
        version = event_data.get("Version", "")
        image = "Sysmon Service"
        parent_image = ""
        command_line = f"Sysmon Service State Changed: State={state} Version={version}".strip()
        parent_command_line = ""
    elif channel == config.SYSMON_CHANNEL and event_id == 8:
        # Sysmon Event ID 8: CreateRemoteThread (スレッド注入 / DLLインジェクション)
        process_id = _parse_int(event_data.get("SourceProcessId"))
        parent_process_id = None
        image = event_data.get("SourceImage", "")
        parent_image = ""
        tgt_pid = event_data.get("TargetProcessId", "")
        tgt_image = event_data.get("TargetImage", "")
        start_addr = event_data.get("StartAddress", "")
        start_mod = event_data.get("StartModule", "")
        start_fn = event_data.get("StartFunction", "")
        command_line = (
            f"CreateRemoteThread (ID=8): Target={tgt_image} (TargetPID={tgt_pid}) "
            f"StartAddress={start_addr} StartModule={start_mod} StartFunction={start_fn}"
        ).strip()
        parent_command_line = ""
        extracted_details = {
            "target_image": tgt_image,
            "target_pid": tgt_pid,
            "start_address": start_addr,
            "start_module": start_mod,
            "start_function": start_fn,
        }
    elif channel == config.SYSMON_CHANNEL and event_id == 10:
        # Sysmon Event ID 10: ProcessAccess (LSASSメモリダンプ・不正プロセスメモリアクセス)
        process_id = _parse_int(event_data.get("SourceProcessId"))
        parent_process_id = None
        image = event_data.get("SourceImage", "")
        parent_image = ""
        tgt_pid = event_data.get("TargetProcessId", "")
        tgt_image = event_data.get("TargetImage", "")
        granted_access = event_data.get("GrantedAccess", "")
        call_trace = event_data.get("CallTrace", "")
        call_trace_short = call_trace[:220] + ("..." if len(call_trace) > 220 else "")
        command_line = (
            f"ProcessAccess (ID=10): Target={tgt_image} (TargetPID={tgt_pid}) "
            f"GrantedAccess={granted_access} CallTrace={call_trace_short}"
        ).strip()
        parent_command_line = ""
        extracted_details = {
            "target_image": tgt_image,
            "target_pid": tgt_pid,
            "granted_access": granted_access,
            "call_trace": call_trace,
        }
    elif channel == config.SYSMON_CHANNEL and event_id == 11:
        # Sysmon Event ID 11: FileCreate (ファイル作成)
        process_id = _parse_int(event_data.get("ProcessId"))
        parent_process_id = None
        image = event_data.get("Image", "")
        parent_image = ""
        target_filename = event_data.get("TargetFilename", "")
        creation_utc = event_data.get("CreationUtcTime", "")
        command_line = (
            f"FileCreate (ID=11): TargetFilename={target_filename} (Created={creation_utc})"
        ).strip()
        parent_command_line = ""
        extracted_details = {
            "target_filename": target_filename,
            "creation_utc_time": creation_utc,
        }
    elif channel == config.SYSMON_CHANNEL and event_id in (12, 13, 14):
        # Sysmon Event ID 12/13/14: RegistryEvent (レジストリ変更・永続化)
        process_id = _parse_int(event_data.get("ProcessId"))
        parent_process_id = None
        image = event_data.get("Image", "")
        parent_image = ""
        evt_type = event_data.get("EventType", "")
        target_object = event_data.get("TargetObject", "")
        details = event_data.get("Details", "") or event_data.get("NewName", "")
        command_line = (
            f"RegistryEvent (ID={event_id}, Type={evt_type}): "
            f"TargetObject={target_object} Details={details}"
        ).strip()
        parent_command_line = ""
        extracted_details = {
            "event_type": evt_type,
            "target_object": target_object,
            "details": details,
        }
    elif channel == config.SYSMON_CHANNEL and event_id == 16:
        # Sysmon Event ID 16: Sysmon config state changed
        process_id = None
        parent_process_id = None
        cfg_path = event_data.get("Configuration", "")
        cfg_hash = event_data.get("ConfigurationFileHash", "")
        image = "Sysmon Config"
        parent_image = ""
        command_line = (
            f"Sysmon Config Changed: Configuration={cfg_path} Hash={cfg_hash}"
        ).strip()
        parent_command_line = ""
    elif channel == config.SYSMON_CHANNEL and event_id == 22:
        # Sysmon Event ID 22: DNSEvent (DNSクエリ)
        process_id = _parse_int(event_data.get("ProcessId"))
        parent_process_id = None
        image = event_data.get("Image", "")
        parent_image = ""
        query_name = event_data.get("QueryName", "")
        query_status = event_data.get("QueryStatus", "")
        query_results = event_data.get("QueryResults", "")
        parsed_dest_ip = _extract_first_ip_from_dns_results(query_results)
        results_short = query_results[:180] + ("..." if len(query_results) > 180 else "")
        command_line = (
            f"DNSEvent (ID=22): QueryName={query_name} Status={query_status} Results={results_short}"
        ).strip()
        parent_command_line = ""
        extracted_details = {
            "query_name": query_name,
            "query_status": query_status,
            "query_results": query_results,
        }
    elif channel == config.SYSMON_CHANNEL and event_id == 255:
        # Sysmon Event ID 255: Error report
        process_id = None
        parent_process_id = None
        err_id = event_data.get("ID", "")
        desc = event_data.get("Description", "")
        image = "Sysmon Driver/Service"
        parent_image = ""
        command_line = f"Sysmon Error (ID={err_id}): {desc}".strip()
        parent_command_line = ""
    elif event_id in (1102, 104):
        # Security 1102 (監査ログ消去) / System 104 (イベントログ消去)
        process_id = _parse_int(event_data.get("ClientProcessId"))
        parent_process_id = None
        subj_domain = event_data.get("SubjectDomainName", "")
        subj_user = event_data.get("SubjectUserName", "")
        cleared_ch = event_data.get("Channel") or channel
        actor = f"{subj_domain}\\{subj_user}".strip("\\")
        image = "Windows Event Log Cleared"
        parent_image = ""
        command_line = (
            f"Event Log Cleared (ID={event_id}): ClearedChannel={cleared_ch} Subject={actor}"
        ).strip()
        parent_command_line = ""
    elif event_id == 4719:
        # Security 4719: System audit policy was changed
        process_id = None
        parent_process_id = None
        subj_user = event_data.get("SubjectUserName", "")
        subcat = event_data.get("SubcategoryGuid", "")
        changes = event_data.get("AuditPolicyChanges", "")
        image = "Windows Audit Policy"
        parent_image = ""
        command_line = (
            f"Audit Policy Changed (ID=4719): Subcategory={subcat} "
            f"Changes={changes} Subject={subj_user}"
        ).strip()
        parent_command_line = ""
    elif channel == config.SYSTEM_CHANNEL and event_id in (7036, 7040):
        # System 7036 (Service state changed) / 7040 (Service start type changed)
        process_id = None
        parent_process_id = None
        svc_name = event_data.get("param1") or event_data.get("_pos_0") or ""
        svc_state = event_data.get("param2") or event_data.get("_pos_1") or ""
        svc_extra = event_data.get("param3") or event_data.get("_pos_2") or ""
        image = svc_name or "Service Control Manager"
        parent_image = ""
        command_line = (
            f"Service Control Event (ID={event_id}): Service={svc_name} "
            f"State={svc_state} Detail={svc_extra}"
        ).strip()
        parent_command_line = ""
    else:
        # Sysmon Event ID 1 / 3 等
        process_id = _parse_int(event_data.get("ProcessId"))
        parent_process_id = _parse_int(event_data.get("ParentProcessId"))
        image = event_data.get("Image", "")
        parent_image = event_data.get("ParentImage", "")
        command_line = event_data.get("CommandLine", "")
        parent_command_line = event_data.get("ParentCommandLine") or parent_image

    destination_ip = (
        event_data.get("DestinationIp")
        or event_data.get("IpAddress")
        or parsed_dest_ip
        or ""
    )
    if destination_ip in ("-", "::1", "127.0.0.1"):
        # ローカルループバックや空ハイフンはそのまま保持または整形
        pass

    destination_port = _parse_int(
        event_data.get("DestinationPort") or event_data.get("IpPort")
    )

    normalized = NormalizedEvent(
        channel=channel,
        event_id=event_id,
        event_record_id=event_record_id,
        utc_time=utc_time,
        process_id=process_id,
        image=image,
        command_line=command_line,
        parent_process_id=parent_process_id,
        parent_image=parent_image,
        parent_command_line=parent_command_line,
        destination_ip=destination_ip,
        destination_port=destination_port,
        user=event_data.get("User") or event_data.get("TargetUserName") or "",
        logon_type=event_data.get("LogonType", ""),
        status_code=event_data.get("Status", ""),
        event_details=extracted_details,
    )
    return normalized


def _image_basename(path: str) -> str:
    """実行ファイルパスから小文字のベース名を取得します。"""
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _screen_create_remote_thread(event: NormalizedEvent, reasons: list[str]) -> None:
    """Sysmon Event ID 8 (CreateRemoteThread) のスレッド注入判定を行います。"""
    tgt_img = event.event_details.get("target_image", "")
    src_base = _image_basename(event.image)
    tgt_base = _image_basename(tgt_img)
    start_mod = (event.event_details.get("start_module") or "").strip().lower()
    src_lower = (event.image or "").lower()

    if src_base and src_base == tgt_base:
        return

    is_trusted_src = src_base in config.TRUSTED_SYSTEM_INJECTOR_NAMES
    if is_trusted_src and start_mod and tgt_base != "lsass.exe":
        return

    if not start_mod or (
        start_mod and not start_mod.endswith((".dll", ".exe", ".sys", ".ocx"))
    ):
        reasons.append(
            f"[CRITICAL候補] モジュール裏付けのないスレッド注入疑い (CreateRemoteThread: "
            f"{event.image} -> {tgt_img}, StartAddress={event.event_details.get('start_address', '')})"
        )
    elif (
        tgt_base in config.HIGH_RISK_TARGET_PROCESSES
        or src_base in config.DROPPER_SOURCE_IMAGES
        or any(tp.lower() in src_lower for tp in config.SUSPICIOUS_TEMP_PATHS)
    ):
        reasons.append(
            f"[CRITICAL候補] 他プロセスへのスレッド注入 (CreateRemoteThread: {event.image} -> {tgt_img})"
        )


def _screen_process_access(event: NormalizedEvent, reasons: list[str]) -> None:
    """Sysmon Event ID 10 (ProcessAccess) のLSASSメモリダンプ・不正メモリ書込判定を行います。"""
    tgt_img = event.event_details.get("target_image", "")
    src_base = _image_basename(event.image)
    tgt_base = _image_basename(tgt_img)
    src_lower = (event.image or "").lower()
    granted_str = event.event_details.get("granted_access", "")
    granted_mask = _parse_int(granted_str) or 0
    call_trace_lower = (event.event_details.get("call_trace") or "").lower()

    # 監視エージェント自身のプロセス照会 (PROCESS_QUERY系) は除外
    if event.process_id in (os.getpid(), os.getppid()) and tgt_base != "lsass.exe":
        return

    has_vm_read = bool(granted_mask & 0x0010)
    has_vm_write_or_op = bool(granted_mask & 0x0028)
    has_unbacked_calltrace = "unknown" in call_trace_lower

    if tgt_base == "lsass.exe" and (has_vm_read or has_vm_write_or_op):
        is_trusted_core = (
            src_base in ("csrss.exe", "wininit.exe", "smss.exe", "services.exe", "lsass.exe", "svchost.exe")
            and src_lower.startswith("c:\\windows\\system32\\")
        )
        is_trusted_defender = (
            src_base in ("msmpeng.exe", "nissrv.exe") and "\\windows defender\\" in src_lower
        )
        if (not is_trusted_core and not is_trusted_defender) or has_unbacked_calltrace:
            reasons.append(
                f"[CRITICAL候補] LSASS プロセスメモリへの高権限アクセス (認証情報ダンプ疑い: "
                f"{event.image}, GrantedAccess={granted_str})"
            )
    elif (
        has_vm_write_or_op
        and src_base != tgt_base
        and tgt_base in config.HIGH_RISK_TARGET_PROCESSES
        and (
            src_base in config.DROPPER_SOURCE_IMAGES
            or any(tp.lower() in src_lower for tp in config.SUSPICIOUS_TEMP_PATHS)
            or has_unbacked_calltrace
        )
    ):
        reasons.append(
            f"[CRITICAL候補] 他プロセスへのメモリ書込権限取得 ({event.image} -> {tgt_img}, GrantedAccess={granted_str})"
        )


def _screen_file_create(event: NormalizedEvent, reasons: list[str]) -> None:
    """Sysmon Event ID 11 (FileCreate) の永続化投下・不審スクリプト作成・ランサム兆候を判定します。"""
    target_file = event.event_details.get("target_filename", "")
    if not target_file:
        return
    target_lower = target_file.lower()
    target_name = _image_basename(target_file)
    src_base = _image_basename(event.image)

    if any(pat in target_name for pat in config.RANSOMWARE_NOTE_PATTERNS):
        reasons.append(f"[CRITICAL候補] ランサムノート疑いのファイル作成を検知 ({target_file})")
        return

    is_exec_or_script = any(target_lower.endswith(ext) for ext in config.SUSPICIOUS_EXTENSIONS) or target_lower.endswith(".lnk")
    if not is_exec_or_script:
        return

    if any(p.lower() in target_lower for p in config.PERSISTENCE_FILE_PATHS):
        reasons.append(
            f"[CRITICAL候補] スタートアップ/タスク領域への実行ファイル・スクリプト投下 ({target_file})"
        )
        return

    if any(p in target_lower for p in ("\\users\\public\\", "\\windows\\temp\\")):
        reasons.append(
            f"公開/システム一時フォルダへの実行ファイル・スクリプト作成 ({event.image} -> {target_file})"
        )
        return

    if src_base in config.DROPPER_SOURCE_IMAGES and any(
        tp.lower() in target_lower for tp in config.SUSPICIOUS_TEMP_PATHS
    ):
        reasons.append(
            f"Office/LOLBin ({src_base}) による一時領域への実行ファイル・スクリプト投下 ({target_file})"
        )


def _screen_registry_event(event: NormalizedEvent, reasons: list[str]) -> None:
    """Sysmon Event ID 12/13/14 (RegistryEvent) の永続化・防衛機能無効化を判定します。"""
    target_obj = event.event_details.get("target_object", "")
    details = event.event_details.get("details", "")
    if not target_obj:
        return
    target_lower = target_obj.lower()
    details_lower = details.lower()
    src_base = _image_basename(event.image)

    if any(path_pat in target_lower for path_pat in config.CRITICAL_REGISTRY_PATHS):
        reasons.append(
            f"[CRITICAL候補] 防衛機能妨害または高危険度永続化レジストリ変更 ({target_obj})"
        )
        return

    if any(path_pat in target_lower for path_pat in config.PERSISTENCE_REGISTRY_PATHS):
        is_suspicious_val = (
            any(tp.lower() in details_lower for tp in config.SUSPICIOUS_TEMP_PATHS)
            or any(kw.lower() in details_lower for kw in config.SUSPICIOUS_KEYWORDS)
            or src_base in config.DROPPER_SOURCE_IMAGES
            or src_base == "reg.exe"
        )
        if is_suspicious_val:
            reasons.append(
                f"レジストリ自動起動 (Run/Startup) への不審な永続化登録 ({target_obj} -> {details})"
            )


def _screen_dns_event(event: NormalizedEvent, reasons: list[str]) -> None:
    """Sysmon Event ID 22 (DNSEvent) の不審名前解決・DNSトンネリングを判定します。"""
    qname = (event.event_details.get("query_name") or "").strip()
    if not qname:
        return
    q_lower = qname.lower().rstrip(".")
    if q_lower in ("localhost", "wpad") or q_lower.endswith((".local", ".arpa", ".lan", ".home")):
        return

    src_base = _image_basename(event.image)
    src_lower = (event.image or "").lower()
    is_lolbin_or_temp = (
        src_base in config.SUSPICIOUS_NETWORK_IMAGES
        or any(p in src_lower for p in ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"))
    )

    # 1. ダイナミックDNS・C2悪用・トンネル系ドメイン
    high_risk_dns = (
        ".onion",
        "ngrok.io",
        "ngrok-free.app",
        "trycloudflare.com",
        "duckdns.org",
        "no-ip.com",
        "ddns.net",
        "interact.sh",
        "burpcollaborator.net",
    )
    if any(dom in q_lower for dom in high_risk_dns):
        reasons.append(f"不審/ダイナミックDNSドメインへの名前解決 ({event.image} -> {qname})")
        return

    if is_lolbin_or_temp and any(dom in q_lower for dom in config.SUSPICIOUS_DNS_DOMAINS):
        reasons.append(f"LOLBin/一時ディレクトリプロセスによる不審ドメイン参照 ({event.image} -> {qname})")
        return

    # 2. LOLBin / スクリプトホストによる外部名前解決
    if src_base in config.SUSPICIOUS_NETWORK_IMAGES:
        reasons.append(f"LOLBin/スクリプトホスト ({src_base}) によるDNS名前解決 ({qname})")
        return

    # 3. 高リスク一時ディレクトリ上のプロセスによる外部名前解決
    if any(p in src_lower for p in ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\")):
        reasons.append(f"一時・公開フォルダ上のプロセスによるDNS名前解決 ({event.image} -> {qname})")
        return

    # 4. DNSトンネリング疑いの異常長ラベル/クエリ長
    if not q_lower.endswith(config.BENIGN_LONG_DNS_SUFFIXES):
        max_label_len = max((len(lbl) for lbl in q_lower.split(".")), default=0)
        if max_label_len >= 50 or len(q_lower) >= 100:
            reasons.append(f"DNSトンネリング疑いの異常長クエリを検知 ({qname})")


def _is_uv_python_runtime(img_lower: str) -> bool:
    """`uv` 管理の公式 Python ランタイム (`AppData\\Roaming\\uv\\python\\...`) かを判定します。"""
    return (
        "\\appdata\\roaming\\uv\\python\\" in img_lower
        and _image_basename(img_lower) in ("python.exe", "pythonw.exe")
    )


def _find_temp_payload_in_command_line(cmd_lower: str) -> str | None:
    """
    コマンドラインが一時・不審ディレクトリ配下の実行ファイル・スクリプトを参照している場合、
    一致したディレクトリパターンを返します（`uv` Python 本体のパス文字列は除外して誤検知を防ぎます）。
    """
    if not cmd_lower:
        return None
    cleaned_cmd = _UV_PYTHON_EXE_RE.sub("", cmd_lower)
    high_risk_temp = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\")

    for temp_path in config.SUSPICIOUS_TEMP_PATHS:
        tp_lower = temp_path.lower()
        if tp_lower not in cleaned_cmd:
            continue
        exts = (
            config.SUSPICIOUS_EXTENSIONS + (".py", ".pyw")
            if tp_lower in high_risk_temp
            else config.SUSPICIOUS_EXTENSIONS
        )
        ext_alt = "|".join(re.escape(ext) for ext in exts)
        pattern = re.escape(tp_lower) + r"[^\"'\r\n]*?(?:" + ext_alt + r")(?=[\s\"';,&|]|$)"
        if re.search(pattern, cleaned_cmd, re.IGNORECASE):
            return temp_path
    return None


def _enrich_live_command_line_if_empty(event: NormalizedEvent) -> None:
    """
    Sysmon Event ID 3 等で CommandLine が欠落している場合、対象プロセスがまだ稼働中であれば
    psutil を用いて読み取り専用で実際のコマンドラインと親PIDを補完します。
    """
    if event.command_line or not event.process_id or event.process_id <= 4:
        return
    if not HAS_PSUTIL or psutil is None:
        return

    try:
        proc = psutil.Process(event.process_id)
        expected_base = _image_basename(event.image)
        actual_name = (proc.name() or "").lower()
        if expected_base and expected_base != actual_name:
            return
        cmdline_list = proc.cmdline()
        if cmdline_list:
            event.command_line = " ".join(cmdline_list)
        if event.parent_process_id is None:
            event.parent_process_id = proc.ppid()
    except Exception:
        return


def screen_event(event: NormalizedEvent) -> tuple[bool, list[str]]:
    """
    【第1層: ルールベース一次スクリーニング】
    すべてのイベントをGeminiに渡すことを防ぎ、不審候補のみを抽出します。

    判定基準:
    1. コマンドラインに不審キーワード・Sysmon無効化コマンドが含まれる。
    2. 一時ディレクトリ (`AppData\\Local\\Temp` 等) からのスクリプト・実行ファイル起動。
    3. Sysmon Event ID 3 で PowerShell / cmd / rundll32 / mshta 等が外部IPへ通信。
    4. Security Event ID 4625 (ログオン失敗) のうちリモート・ネットワーク経由の不審試行。
    5. Sysmon改ざん・ログ消去・サービス停止などの Defense Evasion イベント
       (Sysmon 4/16/255, Security 1102/4719, System 104/7036/7040)。
    6. 拡張Sysmon検知: スレッド注入 (ID 8)、LSASSメモリ読取等 (ID 10)、
       永続化/不審ファイル作成 (ID 11)、レジストリ永続化/無効化 (ID 12/13)、DNS (ID 22)。
    """
    # 監視エージェント自身のプロセス (API通信やイベント照会等) による自己検知を防止
    if event.process_id in (os.getpid(), os.getppid()) and event.event_id in (1, 3, 22):
        event.screening_reasons = []
        return (False, [])

    img_lower = (event.image or "").lower()
    is_uv_python = _is_uv_python_runtime(img_lower)

    # ID 3 等でコマンドラインが空の不審候補/Pythonプロセスは稼働中情報からコマンドラインを補完
    if (
        event.event_id == 3
        and not event.command_line
        and (
            is_uv_python
            or _image_basename(img_lower) in config.SUSPICIOUS_NETWORK_IMAGES
            or any(tp.lower() in img_lower for tp in config.SUSPICIOUS_TEMP_PATHS)
        )
    ):
        _enrich_live_command_line_if_empty(event)

    reasons: list[str] = list(event.screening_reasons)
    cmd_lower = (event.command_line or "").lower()
    parent_cmd_lower = (event.parent_command_line or "").lower()

    # 条件0: Sysmon / ログ改ざん・サービス停止関連のイベントID直接検知
    if event.channel == config.SYSMON_CHANNEL:
        if event.event_id == 4:
            if "state=started" not in cmd_lower:
                reasons.append(
                    f"[CRITICAL候補] Sysmon サービス状態変化/停止検知 ({event.command_line})"
                )
        elif event.event_id == 16:
            reasons.append(
                f"[CRITICAL候補] Sysmon 設定変更/ルール改ざん検知 ({event.command_line})"
            )
        elif event.event_id == 255:
            reasons.append(
                f"[CRITICAL候補] Sysmon エラー/異常報告 ({event.command_line})"
            )
        elif event.event_id == 8:
            _screen_create_remote_thread(event, reasons)
        elif event.event_id == 10:
            _screen_process_access(event, reasons)
        elif event.event_id == 11:
            _screen_file_create(event, reasons)
        elif event.event_id in (12, 13, 14):
            _screen_registry_event(event, reasons)
        elif event.event_id == 22:
            _screen_dns_event(event, reasons)
    elif event.event_id in (1102, 104):
        reasons.append(
            f"[CRITICAL候補] イベントログ消去を検知 (EventID={event.event_id}: {event.command_line})"
        )
    elif event.event_id == 4719:
        if any(tok in cmd_lower for tok in ("removed", "disable", "%%8448", "-")):
            reasons.append(
                f"[CRITICAL候補] システム監査ポリシーの無効化/削除を検知 ({event.command_line})"
            )
    elif event.channel == config.SYSTEM_CHANNEL and event.event_id in (7036, 7040):
        if any(svc in cmd_lower for svc in ("sysmon", "eventlog", "windows event log")):
            if any(st in cmd_lower for st in ("stopped", "停止", "disabled", "無効", "demand", "手動")):
                reasons.append(
                    f"[CRITICAL候補] 監視関連サービス (Sysmon/EventLog) の停止・設定変更を検知 ({event.command_line})"
                )

    # 条件1: コマンドライン（または親プロセスコマンドライン）の不審キーワード・Sysmon CLI改ざん検査
    # (ID 8/10/11/22 は専用スクリーニングに委ね、不要な部分一致誤検知を防止)
    if event.event_id not in (8, 10, 11, 22):
        if _SYSMON_CLI_TAMPER_RE.search(event.command_line or ""):
            reasons.append("コマンドラインで Sysmon のアンインストール/設定変更 (-u / -c) を検出")
        elif _SYSMON_CLI_TAMPER_RE.search(event.parent_command_line or ""):
            reasons.append("親プロセスで Sysmon のアンインストール/設定変更 (-u / -c) を検出")

        for keyword in config.SUSPICIOUS_KEYWORDS:
            kw_lower = keyword.lower()
            if kw_lower in cmd_lower:
                reasons.append(f"コマンドラインに不審キーワード '{keyword}' を検出")
            elif kw_lower in parent_cmd_lower:
                reasons.append(f"親プロセスコマンドラインに不審キーワード '{keyword}' を検出")

    # 条件2: 一時ディレクトリからの実行ファイル・スクリプト起動検査 (プロセス生成イベントのみ対象)
    temp_cmd_match = _find_temp_payload_in_command_line(cmd_lower)
    if event.event_id in (1, 4688):
        for temp_path in config.SUSPICIOUS_TEMP_PATHS:
            tp_lower = temp_path.lower()
            if tp_lower in img_lower and not is_uv_python:
                if any(img_lower.endswith(ext) for ext in config.SUSPICIOUS_EXTENSIONS):
                    reasons.append(f"一時・不審ディレクトリからの実行ファイル起動 ({event.image})")
                else:
                    reasons.append(f"一時・不審ディレクトリ内のプロセスイメージ起動 ({event.image})")
        if temp_cmd_match:
            reasons.append(
                f"コマンドラインが一時・不審ディレクトリ内のスクリプト/実行ファイルを参照 ({temp_cmd_match})"
            )

    # 条件3: Sysmon Event ID 3 (ネットワーク接続) の一次スクリーニング
    if event.event_id == 3 and event.destination_ip:
        if event.destination_ip not in ("127.0.0.1", "::1", "0.0.0.0", "-"):
            image_basename = _image_basename(event.image)
            if image_basename in config.SUSPICIOUS_NETWORK_IMAGES:
                reasons.append(
                    f"LOLBin/スクリプトホスト ({image_basename}) による外部通信 "
                    f"({event.destination_ip}:{event.destination_port})"
                )
            elif any(tp.lower() in img_lower for tp in config.SUSPICIOUS_TEMP_PATHS) and not is_uv_python:
                reasons.append(
                    f"一時ディレクトリ上のプロセスによる外部通信 "
                    f"({event.destination_ip}:{event.destination_port})"
                )
            elif is_uv_python and temp_cmd_match:
                reasons.append(
                    f"uv Python が一時ディレクトリ上のスクリプトから外部通信 "
                    f"({event.destination_ip}:{event.destination_port})"
                )

    # 条件4: Security Event ID 4625 (ログオン失敗) の不審パターン
    if event.event_id == 4625:
        # LogonType 3 (Network) または 10 (RemoteInteractive/RDP) で外部IPを伴う失敗
        if event.logon_type in ("3", "10") and event.destination_ip not in ("", "-", "127.0.0.1", "::1"):
            reasons.append(
                f"リモートログオン失敗 (LogonType={event.logon_type}, SourceIP={event.destination_ip})"
            )

    # 重複理由を順序維持で除外
    deduped_reasons = list(dict.fromkeys(reasons))
    event.screening_reasons = deduped_reasons

    # ホワイトリスト (allowlist.json) 照合: 改ざん・注入・LSASSアクセス等以外の許可ルールを除外
    if deduped_reasons:
        is_allowed, allow_reason = allowlist.is_event_allowlisted(event)
        if is_allowed:
            logger.debug(
                "許可リスト一致のためスキップ (EventID=%d, RecordID=%d): %s",
                event.event_id,
                event.event_record_id,
                allow_reason,
            )
            event.screening_reasons = []
            return (False, [])

    return (len(deduped_reasons) > 0, deduped_reasons)


class CheckpointManager:
    """
    `checkpoint.json` にチャネルごとの最新処理済み `EventRecordID` を記録・管理するクラス。
    破壊的なファイル削除を一切行わず、チェックポイントファイルへの保存のみを行います。
    """

    def __init__(self, checkpoint_path: Path = config.CHECKPOINT_FILE) -> None:
        self.checkpoint_path: Path = checkpoint_path
        self._checkpoints: dict[str, int] = self.load()

    def load(self) -> dict[str, int]:
        """checkpoint.json から各チャネルの最新 EventRecordID を読み込みます。"""
        if not self.checkpoint_path.exists():
            return {}
        try:
            content = self.checkpoint_path.read_text(encoding="utf-8").strip()
            if not content:
                return {}
            data = json.loads(content)
            if isinstance(data, dict):
                return {
                    str(k): int(v)
                    for k, v in data.items()
                    if isinstance(v, (int, float, str)) and str(v).isdigit()
                }
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("checkpoint.json の読み込み中に警告が発生しました (既存値は保持): %s", exc)
        return {}

    def get_last_record_id(self, channel: str) -> int:
        """指定チャネルの最終処理済み EventRecordID を返します（未記録時は 0）。"""
        return self._checkpoints.get(channel, 0)

    def update(self, channel: str, record_id: int, persist: bool = True) -> None:
        """
        指定チャネルの EventRecordID を単調増加（現在の値より大きい場合のみ）で更新し、
        checkpoint.json へ記録します。
        """
        current = self._checkpoints.get(channel, 0)
        if record_id > current:
            self._checkpoints[channel] = record_id
            if persist:
                self.save()

    def reset_channel(self, channel: str, new_record_id: int = 0) -> None:
        """
        ログ消去等による EventRecordID 巻き戻りを検知した際、ファイルを削除せず
        該当チャネルのチェックポイントのみ安全にリセットして監視を復旧します。
        """
        self._checkpoints[channel] = max(0, int(new_record_id))
        self.save(skip_merge_channels={channel})

    def save(self, skip_merge_channels: set[str] | None = None) -> None:
        """現在のチェックポイント辞書を checkpoint.json に保存します。"""
        skip_set = skip_merge_channels or set()
        try:
            # 既存ファイルがある場合はマージして単調増加を保証 (リセット指定チャネルは除外)
            if self.checkpoint_path.exists():
                try:
                    existing = json.loads(self.checkpoint_path.read_text(encoding="utf-8") or "{}")
                    if isinstance(existing, dict):
                        for ch, rid in existing.items():
                            if ch in skip_set:
                                continue
                            if isinstance(rid, int) and rid > self._checkpoints.get(ch, 0):
                                self._checkpoints[ch] = rid
                except (OSError, ValueError, json.JSONDecodeError):
                    pass

            serialized = json.dumps(self._checkpoints, indent=2, ensure_ascii=False)
            with open(self.checkpoint_path, mode="w", encoding="utf-8") as fp:
                fp.write(serialized + "\n")
        except OSError as exc:
            logger.error("checkpoint.json の保存に失敗しました: %s", exc)


class WindowsEventReader:
    """
    pywin32 (`win32evtlog`) を用いて Windows イベントログを読み取り専用で取得するクラス。
    Sysmon の改ざん・ログ消去・サービス停止の検知および Security (4688) 自動フォールバックを備えます。
    """

    def __init__(self, checkpoint_manager: CheckpointManager) -> None:
        self.checkpoint_manager = checkpoint_manager
        self.sysmon_available: bool | None = None
        self.sysmon_service_running: bool | None = None
        self._known_sysmon_service_name: str | None = None
        self._tamper_alert_cooldowns: dict[str, float] = {}
        self._pending_tamper_events: list[NormalizedEvent] = []

    @staticmethod
    def _build_xpath_query(event_ids: set[int], last_record_id: int) -> str:
        """指定された EventID 集合と EventRecordID 下限に基づく XPath クエリを生成します。"""
        id_conditions = " or ".join(f"EventID={eid}" for eid in sorted(event_ids))
        return (
            f"*[System[({id_conditions}) and (EventRecordID > {int(last_record_id)})]]"
        )

    @staticmethod
    def _utc_now_str() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _should_emit_tamper_alert(self, key: str) -> bool:
        """同一のサービス停止・改ざんアラートが15秒ごとに連続発報されるのを防ぎます。"""
        now = time.monotonic()
        last_ts = self._tamper_alert_cooldowns.get(key)
        if last_ts is not None and (now - last_ts) < config.SERVICE_HEARTBEAT_COOLDOWN_SECONDS:
            return False
        self._tamper_alert_cooldowns[key] = now
        return True

    def _make_tamper_event(
        self,
        channel: str,
        event_id: int,
        image: str,
        command_line: str,
        reason: str,
        record_id: int = 0,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            channel=channel,
            event_id=event_id,
            event_record_id=record_id,
            utc_time=self._utc_now_str(),
            process_id=None,
            image=image,
            command_line=command_line,
            screening_reasons=[reason],
        )

    def _get_latest_channel_record_id(self, channel: str) -> tuple[bool, int | None]:
        """
        指定チャネルに存在する最新の EventRecordID を読み取り専用で取得します。
        戻り値: (クエリ成功フラグ, 最新EventRecordID または 空の場合None)
        """
        if not HAS_PYWIN32 or win32evtlog is None:
            return (False, None)
        try:
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            query_handle = win32evtlog.EvtQuery(channel, flags, "*", None)
            raw_handles = win32evtlog.EvtNext(query_handle, 1, 1000, 0)
            if not raw_handles:
                return (True, None)
            xml_str = win32evtlog.EvtRender(raw_handles[0], win32evtlog.EvtRenderEventXml)
            parsed = parse_event_xml(xml_str, default_channel=channel)
            if parsed is None:
                return (False, None)
            return (True, parsed.event_record_id)
        except Exception as exc:
            self._handle_evtlog_exception(channel, exc)
            return (False, None)

    def check_tamper_health(self) -> list[NormalizedEvent]:
        """
        Windows の EventLog / Sysmon サービス稼働状態を読み取り専用で確認し、
        停止・無効化・アンインストールを検知した場合は改ざんアラートイベントを返します。
        """
        alerts: list[NormalizedEvent] = []
        if not HAS_PSUTIL or psutil is None or not hasattr(psutil, "win_service_get"):
            return alerts

        # 1. Windows EventLog サービス死活チェック
        try:
            evt_svc = psutil.win_service_get("EventLog")
            evt_status = (evt_svc.status() or "").lower()
            if evt_status != "running":
                if self._should_emit_tamper_alert("service_eventlog_down"):
                    alerts.append(
                        self._make_tamper_event(
                            channel=config.SYSTEM_CHANNEL,
                            event_id=7036,
                            image="EventLog Service",
                            command_line=f"Windows EventLog service is NOT running (status={evt_status})",
                            reason=f"[CRITICAL候補] Windows EventLog サービス停止検知 (status={evt_status})",
                        )
                    )
            else:
                self._tamper_alert_cooldowns.pop("service_eventlog_down", None)
        except Exception as exc:
            logger.debug("EventLog サービス状態確認エラー: %s", exc)

        # 2. Sysmon サービス (Sysmon64 / Sysmon) 死活チェック
        found_svc_name: str | None = None
        found_svc_status: str = ""
        svc_access_denied = False
        for candidate_name in ("Sysmon64", "Sysmon"):
            try:
                svc = psutil.win_service_get(candidate_name)
                found_svc_name = candidate_name
                found_svc_status = (svc.status() or "").lower()
                break
            except (psutil.AccessDenied, PermissionError) as perm_exc:
                svc_access_denied = True
                logger.debug("サービス '%s' の状態照会権限が不足しています: %s", candidate_name, perm_exc)
                break
            except psutil.NoSuchProcess:
                continue
            except Exception as svc_exc:
                logger.debug("サービス '%s' の状態照会中に例外が発生しました: %s", candidate_name, svc_exc)
                continue

        if found_svc_name is not None:
            self._known_sysmon_service_name = found_svc_name
            if found_svc_status == "running":
                if self.sysmon_service_running is False:
                    logger.info("Sysmon サービス (%s) の復旧・稼働再開を確認しました。", found_svc_name)
                self.sysmon_service_running = True
                self._tamper_alert_cooldowns.pop("service_sysmon_down", None)
                if self.sysmon_available is False:
                    # 再導入された場合のためチャネル再探索を許可
                    self.sysmon_available = None
            else:
                self.sysmon_service_running = False
                logger.error(
                    "[Sysmon異常検知] サービス '%s' が停止状態です (status=%s)。Security 4688 監視を有効化します。",
                    found_svc_name,
                    found_svc_status,
                )
                if self._should_emit_tamper_alert("service_sysmon_down"):
                    alerts.append(
                        self._make_tamper_event(
                            channel=config.SYSMON_CHANNEL,
                            event_id=4,
                            image=found_svc_name,
                            command_line=f"Sysmon service '{found_svc_name}' is NOT running (status={found_svc_status})",
                            reason=f"[CRITICAL候補] Sysmon サービス '{found_svc_name}' の停止・無効化を検知 (status={found_svc_status})",
                        )
                    )
        elif svc_access_denied:
            # 権限不足時は状態不明として扱い、誤った「サービス消失」アラートを出さない
            pass
        else:
            # 過去に Sysmon 稼働を確認済みだったのにサービスごと消滅した場合（アンインストール/削除）
            if self._known_sysmon_service_name is not None or self.sysmon_available is True:
                prev_name = self._known_sysmon_service_name or "Sysmon64"
                self.sysmon_service_running = False
                self.sysmon_available = False
                if self._should_emit_tamper_alert("service_sysmon_removed"):
                    alerts.append(
                        self._make_tamper_event(
                            channel=config.SYSMON_CHANNEL,
                            event_id=4,
                            image=prev_name,
                            command_line=f"Sysmon service '{prev_name}' disappeared / uninstalled during monitoring",
                            reason=f"[CRITICAL候補] 稼働中だった Sysmon サービス '{prev_name}' の消失・アンインストールを検知",
                        )
                    )
            else:
                self.sysmon_service_running = False

        return alerts

    def read_channel_events(
        self,
        channel: str,
        target_event_ids: set[int],
        max_events: int = config.MAX_EVENTS_PER_POLL,
        _rewind_checked: bool = False,
    ) -> list[NormalizedEvent]:
        """
        指定されたチャネルから未処理のイベントを読み取り専用で取得します。
        管理者権限不足エラー・チャネル消失・EventRecordID巻き戻り（ログ消去）を検知します。
        """
        if not HAS_PYWIN32 or win32evtlog is None:
            logger.error(
                "pywin32 (win32evtlog) がインストールされていないため、イベントログを取得できません。"
            )
            return []

        last_record_id = self.checkpoint_manager.get_last_record_id(channel)
        xpath_query = self._build_xpath_query(target_event_ids, last_record_id)
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

        if last_record_id == 0:
            flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection

        events: list[NormalizedEvent] = []
        try:
            query_handle = win32evtlog.EvtQuery(channel, flags, xpath_query, None)
        except Exception as exc:
            self._handle_evtlog_exception(channel, exc)
            return []

        if channel == config.SYSMON_CHANNEL:
            self.sysmon_available = True

        try:
            raw_handles = win32evtlog.EvtNext(query_handle, max_events, 2000, 0)
            for evt_handle in raw_handles:
                try:
                    xml_str = win32evtlog.EvtRender(
                        evt_handle, win32evtlog.EvtRenderEventXml
                    )
                    parsed = parse_event_xml(xml_str, default_channel=channel)
                    if parsed is not None:
                        events.append(parsed)
                except Exception as render_exc:
                    logger.debug("イベントXMLのレンダリング失敗: %s", render_exc)
        except Exception as next_exc:
            logger.warning("チャネル '%s' からのイベント列挙中にエラーが発生しました: %s", channel, next_exc)

        # 件数0かつ既知の last_record_id > 0 の場合、ログ消去による EventRecordID 巻き戻りを点検
        if not events and last_record_id > 0 and not _rewind_checked:
            ok, newest_id = self._get_latest_channel_record_id(channel)
            if ok and (newest_id is None or newest_id < last_record_id):
                logger.error(
                    "[改ざん/ログ消去検知] チャネル '%s' の EventRecordID が巻き戻りました "
                    "(前回ID=%d -> 現在最新ID=%s)。チェックポイントをリセットして監視を即時復旧します。",
                    channel,
                    last_record_id,
                    newest_id,
                )
                self.checkpoint_manager.reset_channel(channel, 0)
                tamper_eid = 1102 if channel == config.SECURITY_CHANNEL else 104
                rewind_alert = self._make_tamper_event(
                    channel=channel,
                    event_id=tamper_eid,
                    image="Windows Event Log Tamper Detection",
                    command_line=(
                        f"EventRecordID rollback detected on '{channel}': "
                        f"previous={last_record_id}, current_newest={newest_id}"
                    ),
                    reason=(
                        f"[CRITICAL候補] チャネル '{channel}' のイベントログ消去 / EventRecordID巻き戻りを検知 "
                        f"(前回ID={last_record_id} -> 現在最新ID={newest_id})"
                    ),
                    record_id=newest_id or 0,
                )
                recovered_events = self.read_channel_events(
                    channel=channel,
                    target_event_ids=target_event_ids,
                    max_events=max_events,
                    _rewind_checked=True,
                )
                return [rewind_alert, *recovered_events]

        # EvtQueryReverseDirection で取得した場合は時系列順（EventRecordID 昇順）に整列
        events.sort(key=lambda e: e.event_record_id)

        # キャッシュ登録とチェックポイント更新
        highest_id = last_record_id
        for ev in events:
            register_event_in_cache(ev)
            if ev.event_record_id > highest_id:
                highest_id = ev.event_record_id

        if highest_id > last_record_id:
            self.checkpoint_manager.update(channel, highest_id, persist=True)

        return events

    def poll_suspicious_candidates(self) -> list[NormalizedEvent]:
        """
        Sysmon / Security / System チャネルおよびサービス死活を巡回し、
        一次スクリーニングを通過した「不審候補イベント」のみをリストで返します。
        """
        candidates: list[NormalizedEvent] = []

        # 0. Sysmon / EventLog サービス死活チェック（Heartbeat）
        tamper_health_events = self.check_tamper_health()

        # 1. Microsoft-Windows-Sysmon/Operational の巡回 (Event ID 1, 3, 4, 16, 255)
        if self.sysmon_available is not False:
            sysmon_events = self.read_channel_events(
                channel=config.SYSMON_CHANNEL,
                target_event_ids=config.SYSMON_EVENT_IDS,
            )
            for ev in sysmon_events:
                is_suspicious, _ = screen_event(ev)
                if is_suspicious:
                    candidates.append(ev)

        # 2. Security チャネルの巡回 (1102, 4624, 4625, 4688, 4719)
        security_events = self.read_channel_events(
            channel=config.SECURITY_CHANNEL,
            target_event_ids=config.SECURITY_EVENT_IDS,
        )
        sysmon_actively_recording = (
            self.sysmon_available is True and self.sysmon_service_running is not False
        )
        for ev in security_events:
            # Sysmon が有効かつサービス稼働中の場合のみ 4688 重複をスキップし、停止/未導入時は補完監視へ自動切替
            if ev.event_id == 4688 and sysmon_actively_recording:
                continue
            is_suspicious, _ = screen_event(ev)
            if is_suspicious:
                candidates.append(ev)

        # 3. System チャネルの巡回 (104 ログ消去, 7036/7040 Sysmon/EventLogサービス変更)
        system_events = self.read_channel_events(
            channel=config.SYSTEM_CHANNEL,
            target_event_ids=config.SYSTEM_EVENT_IDS,
        )
        for ev in system_events:
            is_suspicious, _ = screen_event(ev)
            if is_suspicious:
                candidates.append(ev)

        # 4. 改ざん・サービス停止検知イベントを統合
        if self._pending_tamper_events:
            candidates.extend(self._pending_tamper_events)
            self._pending_tamper_events.clear()
        candidates.extend(tamper_health_events)

        return candidates

    def _handle_evtlog_exception(self, channel: str, exc: Exception) -> None:
        """
        pywin32 のイベントログ読み取り例外（権限不足・チャネル未導入・削除等）を判別し、
        分かりやすいメッセージでログ出力します。
        """
        winerror = getattr(exc, "winerror", None)
        if winerror == 5 or isinstance(exc, PermissionError):
            logger.error(
                "[権限不足エラー] チャネル '%s' の読み取りが拒否されました (WinError 5: Access Denied)。"
                "PowerShell または コマンドプロンプトを『管理者として実行』して再起動してください。",
                channel,
            )
        elif winerror in (15007, 2):
            if channel == config.SYSMON_CHANNEL:
                if self.sysmon_available is True:
                    logger.error(
                        "[重大・Sysmonチャネル消失] 稼働中だったチャネル '%s' が消失しました (WinError %s)。"
                        "Sysmonアンインストール・改ざんの疑いがあります。Security 4688 へ切り替えます。",
                        channel,
                        winerror,
                    )
                    if self._should_emit_tamper_alert("channel_sysmon_vanished"):
                        self._pending_tamper_events.append(
                            self._make_tamper_event(
                                channel=config.SYSMON_CHANNEL,
                                event_id=4,
                                image="Sysmon Channel",
                                command_line=f"Sysmon channel '{channel}' vanished during monitoring (WinError {winerror})",
                                reason=f"[CRITICAL候補] 監視中だった Sysmon チャネルの消失・削除を検知 (WinError {winerror})",
                            )
                        )
                elif self.sysmon_available is not False:
                    logger.warning(
                        "[Sysmon未検出] チャネル '%s' が見つかりません (WinError %s)。"
                        "Sysmon未導入環境と判定し、Security イベントログ (Event ID 4688) へフォールバックします。",
                        channel,
                        winerror,
                    )
                self.sysmon_available = False
            else:
                logger.warning("チャネル '%s' が見つかりません: %s", channel, exc)
        else:
            logger.error("チャネル '%s' のクエリ実行中にエラーが発生しました: %s", channel, exc)
