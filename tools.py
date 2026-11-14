"""
Gemini 自律調査ループ用 Read-Only ツール関数群 (tools.py)

Google Gemini (Function Calling) が不審イベントのコンテキストを深掘りするために呼び出す
完全読み取り専用（Read-Only）のネイティブPython関数を定義します。
生XMLは一切返さず、トークン最適化された指定フィールド辞書のみを返却します。
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any

import config
from event_reader import (
    HAS_PSUTIL,
    HAS_PYWIN32,
    NormalizedEvent,
    get_cached_events,
    parse_event_xml,
    psutil,
    register_event_in_cache,
    win32evtlog,
)

logger = logging.getLogger("sysmon_gemini_agent.tools")


def _query_sysmon_events_readonly(xpath_query: str, max_results: int = 25) -> list[NormalizedEvent]:
    """
    Microsoft-Windows-Sysmon/Operational チャネルに対して読み取り専用のXPathクエリを実行し、
    NormalizedEvent のリストを返します（新しい順）。
    """
    if not HAS_PYWIN32 or win32evtlog is None:
        return []

    results: list[NormalizedEvent] = []
    try:
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        query_handle = win32evtlog.EvtQuery(
            config.SYSMON_CHANNEL,
            flags,
            xpath_query,
            None,
        )
        raw_handles = win32evtlog.EvtNext(query_handle, max_results, 1500, 0)
        for evt_handle in raw_handles:
            try:
                xml_str = win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)
                parsed = parse_event_xml(xml_str, default_channel=config.SYSMON_CHANNEL)
                if parsed is not None:
                    register_event_in_cache(parsed)
                    results.append(parsed)
            except Exception as render_exc:
                logger.debug("ツール内XMLレンダリング失敗: %s", render_exc)
    except Exception as exc:
        logger.debug("Sysmon Read-Only クエリ失敗 (%s): %s", xpath_query, exc)

    return results


def _query_security_process_readonly(process_id: int, max_results: int = 10) -> list[NormalizedEvent]:
    """
    Sysmon未導入時のフォールバックとして Security チャネル (Event ID 4688) から
    指定された ProcessId (16進数表記) のプロセス生成イベントを読み取り専用で検索します。
    """
    if not HAS_PYWIN32 or win32evtlog is None:
        return []

    hex_pid = hex(process_id)
    xpath_query = (
        f"*[System[(EventID=4688)] and "
        f"EventData[Data[@Name='NewProcessId']='{hex_pid}' or Data[@Name='NewProcessId']='{process_id}']]"
    )
    results: list[NormalizedEvent] = []
    try:
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        query_handle = win32evtlog.EvtQuery(
            config.SECURITY_CHANNEL,
            flags,
            xpath_query,
            None,
        )
        raw_handles = win32evtlog.EvtNext(query_handle, max_results, 1500, 0)
        for evt_handle in raw_handles:
            try:
                xml_str = win32evtlog.EvtRender(evt_handle, win32evtlog.EvtRenderEventXml)
                parsed = parse_event_xml(xml_str, default_channel=config.SECURITY_CHANNEL)
                if parsed is not None:
                    register_event_in_cache(parsed)
                    results.append(parsed)
            except Exception as render_exc:
                logger.debug("Security 4688 XMLレンダリング失敗: %s", render_exc)
    except Exception as exc:
        logger.debug("Security Read-Only クエリ失敗 (PID=%s): %s", process_id, exc)

    return results


def get_parent_process(parent_process_id: int) -> dict:
    """指定された親プロセスID (ParentProcessId) の実行イメージおよびコマンドライン情報を取得します。

    不審なプロセスがどの親プロセス（例: explorer.exe, cmd.exe, winword.exe, powershell.exe,
    タスクスケジューラ、WMI 等）から起動されたかを特定し、正規の管理操作かマルウェア/攻撃かを
    切り分けるために使用します。システムへの変更は一切行わない完全読み取り専用ツールです。

    Args:
        parent_process_id: 調査対象となる親プロセスのプロセスID (PID, 整数値)。

    Returns:
        dict: トークン最適化された親プロセス情報の辞書。以下のキーを含みます:
            - UtcTime (str): 親プロセス起動時刻 (UTC)
            - ProcessId (int | None): 親プロセスのPID
            - Image (str): 親プロセスの実行ファイルパス
            - CommandLine (str): 親プロセスの起動コマンドライン引数
            - ParentProcessId (int | None): さらに上位の親プロセス（祖父母プロセス）のPID
            - ParentCommandLine (str): 祖父母プロセスのコマンドラインまたはイメージ名
            - DestinationIp (str): 通信先IP（プロセス生成イベントでは通常空文字）
            - DestinationPort (int | None): 通信先ポート（プロセス生成イベントでは通常None）
    """
    try:
        target_pid = int(parent_process_id)
    except (TypeError, ValueError):
        return {
            "UtcTime": "",
            "ProcessId": None,
            "Image": "",
            "CommandLine": "Invalid parent_process_id parameter",
            "ParentProcessId": None,
            "ParentCommandLine": "",
            "DestinationIp": "",
            "DestinationPort": None,
        }

    logger.info("[Tool Call] get_parent_process(parent_process_id=%d) を実行中...", target_pid)

    # 1. インメモリキャッシュからプロセス生成イベント (Event ID 1 または 4688) を優先検索
    for ev in get_cached_events():
        if ev.event_id in (1, 4688) and ev.process_id == target_pid:
            return ev.to_trimmed_dict()

    # 2. Sysmon Event ID 1 から対象PIDのプロセス生成イベントを直接クエリ
    xpath = (
        f"*[System[(EventID=1)] and "
        f"EventData[Data[@Name='ProcessId']='{target_pid}']]"
    )
    sysmon_matches = _query_sysmon_events_readonly(xpath, max_results=5)
    for ev in sysmon_matches:
        if ev.process_id == target_pid:
            return ev.to_trimmed_dict()

    # 3. Sysmon未導入時のフォールバック: Security Event ID 4688 を検索
    security_matches = _query_security_process_readonly(target_pid, max_results=5)
    for ev in security_matches:
        if ev.process_id == target_pid:
            return ev.to_trimmed_dict()

    # 4. キャッシュ内の子イベントに記録されている ParentImage / ParentCommandLine から補完
    for ev in get_cached_events():
        if ev.parent_process_id == target_pid and (ev.parent_image or ev.parent_command_line):
            return {
                "UtcTime": ev.utc_time,
                "ProcessId": target_pid,
                "Image": ev.parent_image,
                "CommandLine": ev.parent_command_line,
                "ParentProcessId": None,
                "ParentCommandLine": "",
                "DestinationIp": "",
                "DestinationPort": None,
            }

    # 5. ログローテーション済みで過去の起動ログが残っていない場合、稼働中プロセスを Read-Only 照会
    if HAS_PSUTIL and psutil is not None and target_pid > 4:
        try:
            proc = psutil.Process(target_pid)
            exe_path = proc.exe() or proc.name() or ""
            cmdline_str = " ".join(proc.cmdline() or [])
            ppid = proc.ppid()
            create_utc = datetime.fromtimestamp(
                proc.create_time(), tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            return {
                "UtcTime": create_utc,
                "ProcessId": target_pid,
                "Image": exe_path,
                "CommandLine": cmdline_str,
                "ParentProcessId": ppid,
                "ParentCommandLine": "",
                "DestinationIp": "",
                "DestinationPort": None,
            }
        except Exception:
            pass

    # 見つからなかった場合も同一スキーマの空データを返却
    return {
        "UtcTime": "",
        "ProcessId": target_pid,
        "Image": "NOT_FOUND_IN_RECENT_LOGS",
        "CommandLine": "",
        "ParentProcessId": None,
        "ParentCommandLine": "",
        "DestinationIp": "",
        "DestinationPort": None,
    }


def get_process_network_activity(process_id: int) -> list[dict]:
    """指定されたプロセスID (ProcessId) が行った外部通信ログ (Sysmon Event ID 3) およびDNSクエリ (Event ID 22) の一覧を取得します。

    不審なプロセスが外部のC2サーバ、不審なドメイン・IPアドレス、または非標準ポートへ通信（ダウンローダ挙動や
    情報窃取・DNSトンネリング・リバースシェル等）を行っていないかを確認するために使用します。
    システムへの変更は一切行わない完全読み取り専用ツールです。

    Args:
        process_id: 通信履歴を調査する対象プロセスのプロセスID (PID, 整数値)。

    Returns:
        list[dict]: 当該プロセスによるネットワーク接続およびDNSクエリイベント（最大20件）のリスト。
            各要素は以下のキーを持つトークン最適化済み辞書です:
            - UtcTime (str): 通信・名前解決発生時刻 (UTC)
            - ProcessId (int | None): 通信元プロセスのPID
            - Image (str): 通信元プロセスの実行ファイルパス
            - CommandLine (str): コマンドラインまたはDNSクエリ情報
            - ParentProcessId (int | None): 親プロセスPID
            - ParentCommandLine (str): 親プロセスコマンドライン
            - DestinationIp (str): 接続先または名前解決結果IPアドレス
            - DestinationPort (int | None): 接続先ポート番号
    """
    try:
        target_pid = int(process_id)
    except (TypeError, ValueError):
        return []

    logger.info("[Tool Call] get_process_network_activity(process_id=%d) を実行中...", target_pid)

    matched_records: dict[int, dict[str, Any]] = {}

    # 1. インメモリキャッシュ内の Sysmon Event ID 3 / 22 を検索
    for ev in get_cached_events():
        if ev.event_id in (3, 22) and ev.process_id == target_pid:
            matched_records[ev.event_record_id] = ev.to_trimmed_dict()

    # 2. Sysmon Event ID 3 / 22 から対象PIDのネットワーク接続・DNSイベントを直接クエリ
    xpath = (
        f"*[System[(EventID=3 or EventID=22)] and "
        f"EventData[Data[@Name='ProcessId']='{target_pid}']]"
    )
    sysmon_net_events = _query_sysmon_events_readonly(xpath, max_results=20)
    for ev in sysmon_net_events:
        if ev.process_id == target_pid:
            matched_records[ev.event_record_id] = ev.to_trimmed_dict()

    # EventRecordID の降順（新しい通信順）で最大20件を返却
    sorted_keys = sorted(matched_records.keys(), reverse=True)[:20]
    return [matched_records[k] for k in sorted_keys]


def get_process_related_events(process_id: int) -> list[dict]:
    """指定されたプロセスID (ProcessId / SourceProcessId / TargetProcessId) に関連する
    スレッド注入 (ID 8)、プロセスメモリアクセス (ID 10)、ファイル作成 (ID 11)、
    レジストリ変更 (ID 12/13)、DNSクエリ (ID 22) の履歴を取得します。

    一連の攻撃チェーン（ファイル投下→レジストリ永続化→インジェクション/LSASSアクセス）を
    相関分析するために使用する完全読み取り専用ツールです。

    Args:
        process_id: 調査対象プロセスのプロセスID (PID, 整数値)。

    Returns:
        list[dict]: 関連する Sysmon イベント（最大20件）のトークン最適化済み辞書リスト。
    """
    try:
        target_pid = int(process_id)
    except (TypeError, ValueError):
        return []

    logger.info("[Tool Call] get_process_related_events(process_id=%d) を実行中...", target_pid)

    related_ids = (8, 10, 11, 12, 13, 14, 22)
    matched_records: dict[int, dict[str, Any]] = {}
    target_pid_str = str(target_pid)

    for ev in get_cached_events():
        if ev.event_id not in related_ids:
            continue
        is_target_match = (
            ev.process_id == target_pid
            or ev.event_details.get("target_pid") == target_pid_str
        )
        if is_target_match:
            matched_records[ev.event_record_id] = ev.to_trimmed_dict()

    xpath = (
        "*[System[(EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=22)] and "
        f"EventData[(Data[@Name='ProcessId']='{target_pid}' or "
        f"Data[@Name='SourceProcessId']='{target_pid}' or "
        f"Data[@Name='TargetProcessId']='{target_pid}')]]"
    )
    queried_events = _query_sysmon_events_readonly(xpath, max_results=20)
    for ev in queried_events:
        matched_records[ev.event_record_id] = ev.to_trimmed_dict()

    sorted_keys = sorted(matched_records.keys(), reverse=True)[:20]
    return [matched_records[k] for k in sorted_keys]


# Gemini SDK に登録するツール関数リストとディスパッチマップ
AVAILABLE_TOOLS = [
    get_parent_process,
    get_process_network_activity,
    get_process_related_events,
]
TOOL_DISPATCH_MAP = {
    "get_parent_process": get_parent_process,
    "get_process_network_activity": get_process_network_activity,
    "get_process_related_events": get_process_related_events,
}
