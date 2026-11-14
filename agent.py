"""
Google Gemini 自律調査ループ & トリアージレポート出力モジュール (agent.py)

最新の公式 `google-genai` SDK (`from google import genai` / `client = genai.Client()`) を使用し、
一次スクリーニングを通過した不審イベントに対して Read-Only ツール群を用いた
最大 `max_depth = 3` 往復の自律調査ループ（Function Calling）を実行します。
調査結果は `alerts/incident_YYYYMMDD.md` に追記（append）形式で出力します。
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import random
import re
import time
from typing import Any

try:
    from google import genai
    from google.genai import types
    from google.genai.errors import APIError

    HAS_GOOGLE_GENAI = True
except ImportError:
    genai = None  # type: ignore[assignment]
    types = None  # type: ignore[assignment]
    APIError = Exception  # type: ignore[assignment,misc]
    HAS_GOOGLE_GENAI = False

import config
from event_reader import NormalizedEvent
from process_guard import verify_target_process
from tools import AVAILABLE_TOOLS, TOOL_DISPATCH_MAP

logger = logging.getLogger("sysmon_gemini_agent.agent")

SYSTEM_INSTRUCTION = """あなたはWindowsセキュリティ監視（SOC）の専門トリアージAIエージェントです。
ルールベース一次スクリーニングで抽出されたWindowsイベントログ（Sysmon / Security / System）の不審候補について、
提供されたRead-Onlyツール（`get_parent_process`, `get_process_network_activity`, `get_process_related_events`）を必要最小限の回数だけ呼び出して自律調査を行い、最終的なトリアージ判定レポートを日本語のMarkdownで出力してください。

【厳守事項】
1. 調査ループは最大3往復（max_depth = 3）に制限されています。必要な場合のみ `ParentProcessId` から親プロセスを辿るか、`ProcessId` から外部通信・DNS（Sysmon ID 3/22）や関連挙動（スレッド注入 ID 8、LSASSアクセス ID 10、ファイル作成 ID 11、レジストリ変更 ID 12/13）を確認してください。
2. 最終回答には必ず以下の3段階の評価レベルのいずれか1つを先頭行または見出しに明記してください:
   - `[CLEAN]` : 正規の管理操作・OS標準動作・誤検知と判断できる場合
   - `[SUSPICIOUS]` : 不審な兆候があるが単独では確定できず、管理者への確認・追加監視が必要な場合
   - `[CRITICAL]` : 難読化コマンド実行、LOLBin悪用、不審な外部C2通信・DNSトンネリング、スレッド注入（ID 8）、LSASSメモリダンプ疑い（ID 10）、危険な永続化（ID 11/12/13）、権限昇格・侵害の強い兆候、または Sysmon 停止/設定改ざん/ログ消去（EventID 4, 16, 104, 1102, 4719, EventRecordID巻き戻り等）の防衛機能妨害（Defense Evasion）がある場合
3. 最終回答の構成（Markdown形式）:
   - **判定レベル**: `[CLEAN]`, `[SUSPICIOUS]`, `[CRITICAL]` のいずれか
   - **判定理由**: イベント内容およびツール調査結果に基づく具体的な根拠（箇条書き）
   - **推奨確認事項**: セキュリティ担当者が次に確認すべき具体的な調査項目（箇条書き・すべて読み取り専用の確認手順とすること）
"""


class GeminiTriageAgent:
    """
    Google Gemini (`google-genai` SDK) を用いた自律トリアージエージェント。
    - 環境変数 `GEMINI_API_KEY` を使用（ハードコード禁止）
    - `max_depth = 3` による厳格な Function Calling ループ上限
    - Exponential Backoff による 429 / ResourceExhausted リトライ
    - `alerts/incident_YYYYMMDD.md` への追記専用出力
    """

    def __init__(
        self,
        model_name: str = config.GEMINI_MODEL,
        max_depth: int = config.MAX_DEPTH,
        alerts_dir: Path = config.ALERTS_DIR,
        offline_only: bool = False,
    ) -> None:
        self.offline_only: bool = offline_only
        self._api_offline_until: float = 0.0
        self.max_depth: int = min(max(int(max_depth), 1), 3)
        self.alerts_dir: Path = alerts_dir
        self.alerts_dir.mkdir(parents=True, exist_ok=True)
        self._last_model_refresh_ts: float = 0.0

        if self.offline_only:
            self.client = None
            self.auto_model_enabled = False
            self.model_name = "offline-rule-engine"
            logger.info("オフライン専用モードで初期化しました（Gemini API無効・一次ルール即時フォールバック有効）。")
            return

        if not HAS_GOOGLE_GENAI or genai is None:
            raise ImportError(
                "公式SDK 'google-genai' がインストールされていません。"
                "`pip install google-genai` を実行してください。"
            )

        api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if not api_key:
            raise EnvironmentError(
                "環境変数 'GEMINI_API_KEY' が設定されていません。"
                "実行前に `$env:GEMINI_API_KEY = 'あなたのAPIキー'` を設定してください。"
            )

        # 公式 google-genai SDK の Client 初期化 (環境変数 GEMINI_API_KEY を自動参照)
        self.client = genai.Client()
        requested_model = (model_name or "").strip() or "auto"
        self.auto_model_enabled: bool = requested_model.lower() == "auto"
        self.model_name: str = (
            config.DEFAULT_FALLBACK_MODEL if self.auto_model_enabled else requested_model
        )

        if self.auto_model_enabled:
            self.refresh_latest_model(force=True)

    def _call_with_exponential_backoff(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """
        APIレート制限 (429 / ResourceExhausted) や一時的な通信障害発生時に
        指数バックオフ (Exponential Backoff + Jitter) で安全にリトライします。
        """
        backoff = config.INITIAL_BACKOFF_SECONDS
        last_exception: Exception | None = None

        for attempt in range(1, config.MAX_API_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except APIError as api_err:
                last_exception = api_err
                status_code = getattr(api_err, "code", None)
                err_msg = str(api_err).lower()
                is_retryable = (
                    status_code in (429, 500, 502, 503, 504)
                    or "resource_exhausted" in err_msg
                    or "resourceexhausted" in err_msg
                    or "rate limit" in err_msg
                    or "quota" in err_msg
                )
                if not is_retryable or attempt == config.MAX_API_RETRIES:
                    logger.error(
                        "Gemini API エラー (試行 %d/%d, status=%s): %s",
                        attempt,
                        config.MAX_API_RETRIES,
                        status_code,
                        api_err,
                    )
                    raise

                sleep_sec = min(backoff + random.uniform(0.1, 0.8), config.MAX_BACKOFF_SECONDS)
                logger.warning(
                    "Gemini API レート制限または一時エラー (status=%s)。%.1f 秒後にリトライします (%d/%d)...",
                    status_code,
                    sleep_sec,
                    attempt,
                    config.MAX_API_RETRIES,
                )
                time.sleep(sleep_sec)
                backoff *= config.BACKOFF_MULTIPLIER
            except (ConnectionError, TimeoutError, OSError) as net_err:
                last_exception = net_err
                if attempt == config.MAX_API_RETRIES:
                    logger.error(
                        "ネットワーク通信エラーが解消しませんでした (%d/%d): %s",
                        attempt,
                        config.MAX_API_RETRIES,
                        net_err,
                    )
                    raise
                sleep_sec = min(backoff + random.uniform(0.1, 0.8), config.MAX_BACKOFF_SECONDS)
                logger.warning(
                    "通信障害を検出 (%s)。%.1f 秒後にリトライします (%d/%d)...",
                    net_err,
                    sleep_sec,
                    attempt,
                    config.MAX_API_RETRIES,
                )
                time.sleep(sleep_sec)
                backoff *= config.BACKOFF_MULTIPLIER

        if last_exception is not None:
            raise last_exception
        raise RuntimeError("Gemini API 呼び出しが不明な理由で失敗しました。")

    @staticmethod
    def _build_initial_prompt(event: NormalizedEvent) -> str:
        """
        生XMLを一切含めず、トークン最適化された8フィールド辞書 (`to_trimmed_dict()`) と
        一次スクリーニング検知理由のみを整形して初期プロンプトを生成します。
        """
        trimmed_payload: dict[str, Any] = event.to_trimmed_dict()
        reasons_str = "\n".join(f"- {r}" for r in event.screening_reasons) or "- 一次フィルタ条件一致"

        return (
            "以下のWindowsイベントがルールベース一次スクリーニングで「不審候補」として検出されました。\n"
            "必要に応じてツール（`get_parent_process`, `get_process_network_activity`, `get_process_related_events`）を呼び出して"
            "親プロセスや外部通信・DNS・注入/永続化挙動の有無を確認し、トリアージ判定を行ってください。\n\n"
            f"### メタ情報\n"
            f"- Channel: `{event.channel}`\n"
            f"- EventID: `{event.event_id}`\n"
            f"- EventRecordID: `{event.event_record_id}`\n\n"
            f"### 一次スクリーニング検知理由\n"
            f"{reasons_str}\n\n"
            f"### 抽出イベントデータ (Trimmed JSON)\n"
            f"```json\n{json.dumps(trimmed_payload, indent=2, ensure_ascii=False)}\n```\n"
        )

    @staticmethod
    def _extract_severity(report_text: str) -> str:
        """
        レポート本文から最終評価レベル (`[CRITICAL]`, `[SUSPICIOUS]`, `[CLEAN]`) を抽出します。
        説明文中の否定表現（例: 「現時点で [CRITICAL] と断定する悪性挙動はない」）に誤反応しないよう、
        判定レベル宣言行および先頭付近の見出し行を最優先で解析します。
        """
        lines = [line.strip() for line in (report_text or "").splitlines() if line.strip()]

        # 1. 「判定レベル」「評価レベル」を含む宣言行を最優先で確認
        for line in lines[:10]:
            upper_line = line.upper()
            if "判定レベル" in line or "評価レベル" in line:
                for sev in (
                    config.SEVERITY_CRITICAL,
                    config.SEVERITY_SUSPICIOUS,
                    config.SEVERITY_CLEAN,
                ):
                    if sev in upper_line:
                        return sev

        # 2. 先頭付近の見出し行・単独タグ行から評価レベルを抽出
        tag_line_re = re.compile(
            r"^\s*(?:[#>*\-\s]|\*\*)*(\[(CRITICAL|SUSPICIOUS|CLEAN)\])",
            re.IGNORECASE,
        )
        for line in lines[:8]:
            m = tag_line_re.match(line)
            if m:
                return m.group(1).upper()

        # 3. いずれにも該当しない場合のフォールバック
        upper_text = (report_text or "").upper()
        if config.SEVERITY_CRITICAL in upper_text:
            return config.SEVERITY_CRITICAL
        if config.SEVERITY_SUSPICIOUS in upper_text:
            return config.SEVERITY_SUSPICIOUS
        if config.SEVERITY_CLEAN in upper_text:
            return config.SEVERITY_CLEAN
        return config.SEVERITY_SUSPICIOUS

    @staticmethod
    def _is_candidate_triage_model(model_obj: Any, short_name: str) -> bool:
        """`models.list()` からトリアージ用途に適したテキスト生成モデルかを判定します。"""
        lower = short_name.lower()
        if not lower.startswith("gemini-"):
            return False
        excluded_tokens = (
            "image",
            "embedding",
            "nano-banana",
            "tts",
            "audio",
            "live",
            "robotics",
            "computer-use",
        )
        if any(tok in lower for tok in excluded_tokens):
            return False
        supported_actions = getattr(model_obj, "supported_actions", None)
        if supported_actions and "generateContent" not in supported_actions:
            return False
        return True

    @staticmethod
    def _model_priority_key(short_name: str) -> tuple[int, tuple[int, int, int], int, str]:
        """
        将来のモデル命名変更・バージョンアップに自動追従するための優先順位キー。
        1. 安定版優先 (preview / exp より安定版を優先)
        2. 数値バージョン降順 (例: gemini-10-* > gemini-4.5-* > gemini-4-* > gemini-3.8-*)
        3. トリアージ向け軽量・高速ティア優先 (hydrogen / flash > carbon / flash-lite > その他)
        4. モデル名辞書順
        """
        lower = short_name.lower()
        is_stable = 0 if any(tag in lower for tag in ("preview", "exp", "experimental")) else 1

        ver_match = re.match(r"^gemini-(\d+(?:\.\d+)*)", lower)
        if ver_match:
            parts = [int(part) for part in ver_match.group(1).split(".")]
            while len(parts) < 3:
                parts.append(0)
            version_tuple = (parts[0], parts[1], parts[2])
        else:
            version_tuple = (0, 0, 0)

        if "hydrogen" in lower or ("flash" in lower and "lite" not in lower and "omni" not in lower):
            tier_rank = 3
        elif "carbon" in lower or "flash-lite" in lower or "lite" in lower:
            tier_rank = 2
        else:
            tier_rank = 1

        return (is_stable, version_tuple, tier_rank, lower)

    def _list_candidate_models(self, excluded: set[str] | None = None) -> list[str]:
        """`client.models.list()` から利用可能な候補モデルを優先順位順に取得します。"""
        blocked = excluded or set()
        candidates: list[str] = []
        for m in self.client.models.list():
            raw_name = getattr(m, "name", "") or ""
            short_name = raw_name.removeprefix("models/")
            if short_name and short_name not in blocked and self._is_candidate_triage_model(m, short_name):
                candidates.append(short_name)
        candidates.sort(key=self._model_priority_key, reverse=True)
        return candidates

    def refresh_latest_model(self, force: bool = False) -> str:
        """
        `GEMINI_MODEL=auto` のとき、`client.models.list()` を照会して
        その時点で利用可能な最新の軽量・高速テキストモデルへ自動的に追従します。
        API接続エラー時は既存の安全フォールバックモデルを維持して継続します。
        """
        if not self.auto_model_enabled:
            return self.model_name

        now_ts = time.monotonic()
        if not force and (now_ts - self._last_model_refresh_ts) < config.MODEL_REFRESH_INTERVAL_SECONDS:
            return self.model_name

        try:
            candidates = self._list_candidate_models()
            self._last_model_refresh_ts = now_ts
            if candidates:
                best_model = candidates[0]
                if best_model != self.model_name:
                    logger.info(
                        "自動モデル選択: 最新利用可能モデル '%s' を採用します (旧: '%s')。",
                        best_model,
                        self.model_name,
                    )
                    self.model_name = best_model
                else:
                    logger.debug("自動モデル選択: 現在の最新モデル '%s' を継続使用します。", self.model_name)
        except Exception as list_exc:
            logger.warning(
                "起動時/定期の models.list() 取得に失敗したため、既定モデル '%s' を使用します: %s",
                self.model_name,
                list_exc,
            )
        return self.model_name

    @staticmethod
    def _is_model_unavailable_error(api_err: Exception) -> bool:
        """404 やモデル廃止・利用不可を示す APIError かを判定します。"""
        status_code = getattr(api_err, "code", None)
        if status_code in (404, 410):
            return True
        msg = str(api_err).lower()
        return any(
            token in msg
            for token in (
                "not_found",
                "not found",
                "no longer available",
                "deprecated",
                "is not supported for generatecontent",
            )
        )

    def _switch_to_fallback_model(
        self,
        error_msg: str,
        tried_models: set[str] | None = None,
    ) -> bool:
        """
        指定されたモデルが 404 / 廃止等で利用不可の場合、
        1. エラーメッセージ内の推奨モデル (例: 'models/gemini-4-hydrogen')
        2. client.models.list() から動的取得した最新利用可能テキストモデル
        3. config.FALLBACK_GEMINI_MODELS の候補
        の優先順で、その時点で利用可能な新しいモデルへ自動的に切り替えます。
        """
        excluded = set(tried_models or ())
        excluded.add(self.model_name)

        # 1. エラーメッセージ内に推奨モデルが明記されている場合は最優先で採用
        match = re.search(r"models/(gemini-[a-zA-Z0-9._-]+)", error_msg)
        if match:
            suggested = match.group(1)
            if suggested not in excluded:
                logger.warning(
                    "モデル '%s' が利用不可のため、API推奨の後継モデル '%s' へ自動切り替えします。",
                    self.model_name,
                    suggested,
                )
                self.model_name = suggested
                return True

        # 2. API の models.list() から現在利用可能な最新のモデルを動的検索
        try:
            available_models = self._list_candidate_models(excluded=excluded)
            if available_models:
                newest_model = available_models[0]
                logger.warning(
                    "モデル '%s' が利用不可のため、APIから検出した最新利用可能モデル '%s' へ自動切り替えします。",
                    self.model_name,
                    newest_model,
                )
                self.model_name = newest_model
                return True
        except Exception as list_exc:
            logger.debug("models.list() によるモデル動的検索に失敗しました: %s", list_exc)

        # 3. 定義済みフォールバックリストから切り替え
        for candidate in config.FALLBACK_GEMINI_MODELS:
            if candidate not in excluded:
                logger.warning(
                    "モデル '%s' が利用不可のため、フォールバックモデル '%s' へ自動切り替えします。",
                    self.model_name,
                    candidate,
                )
                self.model_name = candidate
                return True
        return False

    def _run_chat_triage_loop(
        self,
        prompt: str,
        base_config: Any,
    ) -> tuple[str, int, list[dict[str, Any]]]:
        """現在の `self.model_name` を使って Function Calling ループを実行します。"""
        tool_trace: list[dict[str, Any]] = []
        chat = self.client.chats.create(
            model=self.model_name,
            config=base_config,
        )
        response = self._call_with_exponential_backoff(chat.send_message, prompt)

        depth = 0
        while response.function_calls and depth < self.max_depth:
            depth += 1
            function_response_parts: list[types.Part] = []

            for fn_call in response.function_calls:
                fn_name = fn_call.name or ""
                fn_args = dict(fn_call.args) if fn_call.args else {}
                logger.info(
                    "[Depth %d/%d] Gemini がツール '%s' を呼び出しました: args=%s",
                    depth,
                    self.max_depth,
                    fn_name,
                    fn_args,
                )

                target_fn = TOOL_DISPATCH_MAP.get(fn_name)
                if target_fn is None:
                    tool_result: Any = {"error": f"Unknown tool: {fn_name}"}
                else:
                    try:
                        tool_result = target_fn(**fn_args)
                    except Exception as tool_exc:
                        logger.warning("ツール '%s' 実行中に例外が発生しました: %s", fn_name, tool_exc)
                        tool_result = {"error": str(tool_exc)}

                tool_trace.append(
                    {
                        "depth": depth,
                        "tool": fn_name,
                        "args": fn_args,
                        "result": tool_result,
                    }
                )

                function_response_parts.append(
                    types.Part.from_function_response(
                        name=fn_name,
                        response={"result": tool_result},
                    )
                )

            # max_depth (3往復目) に達した場合は Function Calling を無効化し、最終レポート出力を強制する
            if depth >= self.max_depth:
                logger.info(
                    "最大調査ループ上限 (max_depth=%d) に到達したため、最終トリアージ判定を生成します。",
                    self.max_depth,
                )
                final_turn_config = types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    tools=AVAILABLE_TOOLS,
                    automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
                    tool_config=types.ToolConfig(
                        function_calling_config=types.FunctionCallingConfig(mode="NONE")
                    ),
                    temperature=0.1,
                )
                response = self._call_with_exponential_backoff(
                    chat.send_message,
                    function_response_parts,
                    config=final_turn_config,
                )
                break
            else:
                response = self._call_with_exponential_backoff(
                    chat.send_message,
                    function_response_parts,
                )

        report_text = (response.text or "").strip()
        return report_text, depth, tool_trace

    @staticmethod
    def classify_offline_severity(event: NormalizedEvent) -> str:
        """
        Gemini API が利用できない環境・障害時に、一次スクリーニング理由とイベント内容から
        ローカルルールのみで `[CRITICAL]` または `[SUSPICIOUS]` を即時判定します。
        """
        reasons_joined = " ".join(event.screening_reasons)
        reasons_lower = reasons_joined.lower()
        cmd_lower = (event.command_line or "").lower()

        if "[critical候補]" in reasons_lower:
            return config.SEVERITY_CRITICAL

        high_risk_tokens = (
            "mimikatz",
            "sekurlsa",
            "vssadmin",
            "wevtutil",
            "fltmc",
            "sysmondrv",
            "clear-winevent",
            "clear-eventlog",
            "auditpol",
            "evtclearlog",
            "sysmon のアンインストール",
            "-enc",
            "encodedcommand",
            "frombase64string",
            "downloadstring",
            "iex",
            "invoke-expression",
            "mshta",
            "certutil -urlcache",
            "certutil.exe -urlcache",
        )
        if any(tok in reasons_lower or tok in cmd_lower for tok in high_risk_tokens):
            return config.SEVERITY_CRITICAL

        if (
            event.event_id == 3
            and event.destination_ip not in ("", "-", "127.0.0.1", "::1", "0.0.0.0")
            and any(tp.lower() in (event.image or "").lower() for tp in config.SUSPICIOUS_TEMP_PATHS)
        ):
            return config.SEVERITY_CRITICAL

        return config.SEVERITY_SUSPICIOUS

    def investigate_offline(
        self,
        event: NormalizedEvent,
        error_reason: str = "",
    ) -> dict[str, Any]:
        """
        オフライン専用モードまたは Gemini API 通信障害時のフォールバックトリアージを実行し、
        ローカル判定・レポート出力・CRITICAL時の通知/迎撃ダイアログ連携を継続します。
        """
        severity = self.classify_offline_severity(event)
        mode_note = (
            "オフライン専用モード (`--offline`)"
            if self.offline_only
            else f"Gemini API 障害時ローカルフォールバック (理由: {error_reason or '通信不可'})"
        )
        reasons_md = "\n".join(f"  - {r}" for r in event.screening_reasons) or "  - 一次スクリーニング条件一致"

        report_text = (
            f"{severity}\n"
            f"- **実行モード**: ⚠️ {mode_note}\n"
            "- **判定理由**:\n"
            f"{reasons_md}\n"
            "- **オフライン補足**: Gemini API への問い合わせが利用できないため、第1層ルールベース検知と"
            "イベント種別重要度に基づきローカルで緊急判定を実施しました。\n"
            "- **推奨確認事項**:\n"
            "  - `alerts/incident_YYYYMMDD.md` 内の対象プロセス・コマンドライン・通信先を確認してください。\n"
            "  - `[CRITICAL]` 判定時は Microsoft Defender ローカルスキャン結果および迎撃パネルで生存確認を行ってください。\n"
            "  - ネットワーク/API障害がマルウェアによる意図的な通信遮断でないか（ファイアウォール/HOSTS設定等）も確認してください。"
        )
        model_label = (
            "offline-rule-engine"
            if self.offline_only
            else f"offline-rule-fallback (待機中AI: {self.model_name})"
        )
        report_file = self.append_triage_report(
            event=event,
            severity=severity,
            report_text=report_text,
            tool_trace=[],
            model_label=model_label,
        )
        logger.warning(
            "ローカルルールによるフォールバック判定を実行しました: EventID=%d, RecordID=%d -> %s",
            event.event_id,
            event.event_record_id,
            severity,
        )
        return {
            "severity": severity,
            "depth_used": 0,
            "tool_trace": [],
            "report_text": report_text,
            "report_file": str(report_file),
            "offline_fallback": True,
            "fallback_error": error_reason,
        }

    def can_attempt_online_now(self) -> bool:
        """現在オンラインの Gemini API へ問い合わせ可能か（クールダウン中でないか）を返します。"""
        if self.offline_only or self.client is None:
            return False
        return time.monotonic() >= self._api_offline_until

    def _execute_gemini_triage_with_model_fallback(
        self,
        event: NormalizedEvent,
    ) -> tuple[str, int, list[dict[str, Any]]]:
        """自動モデル更新・404時後継切替を含めて Gemini 自律調査ループを実行します。"""
        if self.auto_model_enabled:
            self.refresh_latest_model(force=False)

        prompt = self._build_initial_prompt(event)

        # 自動Function Callingを無効化し、明示的な max_depth ループで完全制御する
        base_config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            tools=AVAILABLE_TOOLS,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            temperature=0.1,
        )

        logger.info(
            "Gemini 自律調査を開始します: Model=%s, Channel=%s, EventID=%d, RecordID=%d (max_depth=%d)",
            self.model_name,
            event.channel,
            event.event_id,
            event.event_record_id,
            self.max_depth,
        )

        tried_models: set[str] = set()
        max_fallback_attempts = max(len(config.FALLBACK_GEMINI_MODELS), 3)
        report_text = ""
        depth = 0
        tool_trace: list[dict[str, Any]] = []

        for attempt_idx in range(max_fallback_attempts + 1):
            tried_models.add(self.model_name)
            try:
                report_text, depth, tool_trace = self._run_chat_triage_loop(prompt, base_config)
                self._api_offline_until = 0.0
                break
            except APIError as api_err:
                if (
                    attempt_idx < max_fallback_attempts
                    and self._is_model_unavailable_error(api_err)
                    and self._switch_to_fallback_model(str(api_err), tried_models=tried_models)
                ):
                    continue
                raise

        if not report_text:
            report_text = (
                f"{config.SEVERITY_SUSPICIOUS}\n"
                "- **判定理由**: Gemini からテキスト応答が返却されなかったため、一次スクリーニング結果に基づき要注意と判定しました。\n"
                "- **推奨確認事項**: 該当プロセスの実行ファイルパスおよびコマンドライン引数を手動で確認してください。"
            )
        return report_text, depth, tool_trace

    def try_reinvestigate_online(self, event: NormalizedEvent) -> dict[str, Any] | None:
        """
        オフラインフォールバックで暫定判定したイベントを、オンライン復旧後に
        Gemini API で再トリアージします。
        APIが依然として到達不能な場合は重複フォールバックレポートを出さず None を返します。
        """
        if not self.can_attempt_online_now():
            return None

        try:
            report_text, depth, tool_trace = self._execute_gemini_triage_with_model_fallback(event)
        except Exception as exc:
            self._api_offline_until = time.monotonic() + config.API_OFFLINE_COOLDOWN_SECONDS
            logger.info(
                "オフライン保留イベント (RecordID=%d) のオンライン再判定を延期します (%d秒待機): %s",
                event.event_record_id,
                config.API_OFFLINE_COOLDOWN_SECONDS,
                exc,
            )
            return None

        severity = self._extract_severity(report_text)
        reconciled_report = (
            "✅ **【オンライン復旧・Gemini API 再判定レポート】** "
            "オフラインフォールバック後に通信が復旧したため、Gemini API による再評価を実行しました。\n\n"
            f"{report_text}"
        )
        report_file = self.append_triage_report(
            event=event,
            severity=severity,
            report_text=reconciled_report,
            tool_trace=tool_trace,
        )
        return {
            "severity": severity,
            "depth_used": depth,
            "tool_trace": tool_trace,
            "report_text": reconciled_report,
            "report_file": str(report_file),
            "offline_fallback": False,
            "reconciled_from_offline": True,
        }

    def investigate_event(self, event: NormalizedEvent) -> dict[str, Any]:
        """
        単一の不審候補イベントに対して Gemini Function Calling ループを実行します。
        `max_depth = 3` を厳格に適用し、最大3往復で必ず調査を打ち切ってレポートを生成します。
        オフライン環境や API 障害時は、ローカルルールによるフォールバック判定へ自動切替します。
        """
        if self.offline_only or self.client is None:
            return self.investigate_offline(event, error_reason="オフライン専用モード")

        if not self.can_attempt_online_now():
            return self.investigate_offline(
                event,
                error_reason="Gemini API 一時停止中のためローカルフォールバック継続",
            )

        try:
            report_text, depth, tool_trace = self._execute_gemini_triage_with_model_fallback(event)
        except Exception as triage_exc:
            self._api_offline_until = time.monotonic() + config.API_OFFLINE_COOLDOWN_SECONDS
            logger.error(
                "Gemini API 調査に失敗したため、ローカルルールへフォールバックします (%d秒間待機): %s",
                config.API_OFFLINE_COOLDOWN_SECONDS,
                triage_exc,
            )
            return self.investigate_offline(event, error_reason=str(triage_exc))

        severity = self._extract_severity(report_text)
        report_file = self.append_triage_report(
            event=event,
            severity=severity,
            report_text=report_text,
            tool_trace=tool_trace,
        )

        return {
            "severity": severity,
            "depth_used": depth,
            "tool_trace": tool_trace,
            "report_text": report_text,
            "report_file": str(report_file),
            "offline_fallback": False,
        }

    def append_triage_report(
        self,
        event: NormalizedEvent,
        severity: str,
        report_text: str,
        tool_trace: list[dict[str, Any]],
        model_label: str | None = None,
    ) -> Path:
        """
        【第3層: トリアージ・レポート出力】
        調査結果を Markdown 形式で `alerts/incident_YYYYMMDD.md` に追記（append: mode="a"）します。
        既存ファイルの削除や上書き初期化は一切行いません。
        """
        self.alerts_dir.mkdir(parents=True, exist_ok=True)
        now_local = datetime.now().astimezone()
        date_str = now_local.strftime("%Y%m%d")
        timestamp_str = now_local.strftime("%Y-%m-%d %H:%M:%S %z")
        report_path = self.alerts_dir / f"incident_{date_str}.md"

        trimmed = event.to_trimmed_dict()
        reasons_md = "\n".join(f"  - {r}" for r in event.screening_reasons) or "  - 一次フィルタ一致"
        proc_check = verify_target_process(event.process_id, event.image, event.utc_time)
        used_model = model_label or self.model_name

        if tool_trace:
            trace_lines = []
            for item in tool_trace:
                trace_lines.append(
                    f"  - **[Step {item['depth']}]** `{item['tool']}({json.dumps(item['args'], ensure_ascii=False)})`"
                )
            trace_md = "\n".join(trace_lines)
        else:
            trace_md = "  - ツール追加呼び出しなし（初期イベント情報のみで判定完了）"

        markdown_entry = (
            f"\n---\n\n"
            f"## {severity} インシデント・トリアージレポート ({timestamp_str})\n\n"
            f"- **評価レベル**: **{severity}**\n"
            f"- **使用AIモデル**: `{used_model}`\n"
            f"- **監視チャネル**: `{event.channel}` (Event ID: `{event.event_id}`, Record ID: `{event.event_record_id}`)\n"
            f"- **イベント発生時刻 (UTC)**: `{trimmed['UtcTime']}`\n"
            f"- **対象プロセス**: `{trimmed['Image']}` (PID: `{trimmed['ProcessId']}`)\n"
            f"- **プロセス生存・同一性照合**: {proc_check.reason}\n"
            f"- **コマンドライン**: `{trimmed['CommandLine']}`\n"
            f"- **親プロセス (PID: `{trimmed['ParentProcessId']}`)**: `{trimmed['ParentCommandLine']}`\n"
            f"- **通信先**: `{trimmed['DestinationIp']}:{trimmed['DestinationPort']}`\n"
            f"- **一次スクリーニング検知理由**:\n{reasons_md}\n"
            f"- **Gemini 自律調査ツール履歴 (最大 {self.max_depth} 往復中 {len(tool_trace)} 回実行)**:\n{trace_md}\n\n"
            f"### Gemini 分析・判定結果\n\n"
            f"{report_text}\n"
        )

        # 安全制約に基づき、必ず追記モード (mode="a") のみで書き込む
        with open(report_path, mode="a", encoding="utf-8") as fp:
            fp.write(markdown_entry)

        logger.info("トリアージレポートを追記出力しました: %s (判定: %s)", report_path, severity)
        return report_path
