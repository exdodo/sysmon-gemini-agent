import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from google.genai import types  # noqa: E402
from google.genai.errors import APIError  # noqa: E402

import agent as agent_mod  # noqa: E402
import config  # noqa: E402
from event_reader import NormalizedEvent  # noqa: E402


class _FakeResponse:
    def __init__(self, text: str = "", function_calls=None) -> None:
        self.text = text
        self.function_calls = function_calls or []


class _FakeFnCall:
    def __init__(self, name: str, args: dict) -> None:
        self.name = name
        self.args = args


class _FakeAPIError(APIError):
    def __init__(self, code: int, message: str) -> None:
        Exception.__init__(self, message)
        self.code = code
        self.message = message


def _make_event(record_id: int, command_line: str = "powershell.exe -NoProfile", reasons=None) -> NormalizedEvent:
    return NormalizedEvent(
        channel=config.SYSMON_CHANNEL,
        event_id=1,
        event_record_id=record_id,
        utc_time="2026-11-18 00:00:00.000",
        process_id=1234,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=command_line,
        parent_process_id=100,
        parent_command_line=r"C:\Windows\explorer.exe",
        destination_ip="",
        destination_port=None,
        screening_reasons=reasons or ["powershell.exe 起動検知"],
    )


class TestFlexTierRouting(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.alerts_dir = self.tmp_dir / "alerts"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _build_agent_with_fake_client(self, send_handler):
        created_chat_configs = []
        client_init_kwargs = {}

        class _FakeChat:
            def send_message(self, message, config=None):
                return send_handler(message, config, created_chat_configs)

        class _FakeChats:
            def create(self, model, config):
                created_chat_configs.append(("create", model, config))
                return _FakeChat()

        class _FakeModels:
            def list(self):
                return []

        class _FakeClient:
            def __init__(self, **kwargs):
                client_init_kwargs.update(kwargs)
                self.chats = _FakeChats()
                self.models = _FakeModels()

        with (
            patch.dict(os.environ, {"SYSMON_GEMINI_API_KEY": "test-dummy-key"}),
            patch.object(agent_mod.genai, "Client", _FakeClient),
        ):
            tri = agent_mod.GeminiTriageAgent(
                model_name="gemini-4-hydrogen",
                max_depth=1,
                alerts_dir=self.alerts_dir,
                triage_cache=agent_mod.CleanTriageCache(cache_path=self.tmp_dir / "cache.json"),
            )
        return tri, created_chat_configs, client_init_kwargs

    def test_suspicious_uses_flex_on_all_turns_and_timeout_300s(self) -> None:
        turn_configs = []

        def handler(message, cfg, created):
            if cfg is not None:
                turn_configs.append(("override", cfg))
            if len(turn_configs) == 0 and len(created) == 1 and isinstance(message, str):
                return _FakeResponse(function_calls=[_FakeFnCall("get_parent_process", {"parent_process_id": 100})])
            return _FakeResponse("判定レベル: [SUSPICIOUS]\n判定理由: test")

        tri, created, client_kwargs = self._build_agent_with_fake_client(handler)
        self.assertEqual(client_kwargs["http_options"].timeout, 300_000)

        ev = _make_event(101)
        res = tri.investigate_event(ev)

        self.assertEqual(res["severity"], config.SEVERITY_SUSPICIOUS)
        self.assertEqual(res["service_tier"], "flex")
        self.assertFalse(res["offline_fallback"])
        self.assertEqual(created[0][2].service_tier, types.ServiceTier.FLEX)
        self.assertEqual(created[0][2].http_options.timeout, 300_000)
        self.assertEqual(turn_configs[0][1].service_tier, types.ServiceTier.FLEX)
        self.assertEqual(turn_configs[0][1].http_options.timeout, 300_000)

    def test_critical_uses_standard_immediately(self) -> None:
        def handler(message, cfg, created):
            return _FakeResponse("判定レベル: [CRITICAL]\n判定理由: high risk")

        tri, created, _ = self._build_agent_with_fake_client(handler)
        ev = _make_event(102, command_line="powershell.exe -enc SQBFAFgA", reasons=["[CRITICAL候補] 難読化コマンド検知"])
        res = tri.investigate_event(ev)

        self.assertEqual(res["severity"], config.SEVERITY_CRITICAL)
        self.assertEqual(res["service_tier"], "standard")
        self.assertEqual(created[0][2].service_tier, types.ServiceTier.STANDARD)
        self.assertEqual(created[0][2].http_options.timeout, 60_000)

    def test_flex_retries_503_then_falls_back_to_standard(self) -> None:
        calls = {"count": 0}

        def handler(message, cfg, created):
            calls["count"] += 1
            if created[-1][2].service_tier == types.ServiceTier.FLEX:
                raise _FakeAPIError(503, "503 Service Unavailable: flex queue overloaded")
            return _FakeResponse("判定レベル: [SUSPICIOUS]\n判定理由: fallback ok")

        tri, created, _ = self._build_agent_with_fake_client(handler)
        with patch.object(agent_mod.time, "sleep") as mock_sleep:
            res = tri.investigate_event(_make_event(103))

        self.assertEqual(res["service_tier"], "standard")
        self.assertEqual(calls["count"], config.MAX_API_RETRIES + 1)
        self.assertEqual(mock_sleep.call_count, config.MAX_API_RETRIES - 1)
        self.assertEqual(created[0][2].service_tier, types.ServiceTier.FLEX)
        self.assertEqual(created[1][2].service_tier, types.ServiceTier.STANDARD)

    def test_both_flex_and_standard_fail_triggers_offline_deferral(self) -> None:
        def handler(message, cfg, created):
            raise _FakeAPIError(429, "429 RESOURCE_EXHAUSTED")

        tri, created, _ = self._build_agent_with_fake_client(handler)
        with patch.object(agent_mod.time, "sleep"):
            res = tri.investigate_event(_make_event(104))

        self.assertTrue(res["offline_fallback"])
        self.assertGreater(tri._api_offline_until, 0.0)
        self.assertEqual(len(created), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
