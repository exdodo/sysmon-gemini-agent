import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import agent as agent_mod  # noqa: E402
import allowlist  # noqa: E402
import config  # noqa: E402
import daily_reviewer  # noqa: E402
import event_reader  # noqa: E402
from event_reader import NormalizedEvent  # noqa: E402


class TestV134AlertReviewFixes(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.alerts_dir = self.tmp_dir / "alerts"
        self.alerts_dir.mkdir(parents=True)
        self.allowlist_path = self.tmp_dir / "allowlist.json"
        self.allowlist_path.write_text(
            json.dumps(
                {
                    "trusted_image_prefixes": ["C:\\TrustedApps\\"],
                    "trusted_images": [],
                    "trusted_command_line_contains": [
                        r"C:\Users\demo\AppData\Roaming\Antigravity\bin\agy-node.cmd",
                    ],
                    "trusted_dns_domains": [],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_allowlist_cmd_batch_wrapper_allowed_and_chaining_blocked(self) -> None:
        legit_cmd = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=201,
            image=r"C:\Windows\System32\cmd.exe",
            command_line=(
                r'C:\WINDOWS\system32\cmd.exe /c ""C:\Users\demo\AppData\Roaming\Antigravity\bin\agy-node.cmd" '
                r'--import=file:///C:/Users/demo/loader.js main.mjs"'
            ),
        )
        ok_cmd, _ = allowlist.is_event_allowlisted(legit_cmd, allowlist_path=self.allowlist_path)
        self.assertTrue(ok_cmd)

        legit_prefix_cmd = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=202,
            image=r"C:\Windows\System32\cmd.exe",
            command_line=r'cmd.exe /d /c "C:\TrustedApps\run.cmd" --flag',
        )
        ok_prefix, _ = allowlist.is_event_allowlisted(legit_prefix_cmd, allowlist_path=self.allowlist_path)
        self.assertTrue(ok_prefix)

        blocked_cases = [
            NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=1,
                event_record_id=203,
                image=r"C:\Windows\System32\cmd.exe",
                command_line=r'cmd.exe /c ""C:\Users\demo\AppData\Roaming\Antigravity\bin\agy-node.cmd" && calc.exe"',
            ),
            NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=1,
                event_record_id=204,
                image=r"C:\Windows\System32\cmd.exe",
                command_line=r'cmd.exe /c "C:\Temp\evil.exe C:\Users\demo\AppData\Roaming\Antigravity\bin\agy-node.cmd"',
            ),
            NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=1,
                event_record_id=205,
                image=r"C:\Windows\System32\cmd.exe",
                command_line=r'cmd.exe /c "C:\Users\demo\AppData\Roaming\Antigravity\bin\agy-node.cmd" -enc SQBFAFgA',
            ),
            NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=1,
                event_record_id=206,
                image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                command_line=r'powershell.exe -c "Invoke-Evil; # C:\TrustedApps\ok.ps1"',
            ),
        ]
        for ev in blocked_cases:
            allowed, _ = allowlist.is_event_allowlisted(ev, allowlist_path=self.allowlist_path)
            self.assertFalse(allowed, f"不正なバイパスを許可しました: {ev.command_line}")

    def test_daily_reviewer_reconciles_offline_fallback_duplicates(self) -> None:
        jsonl_path = self.alerts_dir / "events_20261126.jsonl"
        rows = [
            {
                "severity": "[SUSPICIOUS]",
                "timestamp": "2026-11-26 15:54:24 +0900",
                "utc_time": "2026-11-26 06:54:20.000",
                "used_model": "gemini-4-hydrogen",
                "service_tier": "offline",
                "offline_fallback": True,
                "channel": config.SYSMON_CHANNEL,
                "event_id": 1,
                "event_record_id": 945933,
                "channel_info": f"`{config.SYSMON_CHANNEL}` (Event ID: `1`, Record ID: `945933`)",
                "image": r"C:\Windows\System32\conhost.exe",
                "command_line": "conhost.exe 0xffffffff",
                "parent_command_line": "ThinSvr.exe",
                "destination": "",
                "screening_reasons": ["一時・不審ディレクトリからの実行"],
                "ai_summary": "offline fallback",
            },
            {
                "severity": "[CLEAN]",
                "timestamp": "2026-11-26 15:59:27 +0900",
                "utc_time": "2026-11-26 06:54:20.000",
                "used_model": "gemini-4-hydrogen",
                "service_tier": "flex",
                "offline_fallback": False,
                "channel": config.SYSMON_CHANNEL,
                "event_id": 1,
                "event_record_id": 945933,
                "channel_info": f"`{config.SYSMON_CHANNEL}` (Event ID: `1`, Record ID: `945933`)",
                "image": r"C:\Windows\System32\conhost.exe",
                "command_line": "conhost.exe 0xffffffff",
                "parent_command_line": "ThinSvr.exe",
                "destination": "",
                "screening_reasons": ["一時・不審ディレクトリからの実行"],
                "ai_summary": "判定レベル: [CLEAN]",
            },
        ]
        jsonl_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8",
        )
        entries = daily_reviewer.parse_events_jsonl(jsonl_path)
        summary = daily_reviewer.summarize_incident_entries(entries)

        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["reconciled_offline_duplicates"], 1)
        self.assertEqual(summary["severity_counts"][config.SEVERITY_CLEAN], 1)
        self.assertEqual(summary["severity_counts"][config.SEVERITY_SUSPICIOUS], 0)

    def test_long_multiline_cmdline_trimmed_and_safe_markdown(self) -> None:
        long_cmd = (
            'pwsh.exe -Command "`Write-Host start`\n'
            + ("A" * 4400)
            + '\n`Write-Host end`"'
        )
        ev = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=301,
            utc_time="2026-11-28 00:00:00.000",
            process_id=4321,
            image=r"C:\Program Files\PowerShell\7\pwsh.exe",
            command_line=long_cmd,
            parent_process_id=100,
            parent_command_line="line1\nline2",
            screening_reasons=["テスト検知"],
        )
        trimmed = ev.to_trimmed_dict()
        self.assertLessEqual(len(trimmed["CommandLine"]), config.MAX_TRIMMED_CMDLINE_CHARS + 5)
        self.assertIn("...[省略:", trimmed["CommandLine"])
        self.assertTrue(trimmed["CommandLine"].startswith('pwsh.exe -Command "`Write-Host start`'))
        self.assertTrue(trimmed["CommandLine"].endswith('`Write-Host end`"'))

        with patch.dict(os.environ, {"SYSMON_GEMINI_API_KEY": "test-dummy-key"}):
            agent = agent_mod.GeminiTriageAgent(
                alerts_dir=self.alerts_dir,
                offline_only=True,
            )
            report_path = agent.append_triage_report(
                event=ev,
                severity=config.SEVERITY_CLEAN,
                report_text="判定レベル: [CLEAN]\n判定理由: テスト用。",
                tool_trace=[],
                used_model="gemini-4-hydrogen",
                used_tier="flex",
            )

        md_text = report_path.read_text(encoding="utf-8")
        cmd_lines = [line for line in md_text.splitlines() if line.startswith("- **コマンドライン**:")]
        self.assertEqual(len(cmd_lines), 1)
        self.assertIn("\\n", cmd_lines[0])
        self.assertIn("``", cmd_lines[0])
        self.assertIn("- **通信先**: `なし`", md_text)
        self.assertNotIn(":None", md_text)

    def test_event_id_3_enriches_from_recent_event_cache_when_process_exited(self) -> None:
        event_reader._RECENT_EVENTS.clear()
        try:
            proc_create = NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=1,
                event_record_id=400,
                utc_time="2026-11-28 01:00:00.000",
                process_id=44444,
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                command_line=r'"C:\Program Files\PowerShell\7\pwsh.exe" -File C:\TrustedApps\sync.ps1',
                parent_process_id=5555,
                parent_image=r"C:\Windows\explorer.exe",
                parent_command_line=r"C:\Windows\explorer.exe",
            )
            wrong_image_reuse = NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=1,
                event_record_id=401,
                utc_time="2026-11-28 00:59:00.000",
                process_id=44445,
                image=r"C:\Windows\System32\notepad.exe",
                command_line="notepad.exe",
                parent_process_id=1111,
                parent_command_line="explorer.exe",
            )
            future_reuse = NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=1,
                event_record_id=402,
                utc_time="2026-11-28 02:00:00.000",
                process_id=44446,
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                command_line="pwsh.exe -File future.ps1",
                parent_process_id=2222,
                parent_command_line="future_parent.exe",
            )
            event_reader.register_event_in_cache(proc_create)
            event_reader.register_event_in_cache(wrong_image_reuse)
            event_reader.register_event_in_cache(future_reuse)

            net_ev = NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=3,
                event_record_id=410,
                utc_time="2026-11-28 01:05:00.000",
                process_id=44444,
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                destination_ip="20.9.155.152",
                destination_port=443,
            )
            net_ev_wrong_img = NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=3,
                event_record_id=411,
                utc_time="2026-11-28 01:05:00.000",
                process_id=44445,
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                destination_ip="20.9.155.152",
                destination_port=443,
            )
            net_ev_future = NormalizedEvent(
                channel=config.SYSMON_CHANNEL,
                event_id=3,
                event_record_id=412,
                utc_time="2026-11-28 01:05:00.000",
                process_id=44446,
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                destination_ip="20.9.155.152",
                destination_port=443,
            )

            with patch.object(event_reader, "HAS_PSUTIL", False):
                event_reader.screen_event(net_ev)
                event_reader.screen_event(net_ev_wrong_img)
                event_reader.screen_event(net_ev_future)

            self.assertEqual(
                net_ev.command_line,
                r'"C:\Program Files\PowerShell\7\pwsh.exe" -File C:\TrustedApps\sync.ps1',
            )
            self.assertEqual(net_ev.parent_process_id, 5555)
            self.assertEqual(net_ev.parent_command_line, r"C:\Windows\explorer.exe")
            self.assertEqual(net_ev_wrong_img.command_line, "")
            self.assertEqual(net_ev_future.command_line, "")
        finally:
            event_reader._RECENT_EVENTS.clear()

    def test_parse_incident_report_still_parses_single_line_and_reconciles(self) -> None:
        ev = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=555,
            utc_time="2026-11-28 03:00:00.000",
            process_id=8888,
            image=r"C:\Program Files\PowerShell\7\pwsh.exe",
            command_line='pwsh.exe -c "`echo hi`\necho bye"',
            parent_process_id=100,
            parent_command_line=r"C:\Windows\explorer.exe",
            screening_reasons=["テスト"],
        )
        agent = agent_mod.GeminiTriageAgent(alerts_dir=self.alerts_dir, offline_only=True)
        offline_path = agent.append_triage_report(
            event=ev,
            severity=config.SEVERITY_SUSPICIOUS,
            report_text="判定レベル: [SUSPICIOUS]\n実行モード: Gemini API 障害時ローカルフォールバック (理由: timeout)",
            tool_trace=[],
            model_label="offline-rule-fallback (待機中AI: gemini-4-hydrogen)",
            used_tier="offline",
            offline_fallback=True,
        )
        agent.append_triage_report(
            event=ev,
            severity=config.SEVERITY_CLEAN,
            report_text="判定レベル: [CLEAN]\n判定理由: 正常動作。",
            tool_trace=[],
            used_model="gemini-4-hydrogen",
            used_tier="flex",
            offline_fallback=False,
        )

        parsed = daily_reviewer.parse_incident_report(offline_path)
        self.assertEqual(len(parsed), 2)
        self.assertTrue(parsed[0]["offline_fallback"])
        self.assertFalse(parsed[1]["offline_fallback"])
        self.assertIn("`echo hi`", parsed[0]["command_line"])
        self.assertEqual(parsed[0]["destination"], "なし")

        summary = daily_reviewer.summarize_incident_entries(parsed)
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["reconciled_offline_duplicates"], 1)
        self.assertEqual(summary["severity_counts"][config.SEVERITY_CLEAN], 1)
        self.assertEqual(summary["severity_counts"][config.SEVERITY_SUSPICIOUS], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
