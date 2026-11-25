import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import agent as agent_mod  # noqa: E402
import allowlist  # noqa: E402
import config  # noqa: E402
from event_reader import NormalizedEvent, screen_event  # noqa: E402
import process_guard  # noqa: E402
import sanitizer  # noqa: E402


class TestSecurityAndBugFixes(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.allowlist_path = self.tmp_dir / "allowlist.json"
        self.allowlist_path.write_text(
            json.dumps(
                {
                    "trusted_image_prefixes": ["C:\\TrustedApps\\"],
                    "trusted_images": [],
                    "trusted_command_line_contains": [],
                    "trusted_dns_domains": [],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_trusted_image_prefixes_prevents_argument_bypass(self) -> None:
        # Malicious binary passing trusted directory path in CLI args must NOT be allowlisted
        evil_ev = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=1,
            image=r"C:\Temp\evil.exe",
            command_line=r"C:\Temp\evil.exe --fake=C:\TrustedApps\sub\helper.py",
        )
        allowed, _ = allowlist.is_event_allowlisted(evil_ev, allowlist_path=self.allowlist_path)
        self.assertFalse(allowed)

        # Executable physically located under trusted prefix IS allowlisted
        legit_exe = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=2,
            image=r"C:\TrustedApps\tool\.venv\Scripts\pythonw.exe",
            command_line=r"pythonw.exe app.py",
        )
        allowed_legit, _ = allowlist.is_event_allowlisted(legit_exe, allowlist_path=self.allowlist_path)
        self.assertTrue(allowed_legit)

        # Generic interpreter running a script file physically under trusted prefix IS allowlisted
        legit_script = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=3,
            image=r"C:\Users\demo\AppData\Roaming\uv\python\python.exe",
            command_line=r'python.exe "C:\TrustedApps\tool\run.py"',
        )
        allowed_script, _ = allowlist.is_event_allowlisted(legit_script, allowlist_path=self.allowlist_path)
        self.assertTrue(allowed_script)

    def test_process_guard_system_lolbin_skips_system_exe_when_script_found(self) -> None:
        script_file = self.tmp_dir / "payload.ps1"
        script_file.write_text("Write-Output 'ok'", encoding="utf-8")
        ps_exe = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        if not ps_exe.is_file():
            self.skipTest("powershell.exe not found on test host")

        ev = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=10,
            image=str(ps_exe),
            command_line=f'"{ps_exe}" -File "{script_file}"',
        )
        paths = process_guard.extract_scan_target_paths(ev)
        self.assertIn(str(script_file.resolve()), paths)
        self.assertNotIn(str(ps_exe), paths)

    def test_sensitive_text_redaction_in_trimmed_dict_and_prompt(self) -> None:
        raw_cmd = (
            "curl.exe https://api.example.com/v1?api_key=SecretParam999 "
            "-H \"Authorization: Bearer tok_abc123def456\" "
            "--password=MySuperPassword123 AIzaSyDummyKey1234567890abcdefghij"
        )
        masked = sanitizer.redact_sensitive_text(raw_cmd)
        self.assertNotIn("SecretParam999", masked)
        self.assertNotIn("tok_abc123def456", masked)
        self.assertNotIn("MySuperPassword123", masked)
        self.assertNotIn("AIzaSyDummyKey1234567890abcdefghij", masked)

        ev = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=1,
            event_record_id=11,
            image=r"C:\Windows\System32\curl.exe",
            command_line=raw_cmd,
        )
        trimmed = ev.to_trimmed_dict()
        self.assertNotIn("MySuperPassword123", trimmed["CommandLine"])
        prompt = agent_mod.GeminiTriageAgent._build_initial_prompt(ev)
        self.assertNotIn("AIzaSyDummyKey1234567890abcdefghij", prompt)

    def test_sysmon_id_255_getconfig_error5_not_critical(self) -> None:
        ev = NormalizedEvent(
            channel=config.SYSMON_CHANNEL,
            event_id=255,
            event_record_id=20,
            image="Sysmon",
            command_line="Sysmon Error (ID=GetConfigurationOptions): Failed to open service configuration with error 5",
        )
        flagged, reasons = screen_event(ev)
        self.assertTrue(flagged)
        self.assertEqual(
            agent_mod.GeminiTriageAgent.classify_offline_severity(ev),
            config.SEVERITY_SUSPICIOUS,
        )
        self.assertFalse(any("[CRITICAL候補]" in r for r in reasons))


if __name__ == "__main__":
    unittest.main(verbosity=2)
