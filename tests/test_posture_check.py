from pathlib import Path
import re
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import posture_check  # noqa: E402

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class TestEndpointPostureCheck(unittest.TestCase):
    def test_recommended_asr_guids_valid_and_unique(self) -> None:
        guids = [g.lower() for g, _ in posture_check.RECOMMENDED_ASR_RULES]
        self.assertEqual(len(guids), 12)
        self.assertEqual(len(set(guids)), 12)
        for guid in guids:
            self.assertRegex(guid, _UUID_RE)

    def test_collect_posture_lsa_hvci_and_asr_policy_merge(self) -> None:
        fake_reg = {
            posture_check._REG_WIN_NT: {
                "ProductName": "Windows 10 Pro",
                "EditionID": "Professional",
                "DisplayVersion": "26H2",
                "CurrentBuild": "26300",
            },
            posture_check._REG_LSA: {"RunAsPPL": 2, "RunAsPPLBoot": 2},
            posture_check._REG_HVCI: {"Enabled": 1, "WasEnabledBy": 1},
            posture_check._REG_DEFENDER_FEATURES: {"TamperProtection": 1},
            posture_check._REG_ASR_LOCAL: {
                "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 2,  # Audit (overridden by policy below)
                "5beb7efe-fd9a-4556-801d-275e5ffc04cc": 2,  # Audit
            },
            posture_check._REG_ASR_POLICY: {
                "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2": 1,  # Block overrides local
            },
        }
        posture = posture_check.collect_endpoint_posture(
            reg_reader=lambda key: fake_reg.get(key, {})
        )
        self.assertEqual(posture["lsa"]["status"], "ENABLED")
        self.assertEqual(posture["hvci"]["status"], "ENABLED")
        self.assertEqual(posture["tamper_protection"]["status"], "ENABLED")
        self.assertEqual(posture["asr"]["block_count"], 1)
        self.assertEqual(posture["asr"]["audit_count"], 1)
        self.assertEqual(posture["asr"]["disabled_count"], 10)

        report = posture_check.format_posture_report(posture)
        self.assertIn("LSA保護", report)
        self.assertIn("メモリ整合性", report)
        self.assertIn("ApplyAudit", report)

    def test_lsa_reboot_pending_and_disabled_states(self) -> None:
        pending_reg = {
            posture_check._REG_LSA: {"RunAsPPL": 2, "RunAsPPLBoot": 0},
        }
        p1 = posture_check.collect_endpoint_posture(reg_reader=lambda k: pending_reg.get(k, {}))
        self.assertEqual(p1["lsa"]["status"], "REBOOT_PENDING")
        self.assertEqual(p1["hvci"]["status"], "DISABLED")

        empty = posture_check.collect_endpoint_posture(reg_reader=lambda k: {})
        self.assertEqual(empty["lsa"]["status"], "DISABLED")
        self.assertEqual(empty["asr"]["disabled_count"], 12)


if __name__ == "__main__":
    unittest.main(verbosity=2)
