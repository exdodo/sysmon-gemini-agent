from datetime import date, datetime
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from google.genai import types  # noqa: E402

import agent as agent_mod  # noqa: E402
import allowlist  # noqa: E402
import daily_reviewer  # noqa: E402
from log_retention import cleanup_old_incident_reports  # noqa: E402


SAMPLE_INCIDENT_MD = """
---

## [CLEAN] インシデント・トリアージレポート (2026-11-23 09:00:00 +0900)

- **評価レベル**: **[CLEAN]**
- **使用AIモデル**: `gemini-4-hydrogen (tier: flex)`
- **監視チャネル**: `Microsoft-Windows-Sysmon/Operational` (Event ID: `1`, Record ID: `1001`)
- **イベント発生時刻 (UTC)**: `2026-11-23 00:00:00.000`
- **対象プロセス**: `C:\\Users\\demo\\AppData\\Roaming\\Code\\User\\globalStorage\\eamodio.gitlens\\gk.exe` (PID: `1111`)
- **プロセス生存・同一性照合**: 終了済
- **コマンドライン**: `"C:\\Users\\demo\\AppData\\Roaming\\Code\\User\\globalStorage\\eamodio.gitlens\\gk.exe" status`
- **親プロセス (PID: `100`)**: `C:\\Program Files\\Microsoft VS Code\\Code.exe`
- **通信先**: `:None`
- **一次スクリーニング検知理由**:
  - 一時・不審ディレクトリからの実行ファイル起動 (gk.exe)

### Gemini 分析・判定結果

判定レベル: [CLEAN]
判定理由: GitLens 拡張の正規 Git ラッパーバイナリであるため。
"""


class TestDailyReviewerAndAllowlistQueue(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.alerts_dir = self.tmp_dir / "alerts"
        self.alerts_dir.mkdir(parents=True)
        self.allowlist_path = self.tmp_dir / "allowlist.json"
        self.candidates_path = self.tmp_dir / "allowlist_candidates.json"
        self.state_path = self.tmp_dir / "daily_review_state.json"
        allowlist.ensure_allowlist_file(self.allowlist_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_validate_rule_entry_blocks_unsafe_rules(self) -> None:
        self.assertFalse(allowlist.validate_rule_entry("trusted_images", r"C:\Windows\System32\cmd.exe")[0])
        self.assertFalse(allowlist.validate_rule_entry("trusted_image_prefixes", r"C:\Users\demo\AppData\Roaming\\")[0])
        self.assertFalse(allowlist.validate_rule_entry("trusted_command_line_contains", "wevtutil cl Security")[0])
        self.assertTrue(
            allowlist.validate_rule_entry(
                "trusted_images",
                r"C:\Users\demo\AppData\Roaming\Code\User\globalStorage\eamodio.gitlens\gk.exe",
            )[0]
        )

    def test_candidate_store_queue_approve_and_dismiss(self) -> None:
        store = daily_reviewer.AllowlistCandidateStore(candidates_path=self.candidates_path)
        stats = store.add_candidates(
            [
                {"section": "trusted_images", "value": r"C:\Windows\System32\cmd.exe", "count": 5},
                {
                    "section": "trusted_images",
                    "value": r"C:\Users\demo\AppData\Roaming\Code\User\globalStorage\eamodio.gitlens\gk.exe",
                    "reason": "GitLens helper",
                    "count": 13,
                },
            ],
            source_date="20261123",
            allowlist_path=self.allowlist_path,
        )
        self.assertEqual(stats["rejected"], 1)
        self.assertEqual(stats["added"], 1)

        cands = store.list_candidates()
        ok, _ = store.approve_candidate(cands[0]["id"], allowlist_path=self.allowlist_path)
        self.assertTrue(ok)
        self.assertEqual(store.pending_count(), 0)

    def test_daily_review_end_to_end_flex_tier_and_report(self) -> None:
        (self.alerts_dir / "incident_20261123.md").write_text(SAMPLE_INCIDENT_MD, encoding="utf-8")
        captured_calls = []

        class _FakeResp:
            def __init__(self, text: str) -> None:
                self.text = text

        class _FakeModels:
            def list(self):
                return []

            def generate_content(self, model, contents, config):
                captured_calls.append((model, contents, config))
                payload = {
                    "overall_assessment": "SAFE",
                    "attack_likelihood": "低",
                    "executive_summary": "異常なし。",
                    "correlated_findings": [],
                    "recommended_actions": [],
                    "whitelist_candidates": [
                        {
                            "section": "trusted_images",
                            "value": r"C:\Users\demo\AppData\Roaming\Code\User\globalStorage\eamodio.gitlens\gk.exe",
                            "reason": "GitLens helper",
                            "count": 2,
                        }
                    ],
                }
                return _FakeResp(json.dumps(payload, ensure_ascii=False))

        class _FakeClient:
            def __init__(self, **kwargs):
                self.models = _FakeModels()
                self.chats = None

        with (
            patch.dict(os.environ, {"SYSMON_GEMINI_API_KEY": "dummy-key"}),
            patch.object(agent_mod.genai, "Client", _FakeClient),
        ):
            triage = agent_mod.GeminiTriageAgent(
                model_name="gemini-4-hydrogen",
                alerts_dir=self.alerts_dir,
                triage_cache=agent_mod.CleanTriageCache(cache_path=self.tmp_dir / "cache.json"),
            )
            store = daily_reviewer.AllowlistCandidateStore(candidates_path=self.candidates_path)
            reviewer = daily_reviewer.DailyReviewer(
                alerts_dir=self.alerts_dir,
                state_path=self.state_path,
                candidate_store=store,
                allowlist_path=self.allowlist_path,
                review_hour=9,
            )
            self.assertIsNone(reviewer.run_if_due(triage, now=datetime(2026, 11, 24, 8, 30)))
            res = reviewer.run_if_due(triage, now=datetime(2026, 11, 24, 9, 15))
            self.assertIsNotNone(res)
            self.assertEqual(res["used_tier"], "flex")
            self.assertEqual(store.pending_count(), 1)

        cfg = captured_calls[0][2]
        self.assertEqual(cfg.service_tier, types.ServiceTier.FLEX)
        self.assertEqual(cfg.http_options.timeout, 300_000)

        old_rev = self.alerts_dir / "daily_review_20260101.md"
        old_rev.write_text("old review", encoding="utf-8")
        cleanup_res = cleanup_old_incident_reports(alerts_dir=self.alerts_dir, today=date(2026, 11, 24))
        self.assertIn(str(old_rev), cleanup_res["deleted_files"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
