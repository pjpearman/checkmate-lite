import unittest
from pathlib import Path

from answerfile_manager import load_cklb, extract_non_nf_rules


class AnswerFileManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent

    def test_oracle8_sample_counts(self):
        sample = self.repo_root / "tmp" / "IONC_Oracle8_V2R5_20251208-033602.cklb"
        data = load_cklb(sample)
        rules = extract_non_nf_rules(data)
        self.assertEqual(len(rules), 27, "Unexpected non-NF rule count for Oracle8 sample")
        for rule in rules:
            self.assertIn(rule.get("status", "").lower(), {"open", "not_reviewed"})
            self.assertIn("group_id", rule)
            self.assertIn("group_title", rule)

    def test_rhel8_sample_counts(self):
        sample = self.repo_root / "tmp" / "JMEXCESCN6LV_RHEL8_V2R4_20251202-033534.cklb"
        data = load_cklb(sample)
        rules = extract_non_nf_rules(data)
        self.assertEqual(len(rules), 33, "Unexpected non-NF rule count for RHEL8 sample")
        for rule in rules:
            self.assertIn(rule.get("status", "").lower(), {"open", "not_reviewed"})
            self.assertIn("group_id", rule)
            self.assertIn("group_title", rule)


if __name__ == "__main__":
    unittest.main()
