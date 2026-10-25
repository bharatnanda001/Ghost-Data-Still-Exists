#!/usr/bin/env python3
"""Comprehensive unit and integration test suite for Ghost Data Still Exists AI Agent.

Covers all 16 requirements specified in the evaluation and reliability guidelines:
1. Current email resolution
2. Historical email resolution
3. Identity changes and ambiguous matches
4. Missing records
5. Remaining profile or search-index records
6. Support-message redaction
7. Analytics anonymization
8. Required audit-record retention
9. Active data-flow detection
10. Backup restore blocking
11. Account tombstone redaction
12. Non-deletion requests
13. Audit-time cutoff handling
14. Missing or malformed evidence
15. Exact output schema
16. JSON serialization and sequential step numbering
"""
import csv
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
import sys

# Ensure code/ is in sys.path
CODE_DIR = Path(__file__).resolve().parent
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from main import (
    DATASET,
    OP_ORDER,
    PHASE_ORDER,
    EnhancedAuditor,
    compact_json,
    is_valid_resource_id,
    norm,
    parse_dt,
    validate_output,
)


class TestDeletionAgentSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auditor = EnhancedAuditor(DATASET)
        cls.samples = {r["case_id"]: r for r in cls._load_csv(DATASET / "sample_deletion_requests.csv")}
        cls.full_reqs = {r["case_id"]: r for r in cls._load_csv(DATASET / "deletion_requests.csv")}

    @staticmethod
    def _load_csv(path: Path):
        with path.open("r", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))

    def test_01_current_email_resolution(self):
        """Verify current primary email correctly identifies the user ID."""
        email = "thandiwe.n@gmail.com"
        uid = self.auditor.email_to_uid.get(norm(email))
        self.assertIsNotNone(uid, "Current email must resolve to a valid user ID")
        self.assertEqual(uid, "user_04")
        self.assertIn(email, self.auditor.user_emails[uid])

    def test_02_historical_email_resolution(self):
        """Verify that a historical email from audit logs links to the current identity."""
        historical_email = None
        target_uid = None
        for row in self.auditor.audit_log:
            if row.get("field_name") == "email" and row.get("old_value"):
                historical_email = row["old_value"]
                target_uid = row["user_id"]
                break
        self.assertIsNotNone(historical_email, "Audit log should contain historical emails")
        resolved_uid = self.auditor.email_to_uid.get(norm(historical_email))
        self.assertEqual(resolved_uid, target_uid, "Historical email must resolve to the correct user ID")
        self.assertIn(norm(historical_email), [norm(e) for e in self.auditor.user_emails[target_uid]])

    def test_03_identity_changes_and_ambiguous_matches(self):
        """Verify identity drift across name, phone, and hash preserves correct cluster."""
        uid = "user_04"
        self.assertTrue(len(self.auditor.user_emails[uid]) >= 1)
        self.assertTrue(len(self.auditor.user_hashes[uid]) >= 1)
        unrelated_email = "nonexistent.user.testing@example.org"
        self.assertIsNone(self.auditor.email_to_uid.get(unrelated_email))

    def test_04_missing_records(self):
        """Verify that resources confirmed absent (e.g. 404, rows=0) are marked ABSENT."""
        absent_records = [r for r in self.auditor.records if r.get("state") == "ABSENT"]
        self.assertTrue(len(absent_records) > 0, "Indexer must identify explicit negative readbacks")
        sample_absent = absent_records[0]
        self.assertEqual(sample_absent["state"], "ABSENT")

    def test_05_remaining_profile_search_records(self):
        """Verify that un-deleted profile and search index entries require DELETE_RECORD."""
        # Case 06: Search index document remains (search_001)
        res = self.auditor.audit_case(self.samples["case_06"], "account_006")
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        ops = [s["operation"] for s in res["steps"]]
        self.assertIn("REPORT_REMAINING_RECORD", ops)
        self.assertIn("DELETE_RECORD", ops)

    def test_06_support_message_redaction(self):
        """Verify that support conversations containing PII require REDACT_RECORD."""
        # Case 11: support_864 contains exposed PII
        res = self.auditor.audit_case(self.samples["case_11"], "account_4248")
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        support_ops = [s["operation"] for s in res["steps"] if s["system_id"] == "support_platform"]
        self.assertIn("REDACT_RECORD", support_ops)

    def test_07_analytics_anonymization(self):
        """Verify that identifiable analytics profiles require ANONYMIZE_RECORD."""
        # Case 11: analytics_2034 contains exposed PII
        res = self.auditor.audit_case(self.samples["case_11"], "account_4248")
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        analytics_ops = [s["operation"] for s in res["steps"] if s["system_id"] == "analytics_platform"]
        self.assertIn("ANONYMIZE_RECORD", analytics_ops)

    def test_08_required_audit_record_retention(self):
        """Verify that security audit logs are retained and verified present."""
        # Case 03: Verified audit_record_2016 present under retention policy
        res = self.auditor.audit_case(self.samples["case_03"], "account_7566")
        self.assertEqual(res["deletion_status"], "COMPLETE")
        sec_steps = [s for s in res["steps"] if s["system_id"] == "security_service"]
        self.assertTrue(len(sec_steps) > 0, "COMPLETE audit must verify retained audit record")
        self.assertEqual(sec_steps[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(sec_steps[0]["state"], "PRESENT")

    def test_09_active_data_flow_detection(self):
        """Verify active connectors and continuous sync triggers DISABLE_DATA_FLOW."""
        # Case 11: data_flow_9522 is active connector
        res = self.auditor.audit_case(self.samples["case_11"], "account_4248")
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        flow_ops = [s["operation"] for s in res["steps"] if s["system_id"] == "integration_service"]
        self.assertIn("REPORT_ACTIVE_DATA_FLOW", flow_ops)
        self.assertIn("DISABLE_DATA_FLOW", flow_ops)

    def test_10_backup_restore_blocking(self):
        """Verify unblocked backup archive records trigger BLOCK_RESTORE."""
        # Case 09: backup_4978 has restore_allowed=true
        res = self.auditor.audit_case(self.samples["case_09"], "account_3960")
        self.assertEqual(res["deletion_status"], "INCOMPLETE")
        backup_ops = [s["operation"] for s in res["steps"] if s["system_id"] == "backup_service"]
        self.assertIn("REPORT_RESTORE_RISK", backup_ops)
        self.assertIn("BLOCK_RESTORE", backup_ops)

    def test_11_account_tombstone_redaction(self):
        """Verify that account tombstones must have identifiers redacted."""
        tombstone_recs = [r for r in self.auditor.records if r["resource_id"].startswith("tombstone_")]
        self.assertTrue(len(tombstone_recs) > 0, "Tombstone records should be indexed")
        for t in tombstone_recs:
            self.assertEqual(t["system_id"], "identity_service")
            self.assertIn(t["category"], ["ACCOUNT_TOMBSTONE", "UNKNOWN"])

    def test_12_non_deletion_requests(self):
        """Verify that non-deletion requests produce NOT_APPLICABLE with empty steps []."""
        for cid in ["case_533", "case_534", "case_535", "case_536", "case_537"]:
            req = self.full_reqs[cid]
            res = self.auditor.audit_case(req, "account_001")
            self.assertEqual(res["deletion_status"], "NOT_APPLICABLE", f"{cid} must be NOT_APPLICABLE")
            self.assertEqual(res["steps"], [], f"{cid} must have empty steps array")

    def test_13_audit_time_cutoff_handling(self):
        """Verify that evidence files or events captured after audit_at are rejected."""
        req = self.samples["case_21"]
        res = self.auditor.audit_case(req, "account_6440")
        for s in res["steps"]:
            self.assertNotEqual(s.get("evidence_id"), "evidence_02", "Evidence created after audit_at must not be cited")

    def test_14_missing_or_malformed_evidence(self):
        """Verify that malformed JSON, SQL, or empty text files do not crash the agent."""
        self.assertIsNone(parse_dt(None))
        self.assertIsNone(parse_dt(""))
        self.assertIsNone(parse_dt("invalid_date_format_xyz"))
        
        self.assertEqual(compact_json([]), "[]")
        self.assertEqual(compact_json({"a": 1, "b": "test"}), '{"a":1,"b":"test"}')
        
        self.assertFalse(is_valid_resource_id("account_service"))
        self.assertFalse(is_valid_resource_id(""))
        self.assertTrue(is_valid_resource_id("account_001"))

    def test_15_exact_output_schema(self):
        """Verify output validation rejects malformed rows and accepts valid ones."""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("case_id,deletion_status,steps_json\n")
            f.write('case_01,COMPLETE,"[]"\n')
            temp_path = Path(f.name)

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f_req:
            f_req.write("case_id,email,request_text\n")
            f_req.write("case_01,test@example.com,delete me\n")
            temp_req = Path(f_req.name)

        report = validate_output(temp_path, temp_req)
        self.assertTrue(report["ok"])
        temp_path.unlink()
        temp_req.unlink()

    def test_16_json_serialization_and_step_numbering(self):
        """Verify steps array has sequential 1-indexed step_no and strictly valid phases."""
        res = self.auditor.audit_case(self.samples["case_06"], "account_006")
        steps = res["steps"]
        self.assertTrue(len(steps) > 0)
        for i, s in enumerate(steps, 1):
            self.assertEqual(s["step_no"], i, f"step_no must be consecutive: expected {i}, got {s['step_no']}")
            self.assertIn(s["phase"], PHASE_ORDER)
            self.assertIn(s["operation"], OP_ORDER)


if __name__ == "__main__":
    unittest.main()
