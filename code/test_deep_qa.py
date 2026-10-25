import csv
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUT = ROOT / "output.csv"
sys.path.insert(0, str(ROOT / "code"))
from main import EnhancedAuditor

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
VALID_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
VALID_OPERATIONS_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4,
    "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6,
    "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9,
    "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13,
    "VERIFY_RESTORE_BLOCKED": 14,
}


def parse_dt(v):
    if not v:
        return None
    try:
        s = str(v).strip().replace("Z", "+00:00")
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


class DeepQATestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load requests and output
        with (DATASET / "deletion_requests.csv").open("r", encoding="utf-8-sig") as f:
            cls.requests = {r["case_id"]: r for r in csv.DictReader(f)}
        with OUT.open("r", encoding="utf-8-sig") as f:
            cls.output_rows = list(csv.DictReader(f))
        cls.output_by_id = {r["case_id"]: r for r in cls.output_rows}

        # Load evidence manifests
        cls.evidence_manifest = {}
        with (DATASET / "evidence_files.csv").open("r", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                cls.evidence_manifest[r["file_id"]] = {
                    "file_path": r["file_path"],
                    "origin": r["origin"],
                    "captured_at": parse_dt(r["captured_at"]),
                }

    def test_01_output_csv_existence_and_row_count(self):
        """Verify output.csv exists and contains exactly 518 data rows."""
        self.assertTrue(OUT.exists(), "output.csv does not exist in repo root")
        self.assertEqual(len(self.output_rows), 518, f"Expected 518 rows, got {len(self.output_rows)}")
        self.assertEqual(len(self.requests), 518, "Requests CSV does not contain 518 rows")

    def test_02_header_and_column_order(self):
        """Verify exact header column names and order."""
        with OUT.open("r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader)
        self.assertEqual(header, ["case_id", "deletion_status", "steps_json"])

    def test_03_case_id_sorting_and_completeness(self):
        """Verify rows are strictly sorted by case_id with 1:1 request mapping."""
        output_ids = [r["case_id"] for r in self.output_rows]
        sorted_ids = sorted(output_ids)
        self.assertEqual(output_ids, sorted_ids, "output.csv is not sorted by case_id")
        self.assertEqual(set(output_ids), set(self.requests.keys()), "output.csv does not match request IDs exactly")

    def test_04_status_enumeration_and_distribution(self):
        """Verify valid status enumeration and reasonable non-empty distribution."""
        for r in self.output_rows:
            st = r["deletion_status"]
            self.assertIn(st, VALID_STATUSES, f"Invalid status {st} in {r['case_id']}")
        counts = {s: sum(1 for r in self.output_rows if r["deletion_status"] == s) for s in VALID_STATUSES}
        self.assertGreater(counts["COMPLETE"], 50, "Too few COMPLETE cases")
        self.assertGreater(counts["INCOMPLETE"], 100, "Too few INCOMPLETE cases")
        self.assertGreater(counts["NOT_APPLICABLE"], 0, "No NOT_APPLICABLE cases found")

    def test_05_not_applicable_cases_have_empty_steps(self):
        """Verify NOT_APPLICABLE cases have empty array '[]'."""
        for r in self.output_rows:
            if r["deletion_status"] == "NOT_APPLICABLE":
                self.assertEqual(r["steps_json"], "[]", f"NOT_APPLICABLE case {r['case_id']} has non-empty steps")

    def test_06_step_numbering_consecutive_and_1_indexed(self):
        """Verify every step_no starts at 1 and increments strictly consecutively."""
        for r in self.output_rows:
            steps = json.loads(r["steps_json"])
            for idx, s in enumerate(steps, 1):
                self.assertEqual(s.get("step_no"), idx, f"Case {r['case_id']} step {idx} has invalid step_no {s.get('step_no')}")

    def test_07_operation_and_state_matrix_consistency(self):
        """Verify every operation has the exact valid state mandated by the spec."""
        for r in self.output_rows:
            steps = json.loads(r["steps_json"])
            for s in steps:
                op = s.get("operation")
                st = s.get("state")
                self.assertIn(op, VALID_OPERATIONS_STATE, f"Case {r['case_id']} has unknown operation {op}")
                expected_st = VALID_OPERATIONS_STATE[op]
                self.assertEqual(st, expected_st, f"Case {r['case_id']} op {op} has state {st}, expected {expected_st}")

    def test_08_phase_progression_order(self):
        """Verify strict phase order: FINDING -> REMEDIATION -> VERIFICATION."""
        for r in self.output_rows:
            steps = json.loads(r["steps_json"])
            last_phase_rank = 0
            for s in steps:
                p = s.get("phase")
                self.assertIn(p, PHASE_ORDER, f"Invalid phase {p} in {r['case_id']}")
                p_rank = PHASE_ORDER[p]
                self.assertGreaterEqual(p_rank, last_phase_rank, f"Phase order violation in {r['case_id']}: {p} after rank {last_phase_rank}")
                last_phase_rank = p_rank

    def test_09_within_phase_operation_ordering(self):
        """Verify within-phase operation order matches problem statement hierarchy."""
        for r in self.output_rows:
            steps = json.loads(r["steps_json"])
            # Group steps by phase
            by_phase = {"FINDING": [], "REMEDIATION": [], "VERIFICATION": []}
            for s in steps:
                by_phase[s["phase"]].append(s)

            for phase, p_steps in by_phase.items():
                for i in range(len(p_steps) - 1):
                    s1 = p_steps[i]
                    s2 = p_steps[i + 1]
                    op_rank1 = OP_ORDER[s1["operation"]]
                    op_rank2 = OP_ORDER[s2["operation"]]
                    self.assertLessEqual(
                        op_rank1, op_rank2,
                        f"Op order violation in {r['case_id']} phase {phase}: {s1['operation']} (rank {op_rank1}) before {s2['operation']} (rank {op_rank2})"
                    )
                    if op_rank1 == op_rank2:
                        sys1, res1 = s1["system_id"], s1["resource_id"]
                        sys2, res2 = s2["system_id"], s2["resource_id"]
                        self.assertLessEqual(
                            (sys1, res1), (sys2, res2),
                            f"System/Resource sort violation in {r['case_id']}: ({sys1}, {res1}) before ({sys2}, {res2})"
                        )

    def test_10_evidence_grounding_complete_vs_incomplete(self):
        """Verify evidence citation rules for COMPLETE vs INCOMPLETE."""
        for r in self.output_rows:
            cid = r["case_id"]
            stat = r["deletion_status"]
            steps = json.loads(r["steps_json"])
            if stat == "COMPLETE":
                for s in steps:
                    self.assertEqual(s["phase"], "VERIFICATION", f"COMPLETE case {cid} has non-verification step")
                    self.assertTrue(s["evidence_id"], f"COMPLETE case {cid} missing evidence_id on step {s['step_no']}")
            elif stat == "INCOMPLETE":
                for s in steps:
                    if s["phase"] == "FINDING":
                        self.assertTrue(s["evidence_id"], f"INCOMPLETE case {cid} finding missing evidence_id")
                    elif s["phase"] == "REMEDIATION":
                        self.assertEqual(s["evidence_id"], "", f"INCOMPLETE remediation must have empty evidence_id in {cid}")
                    elif s["phase"] == "VERIFICATION":
                        self.assertEqual(s["evidence_id"], "", f"INCOMPLETE future verification must have empty evidence_id in {cid}")

    def test_11_temporal_boundary_audit_at_compliance(self):
        """Verify that no COMPLETE case cites evidence captured AFTER audit_at."""
        violations = []
        for r in self.output_rows:
            cid = r["case_id"]
            if r["deletion_status"] != "COMPLETE":
                continue
            audit_at = parse_dt(self.requests[cid]["audit_at"])
            steps = json.loads(r["steps_json"])
            for s in steps:
                eid = s.get("evidence_id")
                if eid in self.evidence_manifest:
                    cap = self.evidence_manifest[eid]["captured_at"]
                    if cap and cap > audit_at:
                        violations.append((cid, eid, cap, audit_at))
        self.assertEqual(violations, [], f"Temporal boundary violations: {violations}")

    def test_12_non_deletion_intent_classification(self):
        """Verify that non-deletion intent requests are classified as NOT_APPLICABLE."""
        non_del_samples = [
            ("case_custom_export", "I would like to export a copy of all my invoices and profile data."),
            ("case_custom_address", "Please update my delivery address to 42 Wallaby Way."),
            ("case_custom_marketing", "Unsubscribe me from marketing newsletter emails but keep my account active."),
        ]
        auditor = EnhancedAuditor(DATASET)
        for cid, text in non_del_samples:
            req = {
                "case_id": cid,
                "email": "user@example.com",
                "requested_at": "2026-09-01T10:00:00Z",
                "reported_status": "NOT_STARTED",
                "reported_at": "2026-09-01T10:00:00Z",
                "audit_at": "2026-09-10T10:00:00Z",
                "request_text": text,
            }
            res = auditor.audit_case(req, "account_999")
            self.assertEqual(res["deletion_status"], "NOT_APPLICABLE", f"Failed to identify non-deletion for: {text}")
            self.assertEqual(res["steps"], [])

    def test_13_pure_python_pdf_fallback_reliability(self):
        """Verify that PDF parsing succeeds even when pypdf is completely absent."""
        auditor = EnhancedAuditor(DATASET)
        test_pdf = DATASET / "evidence" / "documents" / "delivery_correction_attachment.pdf"
        self.assertTrue(test_pdf.exists())
        text = auditor._extract_pdf_text(test_pdf)
        self.assertIn("support_001", text)
        self.assertIn("priya.raman@gmail.com", text)

    def test_14_idempotent_and_deterministic_output(self):
        """Verify that running the auditor multiple times produces byte-identical output."""
        auditor = EnhancedAuditor(DATASET)
        temp_out1 = ROOT / "test_out1.csv"
        temp_out2 = ROOT / "test_out2.csv"
        try:
            auditor.run(temp_out1)
            auditor.run(temp_out2)
            bytes1 = temp_out1.read_bytes()
            bytes2 = temp_out2.read_bytes()
            self.assertEqual(bytes1, bytes2, "Auditor output is non-deterministic!")
        finally:
            if temp_out1.exists():
                temp_out1.unlink()
            if temp_out2.exists():
                temp_out2.unlink()

    def test_15_cli_flags_and_subcommands(self):
        """Verify CLI flags --validate-only and --compare exit with code 0."""
        # Test validate-only
        res = subprocess.run([sys.executable, str(ROOT / "code" / "main.py"), "--validate-only"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Validate-only failed: {res.stderr}")

        # Test compare on sample output
        res2 = subprocess.run([
            sys.executable, str(ROOT / "code" / "main.py"),
            "--output", str(ROOT / "sample_pred.csv"),
            "--compare", str(DATASET / "sample_output.csv")
        ], capture_output=True, text=True)
        self.assertEqual(res2.returncode, 0, f"Compare failed: {res2.stderr}")


if __name__ == "__main__":
    unittest.main()
