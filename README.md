# Ghost Data Still Exists — AI Deletion Audit Agent

A production-grade, high-accuracy AI Deletion Audit Agent built for the **HackerRank Orchestrate October 2026** challenge: *"Ghost Data Still Exists"*.

This agent autonomously audits data deletion requests, traces current and historical user identities, cross-references multi-modal evidence across disparate systems (SQL snapshots, structured logs, JSON exports, plain text, and PDF attachments), identifies residual ghost data or active re-creation flows, and produces deterministically ordered remediation and verification plans.

---

## 🌟 Solution Overview & Architecture

When a deletion request is processed, systems frequently leave ghost data in search indexes, read replicas, analytics exports, and support attachments, or fail to disable automated sync jobs and restore flows.

This AI agent implements an evidence-driven audit pipeline:

1. **Intent Analysis & Filtering**: Distinguishes valid erasure requests from administrative queries, address updates, and unsubscribe requests (flagged as `NOT_APPLICABLE`).
2. **Identity Resolution**: Reconstructs the complete identity graph (historical user IDs, previous emails, phones, names, and email hashes) from `user_identities.csv` and `user_audit_log.csv`.
3. **Multi-Format Evidence Ingestion**:
   - **SQL Snapshots**: Ingests SQLite memory databases to inspect replica states and embedded JSON payloads.
   - **Structured & Freeform Logs**: Trace-grouped log inspection for event operations, HTTP responses, and key-value records.
   - **JSON Exports**: Service dumps from `account_service`, `search_service`, `support_platform`, `analytics_platform`, `integration_service`, `backup_service`, and `export_service`.
   - **PDF Attachments**: Pure-Python stream and zlib extraction to uncover residual PII in support tickets and export archives.
4. **Temporal State Tracking**: Evaluates the true state of resources as of `audit_at` (verifying whether deletion claims were actually executed or if data persisted).
5. **Deterministic Remediation Engine**: Generates strict 3-phase plans (`FINDING` ➔ `REMEDIATION` ➔ `VERIFICATION`) following exact operation sequences and sorting rules specified in the challenge specification.

---

## 📁 Repository Structure

```text
├── code/
│   ├── main.py                     # Core Agent and EnhancedAuditor engine
│   ├── test_agent_suite.py         # Unit & integration test suite (16 tests)
│   ├── test_deep_qa.py             # Deep QA stress and edge-case tests (15 tests)
│   └── evaluation/
│       ├── enhanced_auditor.py     # Standalone auditor module
│       ├── run_sample_eval.py      # Sample benchmark runner
│       ├── evaluation_report.md    # Detailed accuracy and benchmark report
│       └── usage_report.md         # Token usage, latency, and cost analysis
├── dataset/                        # Input datasets and evidence files
│   ├── deletion_requests.csv       # 518 evaluation deletion requests
│   ├── user_identities.csv         # User profiles
│   ├── user_audit_log.csv          # Historical identity modifications
│   ├── system_activity.csv         # Operational deletion events
│   ├── deletion_rules.csv          # Retention and remediation policies
│   ├── evidence_files.csv          # Manifest of evidence captures
│   └── evidence/                   # PDF, JSON, SQL, and log evidence files
├── evaluation/                     # Root evaluation reports
│   ├── evaluation_report.md
│   └── usage_report.md
├── output.csv                      # Generated audit predictions (518 rows)
├── sample_pred.csv                 # Sample predictions
├── code.zip                        # Submission package
├── log.txt                         # AGENTS.md compliant audit & execution trace
└── README.md                       # Project documentation
```

---

## 🚀 Quick Start & Execution

### 1. Requirements

- Python 3.10+ (Standard library only; zero mandatory third-party dependencies required).
- Optional: `pypdf` for extended PDF parsing (agent includes built-in fallback parser).

### 2. Run the Audit Agent

Generate the final 518 evaluation predictions in `output.csv`:

```bash
python code/main.py
```

### 3. Validate Output Schema

Validate that all predictions comply with format, sequential step numbering, phase ordering, and evidence citations:

```bash
python code/main.py --validate-only
```

### 4. Run Test Suites

Run the complete 31-test QA suite:

```bash
python -m unittest discover -v code
```

---

## 📊 Evaluation & Benchmark Results

- **Total Requests Audited**: 518 cases
- **Status Distribution**:
  - `COMPLETE`: 162
  - `INCOMPLETE`: 346
  - `NOT_APPLICABLE`: 10
- **Validation**: 100% compliant with canonical HackerRank evaluation schema (step ordering, phase ordering, non-empty evidence citations on findings, clean empty strings on future steps).
- **Test Pass Rate**: 31 / 31 tests passed (100%).

---

## 📦 Packaging for HackerRank Submission

Create the `code.zip` package:

**Windows (PowerShell):**
```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

**macOS / Linux:**
```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/.git/*"
```

The submission requires:
1. `code.zip` — Runnable solution and `code/evaluation/` reports.
2. `output.csv` — Exact 518 answer rows.
3. `log.txt` — Full development trace.