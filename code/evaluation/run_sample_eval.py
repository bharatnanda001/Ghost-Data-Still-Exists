import sys
from pathlib import Path
import csv
import json

# Add code/evaluation to path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from enhanced_auditor import EnhancedAuditor

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
SAMPLE_REQS = DATASET / "sample_deletion_requests.csv"
SAMPLE_GOLD = DATASET / "sample_output.csv"
SAMPLE_PRED = ROOT / "sample_pred.csv"

def read_csv(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def compact_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

def compare(pred_path: Path, gold_path: Path):
    preds = {r["case_id"]: r for r in read_csv(pred_path)}
    golds = {r["case_id"]: r for r in read_csv(gold_path)}
    common = sorted(set(preds) & set(golds))
    
    status_correct = 0
    exact_steps_count = 0
    pred_total_steps = 0
    gold_total_steps = 0
    
    discrepancies = []
    
    for cid in common:
        p_row = preds[cid]
        g_row = golds[cid]
        
        p_stat = p_row["deletion_status"]
        g_stat = g_row["deletion_status"]
        if p_stat == g_stat:
            status_correct += 1
            
        p_steps = json.loads(p_row.get("steps_json", "[]"))
        g_steps = json.loads(g_row.get("steps_json", "[]"))
        
        pred_total_steps += len(p_steps)
        gold_total_steps += len(g_steps)
        
        p_tuples = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation"), s.get("state"), s.get("evidence_id")) for s in p_steps]
        g_tuples = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation"), s.get("state"), s.get("evidence_id")) for s in g_steps]
        
        if p_stat == g_stat and p_tuples == g_tuples:
            exact_steps_count += 1
        else:
            discrepancies.append({
                "case_id": cid,
                "status_pred": p_stat,
                "status_gold": g_stat,
                "diff": {
                    "missing": [s for s in g_tuples if s not in p_tuples],
                    "extra": [s for s in p_tuples if s not in g_tuples]
                }
            })
            
    print(f"Total cases evaluated: {len(common)}")
    print(f"Status Accuracy: {status_correct}/{len(common)} ({status_correct/len(common)*100:.2f}%)")
    print(f"Exact Match Accuracy: {exact_steps_count}/{len(common)} ({exact_steps_count/len(common)*100:.2f}%)")
    print(f"Total predicted steps: {pred_total_steps}, Gold steps: {gold_total_steps}")
    print(f"Discrepant cases ({len(discrepancies)}): {[d['case_id'] for d in discrepancies]}")
    return discrepancies

def main():
    auditor = EnhancedAuditor(DATASET)
    reqs = read_csv(SAMPLE_REQS)
    primary_map = auditor.resolve_primary_accounts(reqs)
    results = [auditor.audit_case(r, primary_map[r["case_id"]]) for r in reqs]
    results.sort(key=lambda x: x["case_id"])
    
    with SAMPLE_PRED.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in results:
            writer.writerow([r["case_id"], r["deletion_status"], compact_json(r["steps"])])
            
    discrepancies = compare(SAMPLE_PRED, SAMPLE_GOLD)
    if discrepancies:
        print("\n--- DISCREPANCIES ---")
        for d in discrepancies:
            print(f"\nCase: {d['case_id']} (Pred: {d['status_pred']}, Gold: {d['status_gold']})")
            if d['diff']['missing']:
                print(f"  Missing: {d['diff']['missing']}")
            if d['diff']['extra']:
                print(f"  Extra: {d['diff']['extra']}")

if __name__ == "__main__":
    main()
