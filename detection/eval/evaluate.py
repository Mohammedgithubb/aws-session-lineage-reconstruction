"""Compare detector alerts with ground truth (session level)."""
import json, sqlite3, pathlib
from datetime import datetime

ROOT = pathlib.Path(__file__).resolve().parent.parent

def ts(s): return datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z").timestamp()

def evaluate(truth_path="data/ground_truth.jsonl", db=None, level="Suspicious"):
    order = {"Watch": 1, "Suspicious": 2, "Compromised": 3}
    truth = {}
    for l in open(ROOT / truth_path if not pathlib.Path(truth_path).is_absolute() else truth_path):
        if l.strip():
            t = json.loads(l)
            if "first_call" in t:
                truth.setdefault(t["key"], t)
    con = sqlite3.connect(db or ROOT / "data" / "detector.db")
    alerts = [json.loads(r[0]) for r in con.execute("SELECT json FROM alerts ORDER BY t")]
    first = {}
    for a in alerts:
        if order.get(a["state"], 0) >= order[level]:
            first.setdefault(a["key"], a)
    tp = [k for k in first if k in truth]
    fp = [k for k in first if k not in truth]
    fn = [k for k in truth if k not in first]
    P = len(tp) / (len(tp) + len(fp)) if first else 0.0
    R = len(tp) / len(truth) if truth else 0.0
    print(f"Level counted as a detection: {level} or higher")
    print(f"Attacker sessions in ground truth: {len(truth)}   flagged sessions: {len(first)}")
    print(f"Precision {P:.2f}   Recall {R:.2f}   F1 {2*P*R/(P+R) if P+R else 0:.2f}")
    for k in tp:
        print(f"  caught {truth[k]['role']:<16} {k[-6:]}  time to detect {first[k].get('seen', first[k]['t']) - ts(truth[k]['first_call']):6.0f} s  ({first[k]['state']}, by {', '.join(first[k]['methods'])})")
    for k in fn:
        print(f"  missed {truth[k]['role']:<16} {k[-6:]}")
    for k in fp:
        print(f"  false alarm {first[k]['identity']} {k[-6:]}")
    return {"precision": P, "recall": R, "tp": len(tp), "fp": len(fp), "fn": len(fn)}

if __name__ == "__main__":
    import sys
    evaluate(*(sys.argv[1:2] or []))
