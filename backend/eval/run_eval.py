"""Runs the scoring engine on a labelled email set and reports how often it is right.

The emails in eval/raw/*.json were written by a separate model (Gemini) that was told nothing about
the rules, so the set is not tuned to them. Usage, from backend/:

    python eval/run_eval.py              # table + summary
    python eval/run_eval.py --json out   # also write per-email results to out
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from analyzer import EmailRiskAnalyzer  # noqa: E402
from models import EmailAnalysisRequest  # noqa: E402

FLAG_AT = 35  # Suspicious or worse: the card turns amber/red
MALICIOUS_AT = 70


def load_samples(pattern: str) -> list:
    samples = []
    for path in sorted(glob.glob(pattern)):
        for item in json.loads(Path(path).read_text(encoding="utf-8")):
            item["_file"] = Path(path).name
            samples.append(item)
    return samples


def rates(rows: list, threshold: int) -> dict:
    tp = sum(1 for r in rows if r["label"] == "malicious" and r["score"] >= threshold)
    fn = sum(1 for r in rows if r["label"] == "malicious" and r["score"] < threshold)
    fp = sum(1 for r in rows if r["label"] == "legit" and r["score"] >= threshold)
    tn = sum(1 for r in rows if r["label"] == "legit" and r["score"] < threshold)
    return {
        "threshold": threshold, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "detection_rate": tp / (tp + fn) if tp + fn else 0.0,  # recall
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "accuracy": (tp + tn) / len(rows) if rows else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", default=str(BACKEND / "eval" / "raw" / "*.json"))
    parser.add_argument("--json", help="write per-email results and summary to this file")
    args = parser.parse_args()

    engine = EmailRiskAnalyzer()
    rows = []
    for s in load_samples(args.samples):
        score, verdict, findings = engine.analyze(EmailAnalysisRequest(**s["email"]))
        rows.append({
            "id": s["id"], "label": s["label"], "category": s.get("category", ""), "note": s.get("note", ""),
            "score": score, "verdict": verdict, "rules": [f.rule for f in findings],
        })

    print(f"{'id':<7} {'label':<9} {'score':>5}  {'verdict':<10} {'ok?':<3} rules")
    for r in rows:
        ok = (r["score"] >= FLAG_AT) == (r["label"] == "malicious")
        print(f"{r['id']:<7} {r['label']:<9} {r['score']:>5}  {r['verdict']:<10} {'yes' if ok else 'NO':<3} {', '.join(r['rules']) or '-'}")

    summary = [rates(rows, FLAG_AT), rates(rows, MALICIOUS_AT)]
    for s in summary:
        print(f"\n== flagged at score >= {s['threshold']} ==")
        print(f"                 predicted malicious   predicted safe")
        print(f"  malicious ({s['tp'] + s['fn']:>2})        TP {s['tp']:>3}              FN {s['fn']:>3}")
        print(f"  legit     ({s['fp'] + s['tn']:>2})        FP {s['fp']:>3}              TN {s['tn']:>3}")
        print(f"  detection rate {s['detection_rate']:.0%} | false-positive rate {s['false_positive_rate']:.0%} | "
              f"precision {s['precision']:.0%} | accuracy {s['accuracy']:.0%}")

    fired = {"legit": collections.Counter(), "malicious": collections.Counter()}
    for r in rows:
        fired[r["label"]].update(set(r["rules"]))
    print("\n== rule fired on (emails) ==")
    print(f"  {'rule':<38} {'legit':>5} {'malicious':>9}")
    for rule in sorted(set(fired["legit"]) | set(fired["malicious"]), key=lambda x: (-fired["legit"][x], x)):
        print(f"  {rule:<38} {fired['legit'][rule]:>5} {fired['malicious'][rule]:>9}")

    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "emails": rows}, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
