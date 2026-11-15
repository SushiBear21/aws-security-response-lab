"""Versioned offline classification and analyst-review evidence."""
import argparse
import hashlib
import json
import math
from pathlib import Path
from app.investigate import public_ssh_rules

def evaluate(dataset):
    if dataset.get("schema_version") != 1 or not dataset.get("version"):
        raise ValueError("Versioned dataset required")
    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Nonempty dataset required")
    if len({c["id"] for c in cases}) != len(cases):
        raise ValueError("Duplicate case IDs")
    tp = fp = tn = fn = 0
    rows, efforts, reviews = [], [], {"confirmed": 0, "dismissed": 0, "pending": 0}
    for case in cases:
        if type(case["expected_positive"]) is not bool or not isinstance(case["rules"], list):
            raise ValueError("Boolean label and rule list required")
        if any(not isinstance(rule, dict) for rule in case["rules"]):
            raise ValueError("Malformed rule")
        review = case.get("analyst_review", {"outcome": "pending", "effort_seconds": None})
        outcome, effort = review["outcome"], review.get("effort_seconds")
        if outcome not in reviews:
            raise ValueError("Invalid review outcome")
        if effort is not None and (type(effort) not in (int, float) or not math.isfinite(effort) or effort < 0):
            raise ValueError("Invalid review effort")
        if outcome == "pending" and effort is not None:
            raise ValueError("Pending review cannot report completed effort")
        if effort is not None: efforts.append(effort)
        reviews[outcome] += 1
        predicted = bool(public_ssh_rules(case["rules"]))
        label = case["expected_positive"]
        tp += predicted and label
        fp += predicted and not label
        tn += not predicted and not label
        fn += not predicted and label
        rows.append({"id": case["id"], "predicted_positive": predicted,
                     "expected_positive": label, "correct": predicted == label,
                     "analyst_outcome": outcome})
    return {"schema_version": 1, "dataset_version": dataset["version"],
            "dataset_sha256": hashlib.sha256(json.dumps(dataset, sort_keys=True, allow_nan=False).encode()).hexdigest(),
            "mode": "synthetic_development_fixtures", "sample_size": len(rows),
            "classification_scope": "public SSH configuration; not compromise or network reachability",
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": (tp + tn) / len(rows),
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "analyst_outcomes": reviews, "measured_effort_count": len(efforts),
            "mean_review_effort_seconds": sum(efforts) / len(efforts) if efforts else None,
            "results": rows}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="tests/fixtures/detection-v1.json")
    parser.add_argument("--output")
    args = parser.parse_args()
    report = evaluate(json.loads(Path(args.dataset).read_text(encoding="utf-8")))
    text = json.dumps(report, indent=2) + "\n"
    if args.output: Path(args.output).write_text(text, encoding="utf-8")
    else: print(text)
    return 0 if all(row["correct"] for row in report["results"]) else 1

if __name__ == "__main__":
    raise SystemExit(main())
