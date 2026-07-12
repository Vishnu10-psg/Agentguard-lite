"""
evaluate.py - Evaluates risk_scorer's output against the OFFICIAL ground-truth
labels (dependency_labels.csv), reporting metrics broken out by PB-10's actual
stated success criteria rather than one blended confusion matrix:
  - Vulnerability Detection Rate (target > 85%)
  - License Conflict Detection Rate (target > 90%)
  - False Positive Rate (target < 20%)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from data_loader import load_all
from risk_scorer import score_all_dependencies


def confusion_matrix(scored, labels_by_id, predicted_fn, actual_fn, filter_fn=None):
    tp = fp = fn = tn = 0
    for dep in scored:
        label_row = labels_by_id.get(dep["dep_id"])
        if label_row is None:
            continue
        if filter_fn and not filter_fn(dep, label_row):
            continue

        predicted = predicted_fn(dep)
        actual = actual_fn(label_row)

        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def report(name, tp, fp, fn, tn, target_desc=""):
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    print(f"--- {name} ---")
    print(f"TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"Precision (of flagged, how many correct)     : {precision:.3f}")
    print(f"Recall / Detection Rate (of real risks caught): {recall:.3f}")
    print(f"False Positive Rate (of clean, wrongly flagged): {fpr:.3f}")
    print(f"F1: {f1:.3f}")
    if target_desc:
        print(f"PB-10 target: {target_desc}")
    print()
    return {"precision": precision, "recall": recall, "fpr": fpr, "f1": f1}


def main():
    data = load_all()
    scored = score_all_dependencies(
        data["sbom_dependencies"], data["vulnerability_db"], data["license_rules"]
    )
    labels_by_id = {row["dep_id"]: row for row in data["dependency_labels"]}

    print("=" * 70)
    print("OVERALL (any risk flagged vs. is_risky)")
    print("=" * 70)
    tp, fp, fn, tn = confusion_matrix(
        scored, labels_by_id,
        predicted_fn=lambda d: d["final_score"] > 0,
        actual_fn=lambda l: l["is_risky"].strip().lower() == "true",
    )
    report("Overall", tp, fp, fn, tn, "False Positive Rate < 20%")

    print("=" * 70)
    print("VULNERABILITY DETECTION (CVE hit vs. VULNERABLE_DEPENDENCY label)")
    print("=" * 70)
    tp, fp, fn, tn = confusion_matrix(
        scored, labels_by_id,
        predicted_fn=lambda d: len(d["cve_hits"]) > 0,
        actual_fn=lambda l: l["risk_type"] in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"),
    )
    report("Vulnerability Detection", tp, fp, fn, tn, "Detection Rate (Recall) > 85%")

    print("=" * 70)
    print("LICENSE CONFLICT DETECTION (license penalty vs. LICENSE_CONFLICT label)")
    print("=" * 70)
    tp, fp, fn, tn = confusion_matrix(
        scored, labels_by_id,
        predicted_fn=lambda d: d["license_penalty"] > 0,
        actual_fn=lambda l: l["risk_type"] in ("LICENSE_CONFLICT", "TRANSITIVE_LICENSE_CONFLICT", "LICENSE_UNKNOWN"),
    )
    report("License Conflict Detection", tp, fp, fn, tn, "Detection Rate (Recall) > 90%")

    print("=" * 70)
    print("UNMAINTAINED DETECTION (maintenance penalty vs. UNMAINTAINED label)")
    print("=" * 70)
    tp, fp, fn, tn = confusion_matrix(
        scored, labels_by_id,
        predicted_fn=lambda d: d["is_unmaintained"],
        actual_fn=lambda l: l["risk_type"] == "UNMAINTAINED",
    )
    report("Unmaintained Detection", tp, fp, fn, tn)


if __name__ == "__main__":
    main()