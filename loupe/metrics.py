"""Metrics + the learning curve.

The pass/fail condition is JOINT: the memory arm must drive benign-positive rate
DOWN while keeping recall flat (you can trivially zero the BP-rate by suppressing
everything — `suppression_error` / recall is the guardrail that catches that).

Definitions (a "surfaced" finding = one the validator called exploitable):
  bp_rate            = benign findings surfaced / all surfaced        (want down)
  recall             = real findings surfaced / all real              (want flat/up)
  suppression_error  = real findings NOT surfaced / all real          (the danger)
  precision          = real surfaced / all surfaced
"""
from __future__ import annotations

import csv
from typing import List


def summarize(records: List[dict]) -> dict:
    surfaced = [r for r in records if r["pred_exploitable"]]
    real = [r for r in records if r["label_real"]]
    benign = [r for r in records if not r["label_real"]]
    surfaced_benign = [r for r in surfaced if not r["label_real"]]
    surfaced_real = [r for r in surfaced if r["label_real"]]
    missed_real = [r for r in real if not r["pred_exploitable"]]

    def rate(n, d):
        return (n / d) if d else 0.0

    return {
        "n": len(records),
        "n_real": len(real),
        "n_benign": len(benign),
        "bp_rate": rate(len(surfaced_benign), len(surfaced)),
        "recall": rate(len(surfaced_real), len(real)),
        "precision": rate(len(surfaced_real), len(surfaced)),
        "suppression_error": rate(len(missed_real), len(real)),
        "avg_cost_tokens": rate(sum(r["cost_tokens"] for r in records), len(records)),
        "avg_lessons_used": rate(sum(r["n_lessons_used"] for r in records), len(records)),
    }


def learning_curve(records: List[dict], window: int = 20) -> List[dict]:
    """Sliding-window bp_rate / recall as a function of findings processed —
    the curve whose downward bend (with recall held flat) is the result."""
    pts = []
    for end in range(1, len(records) + 1):
        start = max(0, end - window)
        w = records[start:end]
        s = summarize(w)
        pts.append({"i": end, "bp_rate": s["bp_rate"], "recall": s["recall"],
                    "suppression_error": s["suppression_error"]})
    return pts


def write_curve_csv(path: str, arms: dict[str, List[dict]], window: int = 20):
    """arms: {arm_label: records}. Writes one long-format CSV for plotting."""
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["arm", "i", "bp_rate", "recall", "suppression_error"])
        for label, recs in arms.items():
            for p in learning_curve(recs, window):
                w.writerow([label, p["i"], f"{p['bp_rate']:.4f}",
                            f"{p['recall']:.4f}", f"{p['suppression_error']:.4f}"])
