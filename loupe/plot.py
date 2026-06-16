"""Render results/curve.csv as an overlaid learning-curve image.

Two stacked panels sharing the x-axis (findings processed):
  top    = benign-positive rate   (want the memory arms to bend DOWN)
  bottom = recall + suppression   (the guardrail — must stay flat/high)

matplotlib is an optional dependency; import is guarded.
"""
from __future__ import annotations

import csv
from collections import defaultdict


def plot_curve(csv_path: str, out_path: str) -> str:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        raise RuntimeError("pip install matplotlib") from e

    arms = defaultdict(lambda: {"i": [], "bp": [], "rec": [], "supp": []})
    with open(csv_path) as fh:
        for row in csv.DictReader(fh):
            a = arms[row["arm"]]
            a["i"].append(int(row["i"]))
            a["bp"].append(float(row["bp_rate"]))
            a["rec"].append(float(row["recall"]))
            a["supp"].append(float(row["suppression_error"]))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 7), sharex=True)

    for label, a in arms.items():
        ax1.plot(a["i"], a["bp"], marker=".", label=label)
        ax2.plot(a["i"], a["rec"], marker=".", label=f"{label} · recall")
        ax2.plot(a["i"], a["supp"], marker="x", linestyle="--",
                 label=f"{label} · suppression")

    ax1.set_ylabel("benign-positive rate")
    ax1.set_title("Loupe — does memory bend the benign-positive rate down?")
    ax1.set_ylim(-0.02, 1.02)
    ax1.legend(fontsize=8)
    ax1.grid(alpha=0.3)

    ax2.set_ylabel("recall / suppression")
    ax2.set_xlabel("findings processed")
    ax2.set_ylim(-0.02, 1.02)
    ax2.legend(fontsize=7, ncol=2)
    ax2.grid(alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    return out_path
