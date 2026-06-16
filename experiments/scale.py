#!/usr/bin/env python3
"""Scaled, multi-seed run — the trustworthy benign-positive curve.

Runs each (arm x seed) combination CONCURRENTLY. A memory arm is sequential
internally (finding i+1 sees lessons from finding i — that's the point), but the
independent (arm, seed) runs overlap, so wall-clock ~= one run's length, not the
sum. All seeds see the SAME findings in the SAME order (fixed data seed); only
the model's sampling seed varies, so the spread across seeds is the run-to-run
noise we need error bars for.

    python experiments/scale.py --owasp-dir benchmark --limit 300 --seeds 3

Outputs results/scale_curve.csv (per-position mean+std per arm) and a plot with
shaded std bands.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean, pstdev

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loupe import data
from loupe.llm import TogetherLLM
from loupe.loop import LoopConfig, run_arm
from loupe.metrics import summarize, learning_curve

DATA_SEED = 12345  # fixes findings + order across all model seeds

ARMS = [
    LoopConfig.baseline(),
    LoopConfig(memory=True, distill="raw", label="memory / raw-verdicts"),
    LoopConfig(memory=True, distill="lesson", label="memory / distilled-lessons"),
]


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def one_run(arm: LoopConfig, seed: int, findings, model: str):
    llm = TogetherLLM(model=model, temperature=0.0, seed=seed)
    recs = run_arm(findings, llm, arm)
    return arm.label, seed, recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owasp-dir", default="benchmark")
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--window", type=int, default=40)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--model", default="meta-llama/Llama-3.3-70B-Instruct-Turbo")
    ap.add_argument("--out", default="results/scale_curve.csv")
    args = ap.parse_args()

    load_dotenv()
    findings = data.load_owasp(args.owasp_dir, limit=args.limit, shuffle_seed=DATA_SEED)
    seeds = list(range(args.seeds))
    combos = [(arm, s) for arm in ARMS for s in seeds]
    print(f"findings={len(findings)} arms={len(ARMS)} seeds={args.seeds} "
          f"runs={len(combos)} workers={args.workers}\n")

    # arm.label -> {seed -> records}
    results: dict[str, dict[int, list]] = {a.label: {} for a in ARMS}
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(one_run, arm, s, findings, args.model): (arm.label, s)
                for arm, s in combos}
        done = 0
        for fut in as_completed(futs):
            label, seed, recs = fut.result()
            results[label][seed] = recs
            done += 1
            print(f"  [{done}/{len(combos)}] {label} seed={seed} done")

    # aggregate: per-arm mean +/- std across seeds
    print(f"\n{'arm':<30} {'bp_rate':>14} {'recall':>14} {'supp_err':>14}")
    print("-" * 76)
    for arm in ARMS:
        per_seed = [summarize(results[arm.label][s]) for s in seeds]
        def ms(k):
            xs = [p[k] for p in per_seed]
            return mean(xs), (pstdev(xs) if len(xs) > 1 else 0.0)
        bp, rc, su = ms("bp_rate"), ms("recall"), ms("suppression_error")
        print(f"{arm.label:<30} {bp[0]:>6.3f}±{bp[1]:<6.3f} "
              f"{rc[0]:>6.3f}±{rc[1]:<6.3f} {su[0]:>6.3f}±{su[1]:<6.3f}")

    _write_curves(args.out, results, seeds, args.window)
    print(f"\ncurves -> {args.out}")
    try:
        png = _plot(args.out)
        print(f"plot   -> {png}")
    except Exception as e:
        print(f"(plot skipped: {e})")


def _write_curves(path, results, seeds, window):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["arm", "i", "bp_mean", "bp_std", "recall_mean", "supp_mean"])
        for label, by_seed in results.items():
            curves = [learning_curve(by_seed[s], window) for s in seeds]
            n = min(len(c) for c in curves)
            for i in range(n):
                bp = [curves[s][i]["bp_rate"] for s in range(len(seeds))]
                rc = [curves[s][i]["recall"] for s in range(len(seeds))]
                su = [curves[s][i]["suppression_error"] for s in range(len(seeds))]
                w.writerow([label, i + 1, f"{mean(bp):.4f}",
                            f"{pstdev(bp) if len(bp) > 1 else 0:.4f}",
                            f"{mean(rc):.4f}", f"{mean(su):.4f}"])


def _plot(csv_path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from collections import defaultdict

    arms = defaultdict(lambda: {"i": [], "bp": [], "sd": [], "rc": [], "su": []})
    with open(csv_path) as fh:
        for r in csv.DictReader(fh):
            a = arms[r["arm"]]
            a["i"].append(int(r["i"])); a["bp"].append(float(r["bp_mean"]))
            a["sd"].append(float(r["bp_std"])); a["rc"].append(float(r["recall_mean"]))
            a["su"].append(float(r["supp_mean"]))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 7), sharex=True)
    for label, a in arms.items():
        lo = [b - s for b, s in zip(a["bp"], a["sd"])]
        hi = [b + s for b, s in zip(a["bp"], a["sd"])]
        ax1.plot(a["i"], a["bp"], marker=".", label=label)
        ax1.fill_between(a["i"], lo, hi, alpha=0.15)
        ax2.plot(a["i"], a["rc"], marker=".", label=f"{label} · recall")
        ax2.plot(a["i"], a["su"], linestyle="--", marker="x",
                 label=f"{label} · suppression")
    ax1.set_ylabel("benign-positive rate (mean ± std)")
    ax1.set_title("Loupe — scaled multi-seed learning curve")
    ax1.set_ylim(-0.02, 1.02); ax1.legend(fontsize=8); ax1.grid(alpha=0.3)
    ax2.set_ylabel("recall / suppression"); ax2.set_xlabel("findings processed")
    ax2.set_ylim(-0.02, 1.02); ax2.legend(fontsize=7, ncol=2); ax2.grid(alpha=0.3)
    fig.tight_layout()
    png = csv_path.rsplit(".", 1)[0] + ".png"
    fig.savefig(png, dpi=120)
    return png


if __name__ == "__main__":
    main()
