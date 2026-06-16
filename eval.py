#!/usr/bin/env python3
"""Loupe experiment runner.

Runs the validator over a set of findings under several loop configs and emits
the learning curves. The headline comparison is memory-off (flat baseline) vs.
memory-on (should bend the benign-positive rate down while keeping recall flat).

Examples:
    python eval.py --backend mock                       # offline plumbing demo
    python eval.py --backend together --model meta-llama/Llama-3.3-70B-Instruct-Turbo
    python eval.py --backend together --limit 6         # cheap real smoke test
"""
from __future__ import annotations

import argparse
import os

from loupe import data
from loupe.llm import get_llm
from loupe.loop import LoopConfig, run_arm
from loupe.metrics import summarize, write_curve_csv


def load_dotenv(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


ARMS = [
    LoopConfig.baseline(),
    LoopConfig(memory=True, distill="raw", label="memory-on / raw-verdicts"),
    LoopConfig(memory=True, distill="lesson", label="memory-on / distilled-lessons"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="mock", choices=["mock", "together"])
    ap.add_argument("--model", default="meta-llama/Llama-3.3-70B-Instruct-Turbo")
    ap.add_argument("--data", default="data/fixture.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="cap # findings (cost)")
    ap.add_argument("--window", type=int, default=8)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--out", default="results/curve.csv")
    args = ap.parse_args()

    load_dotenv()
    findings = data.load(args.data)
    if args.limit:
        findings = findings[: args.limit]

    print(f"backend={args.backend} model={args.model if args.backend=='together' else '-'} "
          f"findings={len(findings)}\n")

    arms_records = {}
    print(f"{'arm':<32} {'bp_rate':>8} {'recall':>8} {'supp_err':>9} {'tok/find':>9}")
    print("-" * 70)
    for cfg in ARMS:
        # Fresh LLM per arm so each arm is independently seeded/comparable
        # (mock RNG resets; Together is deterministic per call regardless).
        llm = get_llm(args.backend, args.model, args.temperature, args.seed)
        recs = run_arm(findings, llm, cfg)
        arms_records[cfg.label] = recs
        s = summarize(recs)
        print(f"{cfg.label:<32} {s['bp_rate']:>8.3f} {s['recall']:>8.3f} "
              f"{s['suppression_error']:>9.3f} {s['avg_cost_tokens']:>9.0f}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    write_curve_csv(args.out, arms_records, window=args.window)
    print(f"\ncurves -> {args.out}")
    print("PASS condition: a memory arm shows lower bp_rate than baseline "
          "AND suppression_error stays ~flat.")


if __name__ == "__main__":
    main()
