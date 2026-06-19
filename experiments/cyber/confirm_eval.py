#!/usr/bin/env python3
"""Confirmation: evaluate the FROZEN evolved playbook vs the empty baseline on the
held-out set at higher reps, to tighten the run-2 estimate (N=9 -> larger).

    python -m experiments.cyber.confirm_eval --reps 5 --iters 10
"""
from __future__ import annotations

import argparse
import os

from .cybench_evohunt import eval_set, HELDOUT
from .cybench_selfevolve import load_dotenv, ROOT
from .cybench_ablation import parse_playbook


def _prec(t):
    s = t["solved"] + t["wrong_submit"]
    return (t["solved"] / s) if s else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--iters", type=int, default=10)
    ap.add_argument("--playbook", default="results/evohunt_best_playbook.md")
    args = ap.parse_args()
    load_dotenv()
    path = os.path.join(ROOT, args.playbook)
    pb = parse_playbook(open(path).read()) if os.path.exists(path) else {}
    print(f"confirm: held-out={len(HELDOUT)} reps={args.reps} iters={args.iters} "
          f"(playbook bullets={sum(len(v) for v in pb.values())})\n")

    print("=== empty baseline ===", flush=True)
    b_sr, b_t = eval_set({}, HELDOUT, args.iters, args.reps)
    print("=== frozen evolved ===", flush=True)
    e_sr, e_t = eval_set(pb, HELDOUT, args.iters, args.reps)
    print("\n=== CONFIRM RESULT ===")
    print(f"  baseline  solve_rate {b_sr:.2f}  found_not_submitted {b_t['found_not_submitted']} "
          f"wrong_submit {b_t['wrong_submit']}  precision {_prec(b_t):.2f}  {b_t}")
    print(f"  evolved   solve_rate {e_sr:.2f}  found_not_submitted {e_t['found_not_submitted']} "
          f"wrong_submit {e_t['wrong_submit']}  precision {_prec(e_t):.2f}  {e_t}")
    print(f"  delta solve_rate {e_sr - b_sr:+.2f} | found_not_submitted "
          f"{b_t['found_not_submitted']}->{e_t['found_not_submitted']} | "
          f"wrong_submit {b_t['wrong_submit']}->{e_t['wrong_submit']}")


if __name__ == "__main__":
    main()
