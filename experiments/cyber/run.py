#!/usr/bin/env python3
"""Baseline runner for the mini-Cybench substrate.

Runs the solver over the challenge suite with a given playbook (empty by default)
and reports evidence tiers, solve rate, self-deception, and steps. This confirms
the substrate end-to-end before the evolution loop is added; later, the same
runner scores a candidate playbook against this baseline.

    python -m experiments.cyber.run --model meta-llama/Llama-3.3-70B-Instruct-Turbo
    python -m experiments.cyber.run --playbook experiments/cyber/playbooks/base.md
"""
from __future__ import annotations

import argparse
import os

from loupe.llm import TogetherLLM
from .challenges import build_suite
from .agent import solve
from .oracle import grade, summarize


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def run_suite(playbook: str, llm, max_steps: int, reps: int = 1):
    grades = []
    for _ in range(reps):
        for ch in build_suite():           # fresh state each rollout
            res = solve(ch, playbook, llm, max_steps=max_steps)
            grades.append(grade(ch, res))
    return grades


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="meta-llama/Llama-3.3-70B-Instruct-Turbo")
    ap.add_argument("--playbook", default="", help="path to a playbook .md (else empty)")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--reps", type=int, default=1, help="rollouts per challenge")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--temperature", type=float, default=0.2)
    args = ap.parse_args()

    load_dotenv()
    playbook = open(args.playbook).read() if args.playbook else ""
    llm = TogetherLLM(model=args.model, temperature=args.temperature, seed=args.seed)
    print(f"model={args.model} playbook={'<'+args.playbook+'>' if args.playbook else 'EMPTY'} "
          f"reps={args.reps}\n")

    grades = run_suite(playbook, llm, args.max_steps, args.reps)

    print(f"{'challenge':<20} {'tier':>5} {'solved':>7} {'steps':>6} {'self-decep':>11}")
    print("-" * 54)
    for g in grades:
        print(f"{g.challenge_id:<20} {g.tier:>5} {str(g.solved):>7} {g.steps:>6} "
              f"{str(g.self_deception):>11}")
    s = summarize(grades)
    print("-" * 54)
    print(f"solve_rate={s['solve_rate']:.2f}  mean_score={s['mean_score']:.2f}  "
          f"self_deception={s['self_deception_rate']:.2f}  "
          f"avg_steps(solved)={s['avg_steps_solved']:.1f}  tiers={s['tiers']}")
    fails = [g.failure_report for g in grades if g.failure_report]
    if fails:
        print("\nfailure reports (the reviser's signal):")
        for f in fails:
            print(f"  - {f}")


if __name__ == "__main__":
    main()
