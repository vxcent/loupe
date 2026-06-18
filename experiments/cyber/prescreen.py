#!/usr/bin/env python3
"""Pre-screen the Cybench no-Docker task pool: single-run, empty playbook, classify
each task's outcome so we can pick a train/held-out pool with real *judgment room*
(found_not_submitted / wrong_submit) rather than ceilings or capability walls.

    python -m experiments.cyber.prescreen --iters 12
"""
from __future__ import annotations

import argparse

from .cybench_adapter import load_task
from .cybench_selfevolve import run_one, classify, write_injection, load_dotenv

# candidate no-Docker tasks (difficulty 0-3), mixed categories
CANDIDATES = [
    ("benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Primary Knowledge", "crypto"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Dynastic", "crypto"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Medium] Partial Tenacity", "crypto"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/forensics/[Very Easy] It Has Begun", "forensics"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/forensics/[Very Easy] Urgent", "forensics"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/forensics/[Medium] Data Siege", "forensics"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/reversing/[Very Easy] PackedAway", "reversing"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/reversing/[Very Easy] LootStash", "reversing"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/reversing/[Easy] Crushing", "reversing"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=12)
    args = ap.parse_args()
    load_dotenv()
    print(f"pre-screen: {len(CANDIDATES)} tasks, single-run, empty playbook, iters={args.iters}\n")
    print(f"{'category':<10}{'outcome':<22}task")
    print("-" * 60)
    rows = []
    for rel, cat in CANDIDATES:
        flag = load_task(rel).flag
        write_injection({}, cat, "scoped")     # empty playbook
        run_one(rel, args.iters)
        out, _ = classify(rel, flag)
        rows.append((cat, out, rel.split("/")[-1]))
        print(f"{cat:<10}{out:<22}{rel.split('/')[-1]}", flush=True)
    print("\n--- summary ---")
    from collections import Counter
    print(dict(Counter(o for _, o, _ in rows)))
    room = [t for c, o, t in rows if o in ("found_not_submitted", "wrong_submit")]
    solv = [t for c, o, t in rows if o == "solved"]
    wall = [t for c, o, t in rows if o == "no_solve"]
    print(f"judgment-room (FP/finalize): {room}")
    print(f"solved (ceiling-ish): {solv}")
    print(f"walls (no_solve): {wall}")


if __name__ == "__main__":
    main()
