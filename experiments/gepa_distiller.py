#!/usr/bin/env python3
"""GEPA-lite — reflective + Pareto evolution of the DISTILLER prompt.

The distiller instruction is the current bottleneck (it backfired in v1, we fixed
it by hand). GEPA automates that reflect-and-rewrite loop:

  reflective mutation : read the mistakes a candidate's lessons caused, rewrite
                        the distiller instruction to fix them (richer than RL reward)
  Pareto selection    : keep the FRONTIER of candidates that win on different
                        objectives, never collapsing (bp_rate, recall, suppression)
                        into one scalar

Optimizes on a TRAIN split, reports the frontier on a held-out VAL split (so you
can see overfitting). Together backend only (mutation needs a real LLM).

NOTE: this is the skeleton. A *trustworthy* run needs the eval scaled past the
72-case noise floor (roadmap step 4) — at small N, GEPA will chase noise. Run it
small first just to watch the loop work.

    python experiments/gepa_distiller.py --owasp-dir benchmark --limit 60 --generations 4
"""
from __future__ import annotations

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loupe import data, prompts
from loupe.llm import TogetherLLM
from loupe.loop import LoopConfig, run_arm
from loupe.metrics import summarize


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


# ----- objectives (all MINIMIZED) -------------------------------------------- #
def objectives(metrics: dict) -> tuple:
    return (metrics["bp_rate"], 1.0 - metrics["recall"], metrics["suppression_error"])


def dominates(a: tuple, b: tuple) -> bool:
    return all(x <= y for x, y in zip(a, b)) and any(x < y for x, y in zip(a, b))


def pareto_front(cands: list) -> list:
    front = []
    for c in cands:
        if c["obj"] is None:
            continue
        if not any(dominates(o["obj"], c["obj"]) for o in cands
                   if o is not c and o["obj"] is not None):
            front.append(c)
    return front


# ----- candidate evaluation -------------------------------------------------- #
CFG = LoopConfig(memory=True, distill="lesson", label="gepa")


def evaluate(prompt_text: str, findings, llm) -> tuple[dict, list[str]]:
    llm.distill_system = prompt_text
    recs = run_arm(findings, llm, CFG)
    by_id = {f.id: f for f in findings}
    fails = []
    for r in recs:
        f = by_id.get(r["finding_id"])
        if r["label_real"] and not r["pred_exploitable"]:
            fails.append(f"[{r['class_key']}] {f.title} — REAL but SUPPRESSED")
        elif not r["label_real"] and r["pred_exploitable"]:
            fails.append(f"[{r['class_key']}] {f.title} — BENIGN but SURFACED")
    return summarize(recs), fails[:8]


# ----- reflective mutation --------------------------------------------------- #
MUTATE_SYSTEM = (
    "You are GEPA, a prompt optimizer. You improve the SYSTEM INSTRUCTION given to "
    "a 'distiller' that writes reusable lessons for a security-finding validator. "
    "Rewrite the instruction so the listed mistakes would not recur, WITHOUT "
    "introducing the opposite error (over-suppressing reals vs leaking benigns). "
    "Keep it concise and general. Output ONLY the new instruction text."
)


def mutate(parent: str, fails: list[str], llm: TogetherLLM) -> str:
    fail_block = "\n".join(f"- {x}" for x in fails) or "- (no mistakes recorded)"
    resp = llm.client.chat.completions.create(
        model=llm.model, temperature=0.6, seed=llm.seed,
        messages=[
            {"role": "system", "content": MUTATE_SYSTEM},
            {"role": "user", "content":
                f"CURRENT INSTRUCTION:\n{parent}\n\n"
                f"MISTAKES the lessons from this instruction caused:\n{fail_block}\n\n"
                "Rewrite the instruction."},
        ],
    )
    return (resp.choices[0].message.content or parent).strip()


# ----- the loop -------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/fixture.jsonl")
    ap.add_argument("--owasp-dir", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--generations", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--model", default="meta-llama/Llama-3.3-70B-Instruct-Turbo")
    args = ap.parse_args()

    load_dotenv()
    if args.owasp_dir:
        findings = data.load_owasp(args.owasp_dir, limit=args.limit,
                                   shuffle_seed=args.seed)
    else:
        findings = data.load(args.data)
    rng = random.Random(args.seed)
    rng.shuffle(findings)
    cut = max(2, int(len(findings) * 0.6))
    train, val = findings[:cut], findings[cut:]
    print(f"train={len(train)} val={len(val)} generations={args.generations}\n")

    llm = TogetherLLM(model=args.model, temperature=0.0, seed=args.seed)

    pool = [{"name": "seed", "prompt": prompts.DISTILL_SYSTEM, "obj": None, "fail": None}]
    m, f = evaluate(pool[0]["prompt"], train, llm)
    pool[0]["obj"], pool[0]["fail"] = objectives(m), f
    print(f"{'candidate':<10} {'bp':>6} {'recall':>7} {'supp':>6}  frontier")
    print("-" * 44)
    _row("seed", m, True)

    for gen in range(args.generations):
        front = pareto_front(pool)
        parent = front[gen % len(front)]
        child_prompt = mutate(parent["prompt"], parent["fail"], llm)
        m, f = evaluate(child_prompt, train, llm)
        child = {"name": f"gen{gen+1}", "prompt": child_prompt,
                 "obj": objectives(m), "fail": f}
        pool.append(child)
        _row(child["name"], m, child in pareto_front(pool))

    # report frontier on held-out val
    front = pareto_front(pool)
    print(f"\nPareto frontier on TRAIN: {[c['name'] for c in front]}")
    print(f"\n{'frontier→VAL':<14} {'bp':>6} {'recall':>7} {'supp':>6}")
    print("-" * 40)
    best = None
    for c in front:
        mv, _ = evaluate(c["prompt"], val, llm)
        print(f"{c['name']:<14} {mv['bp_rate']:>6.3f} {mv['recall']:>7.3f} "
              f"{mv['suppression_error']:>6.3f}")
        # pick lowest suppression, then lowest bp_rate, as the shipped prompt
        key = (mv["suppression_error"], mv["bp_rate"], 1 - mv["recall"])
        if best is None or key < best[0]:
            best = (key, c)
    if best:
        out = "results/gepa_best_distiller.txt"
        os.makedirs("results", exist_ok=True)
        with open(out, "w") as fh:
            fh.write(best[1]["prompt"])
        print(f"\nbest-on-val: {best[1]['name']} -> {out}")


def _row(name, m, on_front):
    print(f"{name:<10} {m['bp_rate']:>6.3f} {m['recall']:>7.3f} "
          f"{m['suppression_error']:>6.3f}  {'*' if on_front else ''}")


if __name__ == "__main__":
    main()
