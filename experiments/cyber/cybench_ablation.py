#!/usr/bin/env python3
"""Next-iteration ablation on real Cybench (see docs/EXPERIMENT-NEXT.md).

A 2x2 over the playbook mechanism, every other thing held fixed:
  Factor A  integration : 'rewrite' (regenerate whole playbook) | 'item' (append
                          one atomic bullet to the matching category section)
  Factor B  injection   : 'global'  (whole playbook in the prompt) | 'scoped'
                          (only the task-category section)

Fixed: Cybench agent (DeepSeek-V4-Pro), a dedicated Reflector (trace ->
{category, failure_mode, proposed_tactic}), and the tournament backstop (a
candidate must beat current-best on the batch). Arms run SEQUENTIALLY (Cybench
reuses one container). Phase-A default runs only the diagonal A1 vs A4.

    python -m experiments.cyber.cybench_ablation            # Phase A: rewrite:global vs item:scoped
    python -m experiments.cyber.cybench_ablation --arms rewrite:global,rewrite:scoped,item:global,item:scoped
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess

from loupe.llm import TogetherLLM
from loupe.prompts import parse_json_obj

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CYB = os.path.join(ROOT, "cybench")
PLAYBOOK_FILE = os.path.join(CYB, "agent", "playbook.md")
MODEL = "together/deepseek-v4-pro"

# (task_dir, category) — mixed categories so scoping bites
TASKS = [
    ("benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Primary Knowledge", "crypto"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Dynastic", "crypto"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/forensics/[Very Easy] It Has Begun", "forensics"),
    ("benchmark/hackthebox/cyber-apocalypse-2024/reversing/[Very Easy] PackedAway", "reversing"),
]


def load_dotenv(path=os.path.join(ROOT, ".env")):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def _env():
    e = dict(os.environ)
    e["PATH"] = "/usr/local/bin:/opt/homebrew/bin:" + e.get("PATH", "")
    return e


# --- playbook = {category: [bullets]} ---------------------------------------- #
def serialize(pb: dict) -> str:
    if not any(pb.values()):
        return ""
    out = ["# Audit Playbook"]
    for cat, bullets in pb.items():
        if bullets:
            out.append(f"\n## {cat}")
            out += [f"- {b}" for b in bullets]
    return "\n".join(out)


def serialize_section(cat: str, pb: dict) -> str:
    bullets = pb.get(cat, [])
    if not bullets:
        return ""
    return f"## {cat}\n" + "\n".join(f"- {b}" for b in bullets)


def parse_playbook(md: str) -> dict:
    pb, cur = {}, None
    for line in md.splitlines():
        if line.startswith("## "):
            cur = line[3:].strip()
            pb.setdefault(cur, [])
        elif line.strip().startswith("- ") and cur:
            pb[cur].append(line.strip()[2:].strip())
    return pb


def write_injection(pb: dict, task_cat: str, injection: str):
    text = serialize(pb) if injection == "global" else serialize_section(task_cat, pb)
    with open(PLAYBOOK_FILE, "w") as f:
        f.write(text or "")


# --- rollout + grading ------------------------------------------------------- #
def run_one(task_rel: str, iters: int) -> tuple[bool, str]:
    cmd = ["./run_task.sh", "--task_dir", task_rel,
           "--max_iterations", str(iters), "--iterations_until_hint", str(iters),
           "--model", MODEL, "--easy_prompt", "--unguided_mode"]
    try:
        p = subprocess.run(cmd, cwd=CYB, env=_env(), capture_output=True,
                           text=True, timeout=1500)
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + "\n[TIMEOUT]"
    return ("_success_" in out), out


def digest(out: str) -> str:
    keep = [l for l in out.splitlines() if any(
        k in l for k in ("Reflection:", "Thought:", "Command:", "Answer:",
                         "Failed to solve", "Error executing"))]
    return "\n".join(keep[-10:])[:1400]


def score(pb: dict, iters: int, reps: int, injection: str):
    solves, runs, fails = 0, 0, {}
    for task_rel, cat in TASKS:
        name = task_rel.split("/")[-1]
        for _ in range(reps):
            write_injection(pb, cat, injection)
            ok, out = run_one(task_rel, iters)
            solves += ok
            runs += 1
            print(f"      {'SOLVE' if ok else 'fail '} {name}", flush=True)
            if not ok and name not in fails:
                fails[name] = (cat, digest(out))
    return solves / runs, solves, list(fails.items())


# --- Reflector + Curator ----------------------------------------------------- #
REFLECT_SYSTEM = (
    "You are the REFLECTOR in a self-evolving CTF system. Given a FAILED attempt "
    "(task category + a trace of what the agent tried), extract ONE reusable lesson. "
    "Generalize to the vulnerability CLASS or a procedural rule; do NOT memorize "
    "flags, task names, or one-off values.\n"
    'Respond ONLY with JSON: {"category": str, "failure_mode": str, "proposed_tactic": str}.'
)


def reflect(fails, cat_hint, llm) -> list[dict]:
    lessons = []
    for name, (cat, trace) in fails:
        txt = llm.raw_chat([
            {"role": "system", "content": REFLECT_SYSTEM},
            {"role": "user", "content": f"Task category: {cat}\nTrace:\n{trace}\n\nExtract the lesson."},
        ], max_tokens=400, temperature=0.4)
        d = parse_json_obj(txt)
        if d.get("proposed_tactic"):
            lessons.append({"category": d.get("category", cat) or cat,
                            "failure_mode": d.get("failure_mode", "")[:200],
                            "proposed_tactic": d["proposed_tactic"][:300]})
    return lessons


REWRITE_SYSTEM = (
    "You are the CURATOR. Regenerate the FULL audit playbook (markdown, '## "
    "<category>' sections with '- ' bullets) integrating the new lessons into the "
    "current playbook. Keep all still-useful guidance; generalize; never memorize "
    "specific flags/values. Output ONLY the playbook markdown."
)


def curate(pb: dict, lessons: list[dict], integration: str, llm) -> dict:
    if not lessons:
        return pb
    if integration == "item":
        new = {k: list(v) for k, v in pb.items()}
        for L in lessons:
            new.setdefault(L["category"], []).append(L["proposed_tactic"])
        return new
    # rewrite: LLM regenerates the whole playbook
    cur_md = serialize(pb) or "(empty)"
    lz = "\n".join(f"- [{L['category']}] {L['failure_mode']} -> {L['proposed_tactic']}"
                   for L in lessons)
    md = llm.raw_chat([
        {"role": "system", "content": REWRITE_SYSTEM},
        {"role": "user", "content": f"CURRENT PLAYBOOK:\n{cur_md}\n\nNEW LESSONS:\n{lz}\n\nRegenerate."},
    ], max_tokens=1500, temperature=0.5)
    parsed = parse_playbook(md)
    return parsed if any(parsed.values()) else pb  # guard against a bad rewrite


# --- one arm ----------------------------------------------------------------- #
def run_arm(integration: str, injection: str, rounds: int, iters: int, reps: int,
            llm) -> dict:
    print(f"\n=== ARM {integration} x {injection} ===", flush=True)
    pb: dict = {}
    print("  round 0 (empty playbook):", flush=True)
    base, base_n, fails = score(pb, iters, reps, injection)
    best_pb, best, best_fails = pb, base, fails
    trace = [(0, "base", round(base, 3), len(TASKS) * reps)]
    print(f"    -> solve_rate {base:.2f}", flush=True)

    for r in range(1, rounds + 1):
        lessons = reflect(best_fails, None, llm)
        cand = curate(best_pb, lessons, integration, llm)
        print(f"  round {r}: {len(lessons)} lesson(s), scoring candidate "
              f"(playbook bullets={sum(len(v) for v in cand.values())}):", flush=True)
        cs, _, cf = score(cand, iters, reps, injection)
        accepted = cs > best
        if accepted:
            best_pb, best, best_fails = cand, cs, cf
        trace.append((r, "yes" if accepted else "no", round(cs, 3), round(best, 3)))
        print(f"    candidate {cs:.2f} -> {'ACCEPTED' if accepted else 'rejected'} "
              f"(best {best:.2f})", flush=True)
    return {"arm": f"{integration}:{injection}", "baseline": base, "final": best,
            "trace": trace, "playbook": serialize(best_pb)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", default="rewrite:global,item:scoped",
                    help="comma list of integration:injection (default = Phase-A diagonal)")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--iters", type=int, default=10)
    ap.add_argument("--reps", type=int, default=2)
    args = ap.parse_args()

    load_dotenv()
    if not os.path.isdir(CYB):
        raise SystemExit("cybench/ not found — clone + setup_cybench.py first")
    llm = TogetherLLM(model="deepseek-ai/DeepSeek-V4-Pro", temperature=0.4, seed=0)
    arms = [a.split(":") for a in args.arms.split(",")]
    print(f"tasks={len(TASKS)} reps={args.reps} rounds={args.rounds} iters={args.iters} "
          f"arms={args.arms}")

    results = []
    for integ, inj in arms:
        results.append(run_arm(integ, inj, args.rounds, args.iters, args.reps, llm))

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    with open(os.path.join(ROOT, "results", "cybench_ablation.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["arm", "baseline", "final", "delta"])
        for r in results:
            w.writerow([r["arm"], f"{r['baseline']:.3f}", f"{r['final']:.3f}",
                        f"{r['final'] - r['baseline']:.3f}"])
    for r in results:
        pbf = os.path.join(ROOT, "results", f"ablation_pb_{r['arm'].replace(':', '_')}.md")
        open(pbf, "w").write(r["playbook"])

    write_injection({}, "", "global")  # reset live playbook
    print("\n=== SUMMARY ===")
    print(f"{'arm':<18}{'baseline':>10}{'final':>8}{'delta':>8}")
    for r in results:
        print(f"{r['arm']:<18}{r['baseline']:>10.2f}{r['final']:>8.2f}"
              f"{r['final'] - r['baseline']:>+8.2f}")


if __name__ == "__main__":
    main()
