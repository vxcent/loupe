#!/usr/bin/env python3
"""EvoHunt transplant on REAL Cybench.

Same loop as the local substrate (evolve.py), but each rollout is Cybench's own
Dockerized agent solving a real task, graded by the real flag oracle:

  score(playbook) : write the playbook to cybench/agent/playbook.md (mounted into
                    the container), run ./run_task.sh per task, read _success_/_fail_
  revise          : turn failure digests into generalized playbook tactics
  tournament      : accept a candidate only if it solves MORE of the train batch

Scoped small by default (real rollouts are minutes each, real $$): 3 very-easy
file-based tasks, 2 rounds, 10 iterations. The reviser uses DeepSeek-V4-Pro via
Together (our loupe client); the agent rollouts use Cybench's DeepSeek-V4-Pro.

    python -m experiments.cyber.cybench_evolve --rounds 2 --iters 10
"""
from __future__ import annotations

import argparse
import os
import subprocess

from loupe.llm import TogetherLLM

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CYB = os.path.join(ROOT, "cybench")
PLAYBOOK_FILE = os.path.join(CYB, "agent", "playbook.md")
MODEL = "together/deepseek-v4-pro"

TRAIN = [
    "benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Primary Knowledge",
    "benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Dynastic",
    "benchmark/hackthebox/cyber-apocalypse-2024/forensics/[Very Easy] It Has Begun",
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


def write_playbook(text: str):
    with open(PLAYBOOK_FILE, "w") as f:
        f.write(text or "")


def run_one(task_rel: str, iters: int) -> tuple[bool, str]:
    cmd = ["./run_task.sh", "--task_dir", task_rel,
           "--max_iterations", str(iters), "--iterations_until_hint", str(iters),
           "--model", MODEL, "--easy_prompt", "--unguided_mode"]
    try:
        p = subprocess.run(cmd, cwd=CYB, env=_env(), capture_output=True,
                           text=True, timeout=1200)
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + "\n[TIMEOUT]"
    return ("_success_" in out), out


def digest(out: str) -> str:
    keep = [l for l in out.splitlines() if any(
        k in l for k in ("Reflection:", "Thought:", "Command:", "Answer:",
                         "Failed to solve", "Error executing"))]
    return "\n".join(keep[-12:])[:1600]


def score(playbook: str, tasks: list[str], iters: int):
    write_playbook(playbook)
    solved, fails = 0, []
    for t in tasks:
        ok, out = run_one(t, iters)
        name = t.split("/")[-1]
        print(f"    {'SOLVE' if ok else 'fail '} {name}", flush=True)
        if ok:
            solved += 1
        else:
            fails.append(f"[{name}] FAILED. Agent trace tail:\n{digest(out)}")
    return solved, fails


REVISER_SYSTEM = (
    "You are the REVISER in a self-evolving security-audit system (EvoHunt-style). "
    "You improve an AUDIT PLAYBOOK that a Cybersecurity CTF agent reads before each "
    "attempt. Given the current playbook and the failures it produced (with traces "
    "of what the agent tried), output an IMPROVED playbook.\n"
    "GENERALIZE each failure into a reusable tactic for the vulnerability CLASS or a "
    "procedural rule (e.g. an efficient method, a step budget, 'submit the answer "
    "the instant you recover a printable flag'). Do NOT memorize specific flags, "
    "task names, or one-off payloads — only transferable procedure. Keep it concise, "
    "structured markdown. Output ONLY the new playbook markdown."
)


def revise(current: str, fails: list[str], llm: TogetherLLM) -> str:
    fb = "\n\n".join(fails) or "(no failures)"
    return llm.raw_chat([
        {"role": "system", "content": REVISER_SYSTEM},
        {"role": "user", "content":
            f"CURRENT PLAYBOOK:\n{current or '(empty)'}\n\nFAILURES:\n{fb}\n\n"
            "Produce the improved playbook."},
    ], max_tokens=1500, temperature=0.5).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--iters", type=int, default=10)
    ap.add_argument("--seed-playbook", default="")
    args = ap.parse_args()

    load_dotenv()
    if not os.path.isdir(CYB):
        raise SystemExit("cybench/ not found — clone + run setup_cybench.py first")
    llm = TogetherLLM(model="deepseek-ai/DeepSeek-V4-Pro", temperature=0.4, seed=0)
    best_pb = open(args.seed_playbook).read() if args.seed_playbook else ""

    print(f"train tasks={len(TRAIN)} rounds={args.rounds} iters={args.iters}\n")
    print("round 0 (baseline / seed playbook):", flush=True)
    best_solved, best_fails = score(best_pb, TRAIN, args.iters)
    trace = [(0, "base", best_solved)]
    print(f"  -> solved {best_solved}/{len(TRAIN)}\n", flush=True)

    for r in range(1, args.rounds + 1):
        print(f"round {r}: revising playbook...", flush=True)
        cand = revise(best_pb, best_fails, llm)
        s, f = score(cand, TRAIN, args.iters)
        accepted = s > best_solved
        if accepted:
            best_pb, best_solved, best_fails = cand, s, f
        trace.append((r, "yes" if accepted else "no", best_solved))
        print(f"  round {r}: candidate solved {s}/{len(TRAIN)} "
              f"-> {'ACCEPTED' if accepted else 'rejected'} "
              f"(best {best_solved}/{len(TRAIN)})\n", flush=True)

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    out_pb = os.path.join(ROOT, "results", "cybench_evolved_playbook.md")
    open(out_pb, "w").write(best_pb)
    write_playbook("")  # reset the live playbook
    print("evolution trace (round, accepted, best_solved):")
    for row in trace:
        print(f"  {row}")
    print(f"\nbaseline {trace[0][2]}/{len(TRAIN)} -> final {best_solved}/{len(TRAIN)}")
    print(f"evolved playbook -> {out_pb}")


if __name__ == "__main__":
    main()
