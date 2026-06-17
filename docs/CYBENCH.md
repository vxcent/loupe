# Graduating the EvoHunt transplant to real Cybench

The mini-Cybench substrate (`experiments/cyber/`) validated the self-evolving
playbook loop on a local oracle. This is the plan + status for running it against
**real Cybench** (Stanford, 40 professional CTF tasks, deterministic flag oracle).

## What's been done (no Docker needed — safe)

- Cloned Cybench (`./cybench`, gitignored, ~2.9 GB).
- `experiments/cyber/cybench_adapter.py` — parses a task's `metadata/metadata.json`
  (prompt, categories, difficulty; **flag = final subtask's `answer`**,
  `answer_format`), detects whether a task needs Docker (`start_docker.sh`), and
  exposes a flag oracle (`check_flag`). Self-test (`python -m
  experiments.cyber.cybench_adapter`) parses the benchmark and lists the
  locally-runnable subset.
- **Finding:** 40 tasks; **21 need a live container target** (web/pwn + remote
  crypto); **13 are file-based** (crypto / reversing / forensics — you're given
  files and recover the flag) and parse cleanly with flags. Those 13, spanning
  difficulty 0–5, are the natural first tier.

## The integration (two options)

The playbook injects at one place: Cybench's agent prompt
(`cybench/agent/prompt.py::END_TO_END_PROMPT`) gains a `{playbook}` section. The
evolve loop (`evolve.py`) then wraps task execution exactly as it wraps the local
suite — only the task source and the "run a rollout" call change; the
reviser/tournament/oracle logic is unchanged.

- **Option A — Cybench's own harness (recommended, safest).** Inject the playbook
  into `agent/prompt.py`, run via Cybench's `run_task.py`, read its grading. The
  agent executes its commands **inside Cybench's Kali Docker container**, so
  model-written code is isolated. Requires Docker.
- **Option B — our agent + a constrained local exec tool.** For the 13
  file-based tasks, stage the task files into a scratch dir and give our agent a
  sandboxed `run_python` (subprocess, timeout). No Docker, runs on-leave — **but
  it executes model-written code on the host**, which is a real risk on a primary
  machine (see Safety).

## Safety

A CTF solver agent runs model-generated code. Cybench isolates this in Docker for
a reason. Even the "no-Docker-target" subset still wants **agent-code isolation**.
Do not run Option B unsandboxed on a primary machine. Acceptable isolation, in
order of preference: Docker (Option A) → a disposable VM / remote box → a tightly
constrained, timeboxed, network-denied subprocess in a throwaway dir (Option B,
last resort).

## Setup (Option A)

```bash
# 1. install Docker Desktop (macOS): brew install --cask docker ; then launch it
# 2. Cybench is already cloned at ./cybench
# 3. inject {playbook} into cybench/agent/prompt.py END_TO_END_PROMPT
# 4. wrap cybench/run_task.py in evolve.py's score() (replace the local rollout)
# 5. start with the 13 file-based tasks, then add the 21 container tasks
```

## Contamination note

CTF writeups are public, so report the **empty-vs-evolved-playbook delta**, not
absolute solve rate — the same control we use everywhere.
