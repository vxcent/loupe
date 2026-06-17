"""Adapter: real Cybench task -> our experiment's interface.

Cybench task layout (per task dir):
  metadata/metadata.json   categories, difficulty, easy_prompt/hard_prompt,
                           target_host, and subtasks[]; the FINAL subtask's
                           `answer` is the flag, with `answer_format`.
  init_script.sh           stages the solver-facing files into a working dir
  start_docker.sh          present IFF the task needs a live container target

This module only PARSES metadata and enumerates tasks — no code execution, no
Docker — so it's safe to run now and validates the integration against the real
benchmark. Actually running an agent against a task (which executes model-written
code) is gated behind the Docker/safety decision (see docs/CYBENCH.md).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

REPO = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "cybench")


@dataclass
class CybenchTask:
    id: str
    rel: str
    category: str
    difficulty: str
    prompt: str
    flag: str
    answer_format: str
    needs_docker: bool
    n_subtasks: int


def _meta_path(task_dir: str) -> str:
    return os.path.join(task_dir, "metadata", "metadata.json")


def load_task(task_dir: str, easy: bool = True, repo: str = REPO) -> CybenchTask:
    full = task_dir if os.path.isabs(task_dir) else os.path.join(repo, task_dir)
    with open(_meta_path(full)) as f:
        m = json.load(f)
    subs = m.get("subtasks", [])
    final = subs[-1] if subs else {}
    cats = m.get("categories", [])
    return CybenchTask(
        id=os.path.basename(full.rstrip("/")),
        rel=os.path.relpath(full, repo),
        category=cats[0] if cats else "?",
        difficulty=str(m.get("difficulty", "?")),
        prompt=m.get("easy_prompt" if easy else "hard_prompt", "").strip(),
        flag=final.get("answer", ""),
        answer_format=final.get("answer_format", ""),
        needs_docker=os.path.exists(os.path.join(full, "start_docker.sh")),
        n_subtasks=len(subs),
    )


def task_dirs(repo: str = REPO) -> list[str]:
    with open(os.path.join(repo, "task_list.txt")) as f:
        return [ln.strip() for ln in f if ln.strip()]


def local_tasks(repo: str = REPO) -> list[CybenchTask]:
    """No-Docker-target tasks (file-based: crypto / RE / forensics / misc)."""
    out = []
    for d in task_dirs(repo):
        try:
            t = load_task(d, repo=repo)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        if not t.needs_docker:
            out.append(t)
    return out


def check_flag(task: CybenchTask, submitted: str) -> bool:
    return submitted is not None and submitted.strip() == task.flag.strip()


def _selftest():
    if not os.path.isdir(REPO):
        print(f"Cybench not found at {REPO} — run: "
              "git clone --depth 1 https://github.com/andyzorigin/cybench.git cybench")
        return
    allt, no_meta = [], []
    for d in task_dirs():
        try:
            allt.append(load_task(d))
        except (FileNotFoundError, json.JSONDecodeError):
            no_meta.append(d.replace("benchmark/", ""))
    local = [t for t in allt if not t.needs_docker]
    print(f"total tasks: {len(allt)} parsed (+{len(no_meta)} without standard "
          f"metadata)  |  no-Docker target: {len(local)}\n")
    print(f"{'cat':<10}{'diff':<5}{'subtasks':>9}  task / flag-format")
    print("-" * 72)
    for t in sorted(local, key=lambda x: (x.category, x.difficulty)):
        flag_ok = "✓" if t.flag else "✗ NO FLAG"
        print(f"{t.category:<10}{t.difficulty:<5}{t.n_subtasks:>9}  {t.id}  "
              f"[{t.answer_format or '?'}] {flag_ok}")
    missing = [t.id for t in local if not t.flag]
    print(f"\nparsed {len(local)} local tasks; flags missing: {missing or 'none'}")


if __name__ == "__main__":
    _selftest()
