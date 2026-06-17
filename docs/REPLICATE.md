# Replicate the meaningful findings by hand

Exact commands, what to expect, and where output lands. Run from the repo root.

## 0. One-time setup

```bash
pip install -r requirements.txt           # openai, matplotlib
cp .env.example .env                       # then put your TOGETHER_API_KEY in .env
```

All real runs use Together AI; the agent rollouts use `deepseek-ai/DeepSeek-V4-Pro`.
Outputs land in `results/` (gitignored); committed copies of the key ones are in
`docs/samples/`.

---

## OWASP line (validator memory) — laptop, no Docker

### E1 — the headline curve (memory is a recall-booster, not an FP-cutter)

```bash
bash scripts/get_owasp.sh                  # sparse checkout -> ./benchmark (~once)
python experiments/scale.py --owasp-dir benchmark --limit 300 --seeds 3 --workers 8
# -> results/scale_curve.csv + .png   (cmp docs/samples/owasp-scaled-300.*)
```
Expect: baseline solve... i.e. baseline bp≈0.508 recall≈0.904; distilled-lessons
recall≈0.998, suppression≈0.002 (±0.003). bp_rate barely moves; **recall is where
memory wins.** A cheap smoke first: `python eval.py --backend mock`.

### E3 — memory-pollution defense matrix (deterministic, no API key)

```bash
python experiments/pollution.py            # or: make pollution
```
Expect: corruption stays 1.0 under none / write-gate-only / scope-only, and drops
to **0.0** under `write-gate+scope` or `flag-don't-flip`, with benign_kept = 1.0.

### E4 — GEPA-lite distiller prompt evolution

```bash
python experiments/gepa_distiller.py --owasp-dir benchmark --limit 60 --generations 4
# -> results/gepa_best_distiller.txt
```
Expect: a Pareto frontier over (bp, recall, suppression); the evolved prompt
independently adds a fail-open recall bias.

---

## Cybench line (exploit-grounded self-evolution) — needs Docker

### Setup (once)

```bash
# install + launch Docker Desktop, then:
git clone --depth 1 https://github.com/andyzorigin/cybench.git cybench
python experiments/cyber/setup_cybench.py   # registers DeepSeek-V4-Pro, headless, playbook injection
# smoke test the pipeline:
cd cybench && ./run_task.sh --task_dir 'benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Primary Knowledge' \
  --max_iterations 12 --iterations_until_hint 12 --model together/deepseek-v4-pro --easy_prompt --unguided_mode ; cd ..
# success => the saved log filename contains _success_
```

### E5 — mini-Cybench (local grounded substrate, no Docker needed)

```bash
python -m experiments.cyber.evolve --rounds 4
# -> results/cybench_evolution.csv + results/evolved_playbook.md
```
Expect: baseline 0.67 (weak-XOR fails) → reviser learns the known-plaintext crib
tactic → tournament accepts → 1.00. (cmp `docs/samples/mini-cybench-*`)

### E8 — the instrumented self-evolve (the meaningful capability-increase run)

```bash
python -m experiments.cyber.cybench_selfevolve --rounds 3 --reps 3 --iters 15
# -> results/cybench_selfevolve.csv, results/selfevolve_best_playbook.md,
#    results/selfevolve_candidates/round*.md
```
This is the run that fixes E7's confounds: a **failure taxonomy**
(solved / found_not_submitted / wrong_submit / no_solve) instead of binary solve,
a **grounded** reflector (tactics anchored to the real `Answer:` submission), reps≥3,
and candidate logging. Expect: **solve_rate rises and found_not_submitted falls**
from baseline to final, with the tournament accepting beneficial revisions.
(Several hours, real Together spend. See EXPERIMENTS.md E8 for the numbers.)

### (diagnostic) E6 / E7 — the runs that motivated E8

```bash
python -m experiments.cyber.cybench_evolve   --rounds 2 --iters 10   # E6: tournament holds, full-rewrite harmful
python -m experiments.cyber.cybench_ablation                         # E7: 2x2 diagonal, inconclusive (see correction)
```

---

## How to read a Cybench result by hand

Each rollout writes `cybench/logs/<Task>/together/deepseek-v4-pro/<ts>/together/*_run_log.json`,
and the filename encodes the grade (`_success_` / `_fail_`). To see *why* a run
failed (the E7 lesson — binary solve hides this):

```bash
# was it solve / found-but-not-submitted / wrong-submit / no-solve?
python -c "from experiments.cyber.cybench_selfevolve import classify; \
from experiments.cyber.cybench_adapter import load_task; \
t='benchmark/hackthebox/cyber-apocalypse-2024/crypto/[Very Easy] Primary Knowledge'; \
print(classify(t, load_task(t).flag)[0])"
```
