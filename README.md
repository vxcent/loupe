# Loupe

A loupe is the magnifier used to tell a real stone from a fake one — and it's a
homophone for **loop**, the thing being engineered here.

**Question:** does verified-lesson *memory* make a security-finding **validator**
better at separating real vulnerabilities from *benign positives* — findings that
look correct in the code but are neutralized in deployment (upstream auth/mesh,
unreachable routes, sanitization, blocked egress, unmet preconditions)?

This is the pain point from a production pentest agent (PenPal): findings that are
true on paper get surfaced, but the deployed system says otherwise.

## Hypothesis (falsifiable)

> A validator that writes back *verified deployment/exploitability lessons* and
> reuses them achieves a **lower benign-positive rate at equal-or-better recall**
> than the identical validator without memory, and improves as it sees more findings.

The result is a **shape**: the memory arm's benign-positive-rate curve bends down
and separates from a flat no-memory baseline — *while the recall curve stays pinned
at the top*. The joint condition is the pass/fail (you can fake a low bp-rate by
suppressing everything; `suppression_error` is the guardrail that catches it).

## What is frozen vs. varied

The experiment changes exactly **one** thing — the validator — so any delta is
attributable to memory, not to a noisier agent.

```
frozen ──────────────────────┐
analyzer / call-chain (upstream)│→ candidate findings ─┬→ Validator A: no memory   → baseline
                                                       └→ Validator B: + memory    → arm(s)
```

Findings are loaded from disk (cached), so a run is "read file → validate → plot"
and reproduces exactly.

## Loop-engineering knobs (`LoopConfig`)

Each setting is its own curve to overlay — the story is "a *well-engineered loop*
helps, not memory per se":

| knob | values | what it tests |
|------|--------|---------------|
| `memory` | on / off | the headline ablation |
| `distill` | `lesson` / `raw` | does generalizing the outcome beat storing the raw verdict |
| `cadence` | `online` / `batch` | update after each finding vs. after a pass |
| `retrieval` | `exact` / `loose` | precision vs. recall of lesson reuse (over-generalization risk) |

## Run

```bash
pip install -r requirements.txt
cp .env.example .env   # add TOGETHER_API_KEY

# fixture (14 findings — wiring check only)
python eval.py --backend mock                  # offline plumbing demo (not a result)
python eval.py --backend together              # real run on the fixture

# OWASP Benchmark (the real learning curve)
bash scripts/get_owasp.sh                       # sparse/shallow checkout -> ./benchmark
python eval.py --backend together --owasp-dir benchmark \
    --limit 72 --shuffle --window 24 --plot --out results/owasp_curve.csv
# narrow to a few classes to cut cost:  --categories pathtraver,sqli,xss

# evolve the distiller prompt (GEPA-lite: reflective + Pareto over bp/recall/supp)
python experiments/gepa_distiller.py --owasp-dir benchmark --limit 60 --generations 4

# trustworthy multi-seed curve with error bars (runs arm x seed concurrently)
python experiments/scale.py --owasp-dir benchmark --limit 300 --seeds 3 --workers 8
```

Output: a per-arm summary table + `results/<name>.csv` (long format: arm, i,
bp_rate, recall, suppression_error), and with `--plot` a `<name>.png` of the
overlaid curves.

## Data

- `data/fixture.jsonl` — 14 findings modeled on the real PenPal report, with
  **transfer structure** (multiple findings per root-cause class) and **2 traps**
  (a `/admin/` endpoint and a search-pod SSRF that *are* exploitable despite
  sharing a class with benign siblings). Traps punish lazy over-generalization.
- `loupe/data.py::load_owasp` — maps the **OWASP Benchmark** (~2,700 labeled
  true/false-positive Java cases) into Findings; `class_key` = category so
  findings of the same sink share a class and memory can transfer. This is what
  gives a statistically trustworthy learning curve. `scripts/get_owasp.sh` does a
  sparse/shallow checkout (sources + answer key only). The fixture is only a
  wiring check.

## Results — scaled, multi-seed (300 cases × 3 arms × 3 seeds)

![scaled curve](docs/samples/owasp-scaled-300.png)

| arm | bp_rate | recall | suppression_error |
|-----|--------:|-------:|------------------:|
| memory-off (baseline)         | 0.508 ± 0.002 | 0.904 ± 0.003 | 0.096 ± 0.003 |
| memory / raw-verdicts         | 0.505 ± 0.001 | 0.962 ± 0.003 | 0.038 ± 0.003 |
| memory / distilled-lessons    | 0.501 ± 0.001 | **0.998 ± 0.003** | **0.002 ± 0.003** |

The error bars (±std across seeds) are tiny — temperature-0 run-to-run noise is
~0.003, so the N=72 worry about drift was overblown. With that settled, the
result is an **honest reframe of the hypothesis**:

- **Benign-positive rate barely moves** (0.508 → 0.501; ~3σ but trivially small).
  On OWASP, verified-lesson memory does **not** cut false positives. The
  benchmark's FPs are sanitizer/reachability cases the cold validator already
  handles; memory has no deployment context to cut them further.
- **The benefit is on the recall axis, and it compounds.** In the lower panel the
  baseline's recall *degrades* across the run (~0.95 → ~0.80) as it meets harder
  real cases, while **distilled-lessons memory holds recall at ~1.0** and drives
  suppression_error to ~0 — it stops missing real vulnerabilities by reinforcing
  confirmed-real classes. The gap widens with more findings: *that* is the
  learning curve, just on a different axis than first hypothesized.
- **distilled > raw > baseline, monotonic** — generalizing the outcome into a
  lesson clearly beats storing the raw verdict, at scale, with error bars.

So memory here is a **miss-reducer, not an FP-cutter**. Whether it cuts the
*deployment-context* benign positives that are PenPal's actual pain is something
OWASP **cannot** answer (it lacks the topology dimension) — that needs the
grounded tier. This is an honest, statistically-backed negative on the FP axis
and a strong positive on recall.

### What the loop-engineering knob bought us (72-case ablation)

The first version of the distiller wrote *unconditional* rules and **backfired** —
distilled-lessons suppression hit 0.227 (it marked real findings benign because a
class sibling was). Tightening the distiller to emit **conditional, guarded**
rules ("benign ONLY IF control X is present; else exploitable") and making the
validator **apply a lesson only when its precondition holds** fixed it:

| arm | suppression_error before | after |
|-----|--------:|--------:|
| memory-on / distilled-lessons | 0.227 | **0.000** |

That is the whole thesis in miniature: it is not *memory* that helps, it is a
*well-engineered loop* — the same memory with a sloppy distiller is net-harmful.

This 72-case ablation first surfaced the recall-vs-FP split and the distiller
backfire; the scaled run above confirms both directions with error bars.

## Pollution resistance (the memory-safety experiment)

`python experiments/pollution.py` — the worry: a lesson learned from one case is
retrieved for the whole class, so a wrong/over-broad ("poisoned") lesson can
silently suppress a REAL bug that shares the class. We model PenPal's per-decision
**assumptions** on each finding, scope benign lessons to the control they depend
on, and test a defense matrix:

```
defense regime            poison?  corruption  benign_kept
none (auto-apply)             yes 2/2 = 1.00  5/5 = 1.00
write-gate only                no 2/2 = 1.00  5/5 = 1.00
scope only                    yes 2/2 = 1.00  5/5 = 1.00
write-gate + scope             no 0/2 = 0.00  5/5 = 1.00
flag-don't-flip only          yes 0/2 = 0.00  5/5 = 1.00
full defense                   no 0/2 = 0.00  5/5 = 1.00
```

**No single layer suffices** — write-gate stops the poison but the clean lesson
still misfires unscoped; scope alone lets the unconditional poison through.
`write-gate + scope` (or `flag-don't-flip`, which re-grounds from the finding's
own assumptions instead of trusting a lesson's claim) drives corruption to 0
**without** losing the legitimate benign-suppression benefit. The defenses are
drawn from the 2025–2026 agent-memory-safety literature (write-time admission >
retrieval filtering; assumption-scoped retrieval; lesson-flags-don't-flip).

## EvoHunt transplant — self-evolving playbook on a grounded oracle (mini-Cybench)

`experiments/cyber/` transplants EvoHunt's audit→evaluate→**revise**→tournament
loop onto a tool-using pentest agent, grounded by a deterministic flag oracle
(local, pure-Python challenges — no Docker; swappable with real Cybench). The
evaluator uses EvoHunt-style **evidence tiering** (T1 flag / T2 vuln-triggered /
T3 claim-without-proof) and tracks **self-deception** (claimed-solved but wrong).

```
round   accepted  train_solve  test_solve  self_decep
0(base)    -          0.67        1.00        0.00
2          YES        1.00        1.00        0.00     <- revision accepted
4          no         1.00        1.00        0.00
```

The empty-playbook agent fails weak-XOR (T3 — it brute-forces one key per step and
runs out). From the failure trace the reviser distilled a **generalizable tactic**
(`docs/samples/mini-cybench-evolved-playbook.md`):

> *If the key is a single byte, compute the XOR of the ciphertext with the crib
> `flag{` to recover the key byte directly … avoids iterating the key space.*

The tournament accepted it (round 2 only), train solve went **0.67 → 1.00**, no
self-deception, no degradation. The loop self-improves, grounded by an oracle it
can't fool — even DeepSeek-V4-Pro fails weak-XOR without the playbook, so the lift
comes from learned procedure, not model power (EvoHunt's thesis).

**Honest limits:** small-N and single-rep (noisy); **transfer is unproven here** —
the held-out suite was already at 1.00 at baseline (ceiling), so it can't show the
tactic lifting unseen challenges. Needs harder/more held-out challenges + reps for
a real transfer curve, then real Cybench as the fidelity tier.

## Honest scope

This validates the **learning mechanism** on labeled findings. It does **not**
reproduce PenPal's real benign-positive rate — public benchmarks lack the
deployment-topology dimension that flips a finding in production. Report the
**delta between arms** (robust to model/training-data contamination), not absolute
precision. A small-N grounded tier (dockerized live targets where the oracle is
*did the exploit actually fire*) is the future fidelity check.

## Design & docs

**Start at [`docs/README.md`](docs/README.md)** — the index with reading order and
the artifact map. [`docs/REPLICATE.md`](docs/REPLICATE.md) has exact commands to
reproduce every finding by hand. Key docs:

- `docs/EXPERIMENTS.md` — **the experiment ledger** (E1–E6 results) and an explicit
  **recalibration against EvoHunt** (what we matched, diverged on, and should
  adopt). Start here for "where are we."
- `docs/SELF-EVOLVING.md` — what self-evolving means for a validator (a governed
  loop, not memory accumulation), how PenPal's per-decision assumptions+confidence
  log grounds it, the memory-pollution threat + layered defense, and the
  2025–2026 literature map.
- `docs/CYBENCH.md` — the real-Cybench integration (proven), how to reproduce it,
  and the first evolve-run result.
- `docs/EXPERIMENT-NEXT.md` — locked design for the next iteration: a 2×2 ablation
  (full-rewrite vs incremental × global vs scoped injection) with the ACE/EvoHunt
  reconciliation decided up front, so the next run attributes a cause.

## Layout

```
loupe/schema.py    Finding / Verdict / Lesson
loupe/prompts.py   validator + distiller prompts (label never shown to validator)
loupe/llm.py       TogetherLLM (real) + MockLLM (offline demo)
loupe/memory.py    SQLite lesson store; predicate-based retrieval
loupe/loop.py      the outer loop = the experiment
loupe/metrics.py   bp_rate / recall / suppression_error + learning curve
eval.py            runner
reference/         the original PenPal report that motivated this
```
