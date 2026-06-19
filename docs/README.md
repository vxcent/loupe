# Loupe docs — index

Everything we've done, in the order to read it. The project asks one question —
*can an autonomous security system **self-improve** at telling real from false,
without fine-tuning?* — and answers it across two grounded testbeds (OWASP
findings; real Cybench exploits).

## Read in this order

1. **[EXPERIMENTS.md](EXPERIMENTS.md)** — the spine. Opens with **§0 Provenance &
   credibility** (every implemented feature → its peer-reviewed source paper, venue,
   and GitHub, credibility-tiered — read this to judge how solid each idea is and to
   dig into the papers). Then the full **experiment ledger (E1–E9)** and the
   **recalibration against EvoHunt**. If you read one file, read this.
2. **[REPLICATE.md](REPLICATE.md)** — exact commands to reproduce each meaningful
   finding by hand, with expected output and where results land.
3. **[SELF-EVOLVING.md](SELF-EVOLVING.md)** — the design/theory: what
   "self-evolving" means here (a governed loop, not accumulation), the
   memory-pollution threat + layered defense, and the 2025–2026 literature map.
4. **[CYBENCH.md](CYBENCH.md)** — the real-Cybench integration: how it's wired,
   how to reproduce it (`setup_cybench.py`), and its results.
5. **[EXPERIMENT-NEXT.md](EXPERIMENT-NEXT.md)** — the 2×2 ablation design (the
   discipline doc that prevented kitchen-sink confounding). *Status: its diagonal
   ran as E7 — see EXPERIMENTS.md for what that found and how E8 followed.*

## Where the artifacts are

`docs/samples/` — committed result artifacts you can open directly:

| file | from |
|------|------|
| `owasp-scaled-300.png` / `.csv` | E1 — the headline OWASP curve (memory = recall-booster) |
| `owasp-72case.png` / `.csv` | E2 — the smaller ablation that surfaced the distiller backfire |
| `mini-cybench-evolved-playbook.md` / `mini-cybench-evolution.csv` | E5 — the local-substrate evolve (learned the XOR crib tactic) |
| `cybench-evolve-E6.log` | E6 — first real-Cybench evolve |
| `cybench-ablation-E7.log` | E7 — the 2×2 diagonal (inconclusive; harness-confounded) |
| `cybench-selfevolve-E8.log` / `selfevolve-E8.csv` | **E8 — the meaningful self-evolve (0.58→0.67, tournament-gated)** |
| `selfevolve-best-playbook.md` | E8 — what self-evolution learned (submit-discipline + a reversing tactic) |

## The codebase, at a glance

- `eval.py`, `loupe/` — the validator-memory experiment (OWASP/fixture).
- `experiments/scale.py` — multi-seed concurrent OWASP curve (E1).
- `experiments/pollution.py` — the memory-pollution defense matrix (E3).
- `experiments/gepa_distiller.py` — GEPA-lite prompt evolution (E4).
- `experiments/cyber/` — the Cybench line:
  - `setup_cybench.py` — idempotent integration patcher (model + headless + playbook injection).
  - `cybench_adapter.py` — Cybench task → our interface (flag oracle).
  - `evolve.py` — mini-Cybench (local grounded substrate, E5).
  - `cybench_evolve.py` — first real-Cybench evolve (E6).
  - `cybench_ablation.py` — the 2×2 (E7).
  - `cybench_selfevolve.py` — the instrumented self-evolve with failure taxonomy (E8).
