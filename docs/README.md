# Loupe docs — index

**New here? → [START-HERE.md](START-HERE.md).** It has the punchline, the project snapshot
(what we learned, what we missed, what's next), the distilled failures, and the codebase map.

## Reading order

1. **[START-HERE.md](START-HERE.md)** — onboarding + snapshot. Start here.
2. **[INFERENCE-DESIGN.md](INFERENCE-DESIGN.md)** — *current state of thinking.* The PoC-as-oracle
   architecture: the commit gate (McNemar + Pareto-no-regression + champion), the
   evidence-gathering stopping rule, and the three verdicts (CONFIRMED-REAL / GROUNDED-BENIGN /
   UNCONFIRMED).
3. **[HILLCLIMB-DESIGN.md](HILLCLIMB-DESIGN.md)** — the loop *system* for hill-climbing the verifier: each inference round → trace → grounded grade → harness-vs-model attribution → gated gradual change.
4. **[recap.html](recap.html)** — the visual arc (open in a browser): results next to named SOTA.
4. **[EXPERIMENTS.md](EXPERIMENTS.md)** — the authoritative ledger (E1–E15) + **§0 provenance**
   (every implemented mechanism → its peer-reviewed source, credibility-tiered).

## Reference docs (read as needed)

- **[BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md)** — the 3 industry sets at scale (OWASP / PrimeVul / Cybench) + cross-set synthesis.
- **[BENCHMARK-PLAN.md](BENCHMARK-PLAN.md)** — why those 3 sets, the metrics, the controls.
- **[WHY-BENCHMARKS-DIFFER.md](WHY-BENCHMARKS-DIFFER.md)** — the evidence-locality diagnosis (why OWASP succeeds, PrimeVul collapses).
- **[REPO-LEVEL-LEARNING.md](REPO-LEVEL-LEARNING.md)** — JitVul + SASTBench learning-round results (the regime-sensitivity finding).
- **[REPO-LEVEL-BENCHMARKS.md](REPO-LEVEL-BENCHMARKS.md)** — the 2026 benchmark menu (incl. AIxCC/OSS-CRS, CyberGym, SASTBench), matched to PenPal.
- **[GAIN-PROTOCOL.md](GAIN-PROTOCOL.md)** — the matched-pairs gain metric (CL-Bench-style).
- **[SELF-EVOLVING.md](SELF-EVOLVING.md)** — memory design, the pollution threat + layered defense, the 2025–26 literature map.
- **[CYBENCH.md](CYBENCH.md)** — the real-Cybench integration (`setup_cybench.py`).
- **[REPLICATE.md](REPLICATE.md)** — exact commands to reproduce each finding.
- *[EXPERIMENT-NEXT.md](EXPERIMENT-NEXT.md)* — **superseded** (an early 2×2 plan that ran as E7); kept for history.

## Artifacts

`docs/samples/` — committed result logs/plots for the meaningful runs (OWASP, PrimeVul, Cybench,
JitVul, SASTBench, GEPA, the self-evolve runs). Each is named for the experiment it backs.

## Codebase

See **[START-HERE.md §6](START-HERE.md)** for the full map: `loupe/` (core library), the live
harnesses in `experiments/` (+ `experiments/cyber/`), the data layout, and which experiments are
current vs kept-for-the-record.
