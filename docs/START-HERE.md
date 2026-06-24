# START HERE — onboarding + project snapshot (2026-06-23)

You're inheriting **Loupe**: a research effort to make a security-finding agent **self-improve
at telling real vulnerabilities from false positives, without fine-tuning** — the production
pain point of **PenPal** (a clear-box, cross-package pentest/code-review agent). A real PenPal
report is in `reference/penpal-monorepo-report.md` — read it first to see what the system
actually produces.

This doc gets you to the frontier fast: the current best understanding, the honest arc
(including what failed), and what to do next.

---

## 1. The punchline (read this even if you read nothing else)

Across 15 experiments + a 3-benchmark validation phase, two things became clear:

1. **False-positive reduction is bounded by where the discriminating evidence lives.** Give the
   model the evidence (local dataflow, or the cross-function slice, or *run the exploit*) and
   FPs drop; withhold it and the model defaults to a guess. Self-evolution/prompt-tricks are a
   *second-order polish on top of evidence*, not the lever.
2. **The verification that matters is the OUTCOME.** A finding is *confirmed real* iff a
   controlled attempt **produces the unwanted outcome (a PoC)** — an unfakeable, Goodhart-proof
   oracle. This reframes everything (see `INFERENCE-DESIGN.md`, the current state of thinking):

   - **Inner loop** = try to produce the outcome → three verdicts: **CONFIRMED-REAL** (PoC
     fired), **GROUNDED-BENIGN** (a soundness proof), **UNCONFIRMED** (gave up — *escalate,
     never suppress*). Only promote what you can reproduce ⇒ **zero false positives in the
     confirmed bucket by construction.**
   - **Outer loop** (self-evolution) = observe→evaluate→propose→verify→**commit**, where commit
     is **gated**: McNemar-significant gain in the imbalance-robust metric (MCC), Pareto
     no-regression on recall/precision, beats the champion, scored against a **grounded oracle**.
   - **Two-tier** to keep it affordable: cheap static triage *filters*, PoC-verification
     *confirms* the survivors.

If you build one thing: **the commit gate + a PoC-grounded oracle.** Everything we got wrong
traces to not having those.

---

## 2. Fast reading path

| Time | Read |
|---|---|
| **10 min** | this file → `INFERENCE-DESIGN.md` (the current architecture) |
| **30 min** | + open `recap.html` in a browser (visual arc, results vs SOTA) → `BENCHMARK-RESULTS.md` |
| **deep** | `EXPERIMENTS.md` (full E1–E15 ledger + §0 provenance — every mechanism → its peer-reviewed source) |
| **as needed** | `WHY-BENCHMARKS-DIFFER.md` (the evidence-locality diagnosis), `REPO-LEVEL-LEARNING.md` (JitVul + SASTBench results), `REPO-LEVEL-BENCHMARKS.md` (the 2026 benchmark menu), `REPLICATE.md` (commands) |

---

## 3. The arc in one table

| Phase | What | Finding |
|---|---|---|
| E1–E9 | memory / self-evolving playbook on OWASP + Cybench | self-evolution works but is fragile; needs a tournament gate (E8); verify-before-submit cuts FPs (E9) |
| E10 | GEPA/DSPy validator on OWASP | **context is the FP lever, not the prompt**; GEPA flat once context is good |
| E11–E13 | deployment-context "benign positive" (synthetic) | memory cuts FPs when the neutralizer is shared+probed; but stale/leaky memory → false negatives (the gain and the danger are one mechanism) |
| E14–E15 | reproduction-as-verification | grounded "benign" (failed reproduction) is safe — zero fabrication on real Cybench |
| Benchmark phase | OWASP / PrimeVul / Cybench at scale | OWASP F1 0.81 (CWE-routed, SOTA-adjacent); PrimeVul collapse (isolated-function detection doesn't transfer); Cybench 0 self-deception |
| Repo-level | JitVul + SASTBench | learning round is **regime-sensitive** (helped balanced, harmed imbalanced); the **recall wall** is missing evidence |
| Inference design | the gate + evidence-gathering + PoC-oracle | the unifying architecture (§1) |

---

## 4. Snapshot SINCE SASTBench — learned / missed / next

**What we learned (JitVul + SASTBench + the inference design):**
- A self-evolution **learning round is regime-sensitive**: +0.10 F1 and *generalized* on
  balanced JitVul; **net-harmful (MCC +0.23 → −0.13)** on imbalanced SASTBench. The difference
  is the data regime **and whether the round is gated.**
- **Context lifts precision; learning (sometimes) lifts recall** — different axes. With context
  present, learning adds ~0 (the E10 lesson at repo scale).
- The **recall wall** (SASTBench caught 1/16 real CVEs in *every* cell) is set by **missing
  evidence** — tactics can't fix it; only a deeper slice or execution can.
- MCC is the right headline on imbalanced data (accuracy/F1 hide collapses). McNemar is the
  right significance test for a commit gate. GEPA's Pareto (search-diversity over instances) is
  **not** the same as a Pareto commit gate (no-regression over metrics) — different layers.
- **The PoC-produces-the-outcome insight** crystallized the whole design (§1).

**The misses (so you don't repeat them):**
- **We ran the outer loop OPEN** — `verify → commit` had no gate, so the harmful SASTBench
  round *shipped*. The single biggest architectural miss; the fix is cheap.
- **We over-indexed on OWASP early** — its contained-method format is the regime *least* like
  PenPal; the wins didn't transfer (PrimeVul/SASTBench).
- **`observe` is one-shot** — no iterative evidence-gathering, so the recall wall has no exit.
- **The reflector leaked semi-specific tactics** (JitVul) — generality wasn't enforced.
- **SASTBench's FP labels are approximate** (Semgrep-assumed-benign) — a gate over a noisy
  oracle is suspect; this is *why* the PoC-grounded oracle matters.
- We used **our own runner**, not SASTBench's official harness — faithful reproduction, not a
  certified leaderboard number.

**Next experiment steps (prioritized):**
1. **Wire the commit gate** (McNemar + Pareto-no-regression + champion) into the learning round
   and re-run SASTBench → should convert the harmful commit into a *rejection*. (cheap, proves
   the fix.)
2. **Gate comparison meta-experiment** on JitVul (trusted labels): naive-F1 vs McNemar vs Pareto
   vs conjunction → false-merge / false-reject rates.
3. **PoC-grounded oracle**: per-CWE outcome predicates + a sandbox; two-tier (triage → confirm).
   The real fix for both the oracle and the recall wall.
4. **Iterative `observe`** (abstain-and-escalate + deeper cross-function slice) — attack the
   recall wall.
5. **JitVul circle-back** (deeper slice, reflector generality fix, scale + CI) — still owed.
6. (stretch) a 2026 find-prove-patch bar — **AIxCC/OSS-CRS** or **CyberGym-E2E** (see
   `REPO-LEVEL-BENCHMARKS.md`).

---

## 5. Things we tried and FAILED — distilled

Keep these; they're the expensive lessons:
- **Unconditional/over-broad lessons over-generalize** (E2) → use *precondition-guarded* rules.
- **Full-rewrite reviser causes cross-category pollution + context-collapse** (E6) → incremental
  edits (ACE).
- **Binary solve-metric hides the cause** (E7) → instrument the failure taxonomy.
- **Suppression trap**: a metric that rewards not-submitting collapses to never-submit (E9);
  its mirror, an ungated learning round on imbalanced data, collapses to over-flag (SASTBench).
  → asymmetric, Pareto-guarded, **gated** metrics only.
- **Context truncation** silently hid the discriminative dataflow (E10) → feed the full slice.
- **Stale/leaky memory → false negatives** (E12/E13) → memory needs re-verification + confidence.
- **Asserted (not executed) reproduction lets a strong model "look right for the wrong reason"**
  (E14) → ground in execution (E15).
- **Isolated-function detection doesn't transfer to real repos** (PrimeVul/SASTBench) → the unit
  is the *reachable slice* or the *executed outcome*, not a snippet.

---

## 6. Codebase map

**Core library — `loupe/`** (the validator + memory primitives): `schema.py` (Finding/Verdict/
Lesson + assumption-scoping), `llm.py` (Together backend + MockLLM), `prompts.py`, `memory.py`
(write-gate + scope), `loop.py` (the outer loop), `data.py` (OWASP loader), `metrics.py`, `plot.py`.

**Live harnesses (current frontier):**
- `experiments/sastbench/run_sastbench.py` — SASTBench triage; **git-checkout repo@commit** +
  our validator + learning round (the on-thesis repo-level harness).
- `experiments/bench_jitvul.py` — repo-level learning 2×2 (context × learning), trusted-ish labels.
- `experiments/bench_owasp_scale.py` — OWASP at scale + **CWE routing** (Set 1/1b, F1 0.81).
- `experiments/bench_primevul.py` — PrimeVul vuln↔fix pairs (Set 2, the collapse).
- `experiments/cyber/bench_cybench_repro.py`, `cyber/reproduce_grounded.py` — executable
  reproduction (Set 3 / E15), real flag oracle.
- `experiments/gain_bp.py` — deployment-context synthetic gain + drift/noise (E11–E13).
- `experiments/reproduce_evolve.py` — reproduction-as-verification + skill learning (E14).

**The arc, kept for the record (older / superseded by the above):** `scale.py` (E1),
`pollution.py` (E3), `gepa_distiller.py` (E4), `gepa_validator.py` (E10), and `cyber/`:
`evolve.py` (E5 mini-Cybench), `cybench_evolve.py` (E6), `cybench_ablation.py` (E7),
`cybench_selfevolve.py` (E8), `cybench_evohunt.py` (E9), plus the substrate
(`agent.py`/`challenges.py`/`oracle.py`/`adapter`) and `setup_cybench.py` (idempotent Cybench
integration), `prescreen.py`, `confirm_eval.py`.

**Data:** `data/fixture.jsonl` (the original fixture); `reference/penpal-monorepo-report.md` (a
real PenPal output). Large benchmark checkouts are gitignored: `benchmark/` (OWASP),
`repolevel/` (JitVul + VulEval + SASTBench + a repo-checkout cache), `primevul_data/`,
`cybench/`. Fetch them via `scripts/` and the per-harness headers.

**Docs:** `EXPERIMENTS.md` is the authoritative ledger; `INFERENCE-DESIGN.md` is the current
thinking; `recap.html` is the visual summary. `EXPERIMENT-NEXT.md` is **superseded** (an old 2×2
plan that ran as E7) — kept only for history.

---

## 7. Running things

`requirements.txt` + a Together AI key in `.env` (see `.env.example`; the key in chat history is
shared-plaintext — **rotate it**). Each harness has a runnable example in its module docstring;
`REPLICATE.md` has the canonical commands. Most harnesses run on **MockLLM** (free, offline) for
a plumbing check and **`--backend together`** for a real result. Heavy runs are rate-limited —
shard + run in the background.
