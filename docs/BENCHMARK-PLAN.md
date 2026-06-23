# Execution plan — testing the Loupe harnesses against 3 industry SOTA benchmark sets at scale

**Goal.** Take our *existing* harnesses (the validator/`load_owasp` + `gain_bp.py`; the
reproduction loop `reproduce_evolve.py`; the execution-grounded
`reproduce_grounded.py` + Cybench adapter) and run them at scale against **three
industry-level benchmark sets**, so the FP-reduction findings (E1–E15) graduate from a
*synthetic* PoC to *credible, comparable-to-SOTA* evidence.

This plan is written **after** a verified research pass (sources at the end). It states,
per set: what we test against, the harness, the scale, the exact metrics, the **SOTA
baseline to beat**, the expected finding, the learning/takeaway, and the **confidence
boost**.

---

## 0. The three sets — chosen to span the three FP regimes, each with a known baseline

Our findings split the false-positive problem into three regimes. We pick one
industry benchmark per regime so each harness is tested where it's supposed to win — and
honestly exposed where it might not.

| Set | Benchmark (license) | Regime it tests | Our harness | SOTA bar to beat / compare |
|-----|---------------------|-----------------|-------------|-----------------------------|
| **1** | **OWASP Benchmark v1.2** — 2,740 Java cases, ~1,415 TP / 1,325 FP, clean CSV labels (GPL-2.0) | Code-level FP discrimination | `loupe/` validator + `load_owasp` + `gain_bp.py` (**native**) | CodeQL FPR ≈ **68%**, F1 ≈ 0.74; ZeroFalse LLM F1 ≈ **0.91** (Grok-4/Gemini-2.5) |
| **2** | **PrimeVul** — 235k C/C++ funcs, 5,480 **vuln↔fix pairs**, clean labels (86–92% vs 25–60% legacy), MIT | Real-world repo FP on **trustworthy** labels | same validator + a thin PrimeVul loader; **pairs = native matched-pairs gain** | The collapse bar: SOTA 7B model **68%→3% F1** BigVul→PrimeVul; GPT-4 predicts *both* of a pair vulnerable **54%** (FP bias) |
| **3** | **Cybench** — 40 pro CTF tasks, exact-flag oracle (Apache-2.0) **+ CVE-Bench/UIUC** — 40 real web CVEs, runtime exploit-fired oracle (Apache-2.0) | Executable reproduction; real-CVE deployment-context BP | `reproduce_grounded.py` + existing `setup_cybench.py` adapter (**native** for Cybench) | Cybench: Claude-3.5 **17.5%** unguided (paper); CVE-Bench: best agents **~13%** one-day exploit |

**Secondary/stretch substrates** (cited, used only if a set's primary needs reinforcement):
IRIS + **CWE-Bench-Java** (Java repo-scale, real CodeQL **FDR 90%→85%** baseline to beat — but CC BY-NC-ND), ZeroFalse's **OpenVuln** (58 real Java cases, directly comparable to SOTA F1 0.955), **D2A** (real Infer FP/TP, noisy labels), **NYU CTF Bench** (200 tasks, GPL-2.0), **AutoPenBench** (real-CVE pentest chains, MIT).

---

## 1. Set 1 — OWASP Benchmark v1.2 (code-level FP, at full scale)

**What we're testing against.** 2,740 self-contained Java servlets, each one vuln,
half real / half a deliberate false positive, with a machine-readable `true/false`
label per case across ~11 CWEs. The cleanest TP-vs-FP ground truth in the field, and
the one with a well-documented "before" number (CodeQL FPR ≈ 68%).

**Harness (native).** `loupe/data.py::load_owasp` already parses the CSV + servlets.
`gain_bp.py`/`eval.py` already run the validator. We scale our prior **300-case** runs
(E1/E10) to the **full 2,740** and add the E10 **context** lever (full method, not the
1600-char truncation) and the optional GEPA arm.

**Scale & cost.** Full set = 2,740 cases × {baseline, full-context, +memory} arms ×
multi-seed. At temp-0 with caching, ~2,740 validate calls per arm. **Tiered:** (a)
smoke 160 balanced; (b) representative 800 stratified by CWE; (c) full 2,740 ×3 arms.
Budget the full run as the headline; rate-limiting means run it backgrounded in CWE
shards.

**Metrics (pre-registered, suppression-guarded).** Per-CWE and overall: `fp_rate`,
`precision`, `recall`, `balanced_acc`, `F1`; the matched-pairs **gain** (full-context −
truncated) with bootstrap CI; the suppression guard (ΔFP↑ requires ΔrecallΦ≥−ε).

**Expected finding.** E10 at scale: full source→sink context drives `fp_rate` from
~0.15 → ~0.00–0.10 and precision → ~0.9–1.0 **with no optimization**, landing **near
the ZeroFalse SOTA band (F1 ≈ 0.91)** — and beating raw CodeQL's 68% FPR by a wide
margin. GEPA adds little on top of good context (E10 holds).

**Learning / takeaway.** Confirms, at the field-standard scale and against published
numbers, that **the code-level FP lever is context, not optimization** — and that our
validator is competitive with 2025 SOTA FP-reduction systems.

**Confidence boost.** *High and immediate.* Moves "context is the lever" from a
300-case in-house result to a **2,740-case, CWE-stratified result comparable to a named
2025 SOTA (ZeroFalse) and beating a named baseline (CodeQL)**. Lowest access friction —
do this first.

---

## 2. Set 2 — PrimeVul (real-world repo FP on trustworthy labels) — the credibility-defining test

**What we're testing against.** 235k real C/C++ functions from 755 projects, **clean
labels** (PrimeVul-NVDCheck 92% vs 25–60% for BigVul/Devign), and crucially **5,480
vulnerable↔fixed function pairs**. PrimeVul is *the* benchmark where LLMs that look
great on noisy data **collapse** (a SOTA 7B model: 68% F1 on BigVul → **3% F1** on
PrimeVul; GPT-4 labels *both* members of a pair "vulnerable" **54%** of the time — pure
FP bias). Its **VD-S** metric (false-negative rate at FPR ≤ 0.5%) is purpose-built to
expose FP behavior.

**Why it's the keystone for us.** The vuln↔fix **pair is a native matched-pairs gain
instrument**: the fixed function is the *exact* benign twin of the vulnerable one (same
code, minus the bug). "Does the validator call the vulnerable one real and the fixed one
benign?" is precisely our gain metric — and it's the discriminator GPT-4 fails. This is
where our context-lever claim either survives on **real** code or is honestly falsified.

**Harness (small adaptation).** Reuse the same validator; write a thin
`load_primevul()` that yields `(vulnerable_fn, fixed_fn)` pairs as a finding + its
benign twin. No build needed (JSON function bodies). MIT license — clean to use.

**Scale & cost.** Pair-wise eval on a stratified sample of the 5,480 pairs (start 200
pairs = 400 calls; scale to 1,000+). Report pair-wise accuracy + VD-S, matched to
PrimeVul's own protocol so numbers are directly comparable.

**Metrics.** PrimeVul's **pair-wise correct** (both right), **P-V** (both-vulnerable =
FP bias, the thing to drive down from GPT-4's 54%), **VD-S**, plus our `precision`,
`fp_rate`, and the matched-pairs **gain** (full-context vs truncated) on real code.

**Expected finding (honest, two-outcome).** Either (a) **our context-lever holds on
real code** — pair-wise accuracy and precision materially above GPT-4's baseline, P-V
well below 54% → a *strong, credible* result that the lever generalizes beyond OWASP's
synthetic servlets; or (b) **it partially collapses like everyone else** → an honest,
publishable finding that *synthetic FP wins don't fully transfer to real code*, locating
exactly where the context lever weakens (which CWEs, which code complexity). Both are
high-value; (b) is the one that keeps us honest.

**Learning / takeaway.** Tells us whether FP reduction by context is a **real-code**
phenomenon or a benchmark artifact — the single most important external check on the
whole thesis.

**Confidence boost.** *Highest.* PrimeVul is the field's credibility filter; a good
number here is the difference between "works on a toy" and "works where SOTA fails." A
bad number is the most important thing we could learn before claiming anything to
leadership.

---

## 3. Set 3 — Cybench + CVE-Bench (executable reproduction; real-CVE deployment-context BP)

**What we're testing against.**
- **Cybench** (40 CTF tasks, 6 categories, **exact-flag** oracle, Apache-2.0): the clean
  executable substrate we already integrated (E6–E9). Reproduction = capture the flag —
  unfakeable.
- **CVE-Bench/UIUC** (40 real web-app CVEs, **runtime exploit-fired** oracle via a `/done`
  eval server checking 8 attack categories against real target state, Apache-2.0): the
  holy grail for our deployment-context **benign-positive** thesis — a CVE that is real in
  code but whose exploit **doesn't fire in the sandboxed deployment** is a *grounded*
  benign positive on a **real CVE**, exactly E11/E15 meeting reality.

**Harness.** `reproduce_grounded.py` (E15) + existing `setup_cybench.py` adapter is
**native for Cybench** — scale from our 3–5 task runs to the full 40, and add
benign-positive variants (the E15 design). CVE-Bench is a **new adapter** to its Docker
eval server (heavier — Phase 3).

**Scale & cost.** Cybench full 40 × reps, Dockerized (we have the integration); budget
~hours, run sharded (rate-limited, as observed). CVE-Bench: 40 CVEs × Docker-Compose
targets — a real infra lift; scope to a 10-CVE pilot first.

**Metrics.** Grounded **reproduction rate** (flag captured / exploit fired); on benign
variants the **false-claim rate** (E15's self-deception, must stay ~0); the technique-
library **capability curve** across iterations with **anti-regression** (E14); and the
**thoroughness→confidence** calibration (E15 caveat: does a deeper attempt correctly
separate hard-real from benign?).

**Expected finding.** Cybench: grounded reproduction-as-verification scales — reals
reproduce, benign variants draw ~0 false claims (E15 at 40-task scale), capability rises
with the technique library and the anti-regression guard holds. CVE-Bench: on real CVEs,
"exploit doesn't fire in this deployment" becomes a **grounded benign-positive signal** —
the first real-CVE evidence for the deployment-context flip that started the project.

**Learning / takeaway.** Establishes that the **safe architecture** (technique library +
sandboxed reproduction + benign = failed reproduction) works on **real, executable,
industry** targets — not just the mini-Cybench simulation.

**Confidence boost.** *Decisive for the safety story.* Cybench gives an Apache-licensed,
ICLR-Oral, flag-oracle result; CVE-Bench gives the first **real-CVE deployment-context
benign-positive** measurement — the exact thing no public static benchmark contains and
the project's original motivation.

---

## 4. Phased execution (with gates, so we don't over-invest before a result)

| Phase | Work | Exit gate |
|-------|------|-----------|
| **P0 — prep** (½ day) | Full OWASP checkout (`scripts/get_owasp.sh`); write `load_primevul()`; confirm Cybench Docker still green (`setup_cybench.py`); add a request-rate limiter (we hit 25 min/level). | All three substrates load; one smoke per harness passes. |
| **P1 — smokes** (1 day) | Set 1: 160-case balanced OWASP. Set 2: 200 PrimeVul pairs. Set 3: 5 Cybench tasks + benign variants. | Each harness produces sane metrics on real data; no harness bug. |
| **P2 — scale the cheap two** (2–3 days, backgrounded/sharded) | Set 1: full 2,740 ×3 arms ×seeds, per-CWE. Set 2: 1,000+ PrimeVul pairs with VD-S. | Set 1 vs ZeroFalse/CodeQL reported; Set 2 vs GPT-4 P-V/pair-wise reported, with CIs. |
| **P3 — the executable lift** (1 week) | Set 3: full Cybench 40 + benign variants; then the CVE-Bench/UIUC 10-CVE pilot (Docker eval server). | Grounded reproduction + benign false-claim numbers at scale; first real-CVE BP result. |

**Pre-registered success criteria (all suppression-guarded):** Set 1 — beat CodeQL FPR
and land in the ZeroFalse F1 band. Set 2 — pair-wise accuracy and P-V materially better
than GPT-4's baseline (or an honest, localized collapse). Set 3 — reproduction rate up,
benign false-claims ~0, anti-regression holds.

---

## 5. Risks & honesty guards

- **Rate-limiting** (observed: ~25 min/level on Together). → shard by CWE/task, run
  backgrounded, cache at temp-0, add a limiter. Quote wall-clock honestly.
- **License hygiene:** OWASP GPL-2.0, PrimeVul MIT, Cybench/CVE-Bench Apache-2.0 are
  fine to run; **IRIS/CWE-Bench-Java is CC BY-NC-ND** (non-commercial, no-derivatives) —
  use for comparison only, don't redistribute derived data. NYU CTF is GPL-2.0.
- **Label caveats:** Juliet's synthetic FP rate ≠ natural FP rate; D2A labels are noisy;
  use PrimeVul/OWASP as the *trustworthy* anchors and treat the rest as context.
- **Don't cherry-pick:** report per-CWE and per-category, full confusion matrices, and
  the matched-pairs gain with CIs. A collapse on PrimeVul is a *finding*, not a failure
  to hide (cf. E7/E12/E14 — every honest negative sharpened the thesis).
- **Cross-model:** headline on DeepSeek-V4-Pro; spot-check one weaker/cheaper model to
  test the transfer claim and report cost-per-finding at scale.

---

## 6. The confidence ladder — what each set lets us claim

| After… | We can credibly say… | Strength |
|--------|----------------------|----------|
| today (E1–E15) | "The mechanism works and its failure modes are charted — on synthetic + mini-benchmarks." | PoC |
| **Set 1** | "Context-driven FP reduction is competitive with 2025 SOTA (ZeroFalse) and beats CodeQL, at the field-standard 2,740-case scale." | Industry-comparable |
| **Set 2** | "It holds on **real-world** code with **trustworthy** labels — where models that train on noisy data collapse." *(or a precise, honest map of where it doesn't)* | Credibility-defining |
| **Set 3** | "The safe architecture (technique library + sandboxed reproduction; benign = failed reproduction) works on **real, executable** targets, and we have the first **real-CVE deployment-context benign-positive** measurement." | Decisive for safety + the original thesis |

**Net:** three sets move us from *"promising synthetic PoC"* to *"validated against the
three benchmarks the field actually respects, with numbers placed next to named SOTA."*
That is the confidence boost the goal asks for — and Set 2 (PrimeVul) is the one that
matters most, because it's where the claim is most likely to break.

---

## Sources (verified this pass)
- **OWASP Benchmark:** github.com/OWASP-Benchmark/BenchmarkJava · owasp.org/www-project-benchmark · expectedresults-1.2.csv
- **ZeroFalse / OpenVuln:** arXiv 2510.02534 · **PrimeVul:** arXiv 2403.18624 · github.com/DLVulDet/PrimeVul (ICSE'25)
- **IRIS / CWE-Bench-Java:** arXiv 2405.17238 · github.com/iris-sast/iris (ICLR'25) · **D2A:** arXiv 2102.07995 · github.com/IBM/D2A (ICSE'21)
- **CleanVul** 2411.17274 · **SecVulEval** 2505.19828 · **VulDetectBench** 2406.07595 · **DiverseVul** RAID'23
- **Cybench:** arXiv 2408.08926 · cybench.github.io (ICLR'25 Oral) · **CVE-Bench/UIUC:** arXiv 2503.17332 · github.com/uiuc-kang-lab/cve-bench (ICML'25)
- **NYU CTF Bench:** arXiv 2406.05590 (NeurIPS'24 D&B) · **AutoPenBench:** arXiv 2410.03225 · github.com/lucagioacchini/auto-pen-bench
