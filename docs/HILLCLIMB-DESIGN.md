# Verifier hill-climb — a system of loops for self-evolving vuln validation

How we turn **every round of inference into evaluation data on the verifier's behavior**, and
use that data to **gradually hill-climb** — on SASTBench as the training ground for the *method*.
Synthesis of: the PoC-as-oracle inference design (`INFERENCE-DESIGN.md`), the commit-gate result
(`REPO-LEVEL-LEARNING.md`), the Replit layered-eval lessons, and an EvoHunt recheck.

## 0. What we're optimizing for (state it always)

**True objective:** the verifier's ability to **produce/justify the unwanted OUTCOME** of a real
vulnerability (a PoC). Not triage-accuracy, not raw recall.

**Proxy objective on SASTBench (the training ground):** *not* the 6.3% recall wall — chase the
**qualification axis** (EvoHunt §8.3.1, which we reproduced in E9: *verification improves while
raw solve-rate barely moves*):

> maximize **grounded confirmations** (real vulns CONFIRMED via a produced/justified outcome),
> drive **fabricated confirmations → 0**, and route everything else to **UNCONFIRMED → escalate**
> (never silently "benign").

SASTBench is a *small training ground to refine the METHOD* (takeaway #4). The artifact we ship is
the **refined verifier+harness system**, transferable to PenPal — the SASTBench number is just the
signal we climb.

## 1. The system of loops

```
 OBJECTIVE  (climb this) :  grounded-confirmation quality
   ▲          = real vulns CONFIRMED-with-outcome ↑ , fabrications → 0 , rest → UNCONFIRMED
   │            [EvoHunt §8.3.1: optimize VERIFY/qualify, not raw solve-rate]
   │
 ┌─┴────────────────────────────────────────────────────────────────────────────────┐
 │ L0 — INNER  (per finding, ONE inference round)                                      │
 │   finding ─▶ observe ─▶ gather evidence (iterative, severity-budgeted)             │
 │                           fetch cross-fn slice / probe / attempt exploit            │
 │                                   │                                                 │
 │                                   ▼  attempt to PRODUCE THE OUTCOME                  │
 │              ┌─────────────────── TRACE = {evidence fetched, techniques tried,      │
 │              │                             milestone/tier reached, stop-reason,      │
 │              │                             verdict, confidence}                      │
 │       evidence-tier verdict (EvoHunt):                                              │
 │         T1 outcome produced       → CONFIRMED-REAL                                   │
 │         T2 triggered / partial    → UNCONFIRMED-high  (escalate)                     │
 │         T3 claim-no-proof / none  → UNCONFIRMED-low / benign-lean                    │
 └──────────────┬─────────────────────────────────────────────────────────────────────┘
                │  the TRACE *is* the evaluation datum (not just the verdict)
                ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ L1 — EVALUATE + ATTRIBUTE  (per batch)   ── grounded oracle: SASTBench label / PoC ─│
 │   grade verdicts → confusion + failure taxonomy                                     │
 │   then ATTRIBUTE every miss *from its trace* — the ROUTER (takeaway #3):            │
 │     ├─ HARNESS error  (checkout/slice/tool/parse failed)      ─▶ fix the HARNESS     │
 │     ├─ MODEL error    (had the evidence; misjudged / gave up                          │
 │     │                  too early / fabricated)                ─▶ evolve PROMPT/tactics│
 │     └─ HARD           (evidence not reachable in budget)      ─▶ deepen EVIDENCE policy│
 │   FALSE NEGATIVES (real CVE called FP) = the richest signal (takeaway #2):           │
 │     for each, recover *what was missing* → which bucket above → a gradual change      │
 └──────────────┬─────────────────────────────────────────────────────────────────────┘
                │  attributed, diagnosed failures (cached, deterministic)
                ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ L2 — SELF-EVOLVE  (across batches)                                                  │
 │   reviser proposes ONE gradual change targeted at the DOMINANT attributed cause     │
 │   (harness patch | new technique | prompt edit | evidence-depth bump)               │
 │                                   │                                                 │
 │   COMMIT GATE (layered):  McNemar-significant ∧ Pareto-no-regression ∧ beats-champion│
 │     scored on a GROUNDED oracle; on a held-out disjoint split                        │
 │                                   │ commit                                          │
 │                                   ▼  + add a regression test (Replit)               │
 │                            updated verifier ───────────────────────────▶ ↻          │
 └──────────────────────────────────────────────────────────────────────────────────┘
```

## 2. The four ideas that make it work (your takeaways, operationalized)

1. **Always name the objective** → the verifier's PoC/outcome capability; on SASTBench, the
   *qualification* axis (grounded-confirm + correct-abstain), not the recall wall.
2. **Mine false negatives** → every real CVE we called FP is a logged trace; recover *what was
   missing* (no slice? wrong technique? gave up?) and feed a **gradual** change — not a rewrite.
3. **Attribute before you fix (harness vs model vs hard)** → the eval system's job isn't just a
   score, it's a **router**. You cannot prompt-evolve away a checkout bug, and you cannot patch a
   model-reasoning gap with a harness fix. *Attribution is the new, load-bearing piece.*
4. **SASTBench = method training ground** → we're tuning the *system* (how to trace, attribute,
   propose, gate). The deliverable transfers to PenPal; the benchmark score is the gradient.

## 3. EvoHunt recheck — what to experiment on (takeaway #5)

| EvoHunt mechanism | What to adopt/experiment |
|---|---|
| **§8.3.1: qualification improves while solve-rate barely moves** | **The core reframe.** Set the SASTBench objective to the *verification* axis, not recall — measure "of what it confirms, how many are grounded" + "does it correctly UNCONFIRMED the rest." We already saw this (E9); make it the explicit hill we climb. |
| **Evidence tiering (T1/T2/T3)** | Adopt as the **per-round grade** (richer than binary TP/FP) — it feeds the confidence, the stopping rule, *and* L1's attribution. |
| **Unconstrained incremental reviser edits** (add/remove workflows, heuristics, knowledge) | The L2 proposer — but **gated** (their branch-tournament = our McNemar∧Pareto∧champion). |
| **Transfer to weak models** (Qwen 2.4%→6.5%) | A later experiment: once the system is refined on a strong model, test whether the evolved playbook/harness lifts a cheap model — the deployment-cost axis. |

## 4. What's built vs what to build

**Built (the eval + gate substrate):** `batch_sastbench.py` (cached, resumable predictions over
all 299 CVEs on a fixed repo-disjoint split) + `gate_analysis.py` (post-hoc McNemar/Pareto/
conjunction). The commit gate (L2) and the grounded-oracle plumbing exist.

**To build (the behavior-evaluation engine — the heart of this design):**
1. **Trace emission (L0):** the verifier must log {evidence fetched, techniques tried, evidence
   tier, stop-reason}, not just the verdict. (Today it emits only TP/FP.)
2. **The attribution router (L1):** a classifier over traces → {harness | model | hard}. Start
   rule-based (checkout/parse failure = harness; verdict-flip-with-full-evidence = model;
   frontier-exhausted = hard), then LLM-assisted.
3. **False-negative miner (L1):** for each real-CVE-called-FP, recover the missing evidence and
   bucket it — this directly attacks the 6.3% wall by telling us *why* each was missed.
4. **Iterative evidence-gathering (L0):** the deeper cross-function slice + abstain-and-escalate
   (the lever the recall wall says we need; tactics can't substitute).

## 4b. First run — attribution of the recall wall (and the scaling decision)

Built L0+L1 (`experiments/sastbench/attribute.py`) and ran it on the **119 held-out false
negatives** (real CVEs the baseline triaged as FP). Re-ran each with a trace-emitting,
evidence-reasoning prompt → recovery + attribution. Log `docs/samples/sastbench-attribution.log`.

```
ATTRIBUTION of the recall wall (n=119 missed real CVEs):
  recovered            18  (15%)   a better reasoning prompt ALONE flips FP→TP
  hard-needs-evidence  57  (48%)   deciding evidence not in func+file
  model-misjudge       44  (37%)   claims decisive evidence, still wrong
  harness               0  ( 0%)   plumbing is clean
  of the 57 hard, what's missing: CALLERS 50 · callees 5 · runtime 1
  evidence tiers overall: partial 70 · saw_decisive 47 · guessing 2
```

**Is this a good direction? Yes — decisively.** The attribution is clean (0% harness noise) and
*actionable*, and it turns "the recall wall is 6.3%" into three concrete, differently-fixable
causes:

1. **15% is a free prompt win.** The original triage prompt left recall on the table; *forcing
   evidence-reasoning* recovers ~1 in 7 missed CVEs with no new infra. (Gate it for precision
   first — see below.)
2. **48% need more evidence — and the data says specifically CALLERS** (50 of 57). The model
   knows what it's missing: *who calls this function and with what input* (the up-direction
   taint source), which func+file doesn't contain. This sharpens the vague "deeper slice" into a
   precise build: **fetch the call sites.**
3. **37% are confident misjudgments** (saw_decisive_evidence, still wrong). Tactics rarely talk a
   model out of a confident wrong call → these are where the **execution/PoC oracle** earns its
   keep (settle it by trying to produce the outcome, not by re-reasoning).

**How we scale across SASTBench (the decision):**
- **The attribution router becomes the dispatcher.** It's cheap (~119 calls, 0% harness) and runs
  over the full set to give the population breakdown + per-CWE routing. At scale it sends each
  finding to the cheapest sufficient evidence level — a **two-tier escalation**: trace-prompt →
  **+caller-slice** → **execute/PoC**.
- **Build order, now data-driven:** (1) promote the trace/reasoning prompt to baseline (free 15%,
  *gated*); (2) **caller-context slicing** — the single highest-leverage evidence build, precisely
  targeted at the 48% (callers, not callees); (3) the execution/PoC oracle for the 37%
  confident-misjudge. Each is validated through the commit gate before it ships.
- **Honest caveats:** the 15%/48% are partly the model's *self-report* (it flipped, or it says it
  needs callers) — the real test is: does *providing callers* actually flip the hard bucket?
  (next experiment). And the "recovered 18" must be **gated for precision** — a reasoning prompt
  that flags more could also over-flag FPs; run it as a candidate through `gate_analysis` before
  adopting.

## 5. The one-line thesis of this design

> A self-evolving verifier is only as good as its **evaluation system**. Make each inference round
> emit a trace, grade it on a **grounded outcome oracle**, **attribute** the failure (harness vs
> model vs hard), and let a **gated** reviser make one targeted gradual change per round —
> climbing the **qualification** axis (confirm-what-you-can-prove, escalate the rest), not the
> recall wall. SASTBench is where we tune that machine; PenPal is where we run it.
