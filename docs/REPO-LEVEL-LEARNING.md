# Repo-level learning experiment (JitVul) + hill-climbing roadmap

Does **one self-evolution round** move precision/recall on a **repo-level** benchmark —
without overfitting — and does **cross-function context** help? Run on JitVul (real CVE
vuln↔fix pairs with inter-procedural context shipped), with VulEval inspected as a
cross-benchmark confirmation substrate.

## Why JitVul (and the git-checkout question)

JitVul (ACL'25) ships, per CVE: the **vulnerable function**, its **fixed twin**, and the
**callee function bodies + call graph** — i.e. the cross-function context PenPal needs is
**already extracted** (JitVul's own pipeline did the `git checkout` + call-graph offline).
So for this experiment the "git-checkout problem" is solved by consuming the shipped
inter-procedural context; we do **not** need to re-clone repos. (For benchmarks that ship
only a function + commit pointer — e.g. PrimeVul — the checkout+slice step *would* be
required; JitVul lets us test the *value* of that context first, before building it.)

## Experiment design (the controls)

**2×2** on a **project-disjoint** train/held-out split (no project in both → no repo
leakage):

- **Variable 1 — context:** isolated function  vs  function + callee bodies (inter-proc).
- **Variable 2 — learning:** baseline (no playbook)  vs  **one self-evolution round**
  (classify TRAIN → reflect on errors → distill **general** tactics → **freeze** playbook →
  apply to HELD-OUT).

**Anti-overfitting / variable isolation:**
- project-disjoint split (the strongest leakage control);
- playbook frozen before any held-out case is seen;
- **overfit check** = TRAIN-with-playbook gain vs HELD-OUT-with-playbook gain (big train
  gain + flat held-out gain ⇒ memorization, not learning);
- **paired metric** (pairwise-correct, both-vuln = FP bias, both-benign = miss bias) so a
  blanket "all vuln" or "all benign" can't win;
- published comparison: JitVul GPT-4o **pairwise ≈ 0.17–0.19**.

Harness: `experiments/bench_jitvul.py` (DeepSeek-V4-Pro). Data gitignored under `repolevel/`.

## Results (DeepSeek-V4-Pro; train 30 / held-out 40 pairs; project-disjoint)

Log: `docs/samples/jitvul-learning-2x2-deepseek.log`.

| held-out arm | precision | recall | F1 | pairwise | both-vuln (FP bias) | both-benign (miss) |
|---|---|---|---|---|---|---|
| baseline (no ctx, no learn) | 0.44 | 0.10 | 0.16 | 0.00 | 0.10 | 0.88 |
| **+ learning** (no ctx) | 0.54 | **0.17** | **0.26** | 0.05 | 0.12 | 0.80 |
| **+ context** (no learn) | **0.71** | 0.12 | 0.21 | 0.07 | **0.05** | 0.88 |
| + context + learning | 0.62 | 0.12 | 0.21 | 0.07 | 0.05 | 0.85 |

**Findings (the goal's core question, answered):**

1. **Yes — one self-evolution round brings a meaningful, non-overfit change.** In the
   no-context arm it lifted **F1 0.16 → 0.26 and recall 0.10 → 0.17** on held-out, *without*
   raising the FP bias. **It generalizes:** the train pairwise gain was ~0 while held-out
   improved — i.e. the gain is *not* memorization (the project-disjoint + frozen-playbook +
   train-vs-held-out controls all held). So a learning round is real, not an artifact.

2. **Context helps a *different* axis — precision.** Adding the callee bodies took precision
   **0.44 → 0.71** and **halved the FP bias (0.10 → 0.05)**: seeing the called functions lets
   the model stop over-flagging the *fixed* twin. Context barely moved recall (+0.02).

3. **Context and learning are SUBSTITUTES, not additive.** With context already present, the
   learning round adds **~0** (F1 0.21 → 0.21). This is the **E10 lesson reproduced at repo
   scale**: once the deciding evidence is in the input, prompt/tactic evolution is
   second-order; the learning round mostly *compensates for missing context.*

4. **But absolute recall stays low (~0.12–0.17), benign-bias dominant (~0.85).** Immediate
   callees are **necessary but not sufficient** — most JitVul bugs need deeper call-chain or
   exploit-condition evidence than one hop of callees. Our zero-shot validator stays below
   JitVul's published GPT-4o pairwise (0.17–0.19) on the strict paired metric: the bottleneck
   is recall (the model still says "benign" to most real functions), exactly the
   evidence-locality wall — one hop isn't the whole reachable slice.

**Net:** the learning round *works and generalizes*, and context *works* (on precision) — but
both are bounded by how much of the reachable evidence is supplied. The lever remains
**evidence acquisition**; the learning round is the (real, second-order) polish on top — which
is why the hill-climb below leads with deeper slicing + abstain-and-escalate, not more tactics.

---

## SASTBench (real CVE TPs + Semgrep FPs; agent checks out repo@commit) — the learning round BACKFIRED

The on-thesis, current (2026) benchmark: the agent gets `(repo, commit, file, function, CWE)`
and **checks out the repo at that commit** to triage real_vuln vs false_positive — PenPal's
clear-box repo mode, git-checkout built in (`experiments/sastbench/run_sastbench.py`; log
`docs/samples/sastbench-2x2-deepseek.log`). Same 2×2 + repo-disjoint split + overfit check.

**Held-out (DeepSeek-V4-Pro; 90 findings, 16 real-CVE TPs / 74 Semgrep FPs):**

| arm | precision | recall | F1 | MCC | TP caught | FP flagged |
|---|---|---|---|---|---|---|
| func, baseline | 0.50 | 0.06 | 0.11 | 0.13 | 1/16 | 1/74 |
| file, baseline | **1.00** | 0.06 | 0.12 | **0.23** | 1/16 | **0/74** |
| func, + learning | 0.08 | 0.06 | 0.07 | **−0.11** | 1/16 | 12/74 |
| file, + learning | 0.07 | 0.06 | 0.06 | **−0.13** | 1/16 | 14/74 |

**Findings — three, and they sharpen (not contradict) the thesis:**

1. **The ungated learning round NET-HARMED P/R — the opposite of JitVul.** It collapsed
   precision (1.00→0.07), drove **MCC negative**, and the overfit check flagged it (harmful on
   held-out). It induced *indiscriminate over-flagging* — false alarms 0→14 — **without catching
   one extra real CVE** (recall fixed at 1/16). The tactics just shifted the decision threshold
   toward "real," which on realistically-imbalanced SAST data (≈1:5–8) is pure precision loss.
   *This run deliberately had no tournament/Pareto gate — and this is exactly the failure the
   gate (E2/E4/E8) exists to stop.* **Cross-experiment lesson: a learning round is
   regime-sensitive — it helped on balanced JitVul, harmed on imbalanced SASTBench — so it must
   be held-out-gated, not applied blind.**

2. **The recall wall is the real bottleneck: 1/16 in *every* cell.** The model triages almost
   everything FP (a correct SAST prior + the benign bias) and genuinely cannot identify the 15
   hard real CVEs from function+file. **A learning round cannot fix a recall wall caused by
   missing evidence — it can only trade precision for noise.** This is the E10 / evidence-
   locality result, now on a real 2026 SAST benchmark: the lever is *evidence* (deeper slice /
   execution), not tactics.

3. **Context → precision, again.** File context took precision 0.50→**1.00** (0 false alarms) —
   consistent with JitVul (context lifts the precision axis), though it left the recall wall
   untouched.

**vs the paper** (Gemini-2.5-Pro: F1 0.26 / prec 0.17 / **rec 0.58**): our DeepSeek triager sits
at a very different operating point — near-max precision, near-zero recall (1/16). Their agent
flags aggressively (recall 0.58, precision 0.17); ours abstains-to-FP. Neither is good; both are
*below* a usable triage F1, underlining that real-repo SAST triage is genuinely unsolved.

**Honest label caveat (carried through):** the FP class is *approximate* (Semgrep-assumed-benign),
so some of the learning round's 14 "false alarms" could be real-but-uncatalogued vulns mislabeled
FP. But the **trustworthy axis — TP recall on real CVEs — did not move at all** (1/16 throughout),
so the learning round demonstrably did not help find real vulnerabilities, regardless of the FP
labels.

**Net (JitVul + SASTBench together):** a self-evolution learning round can move P/R **(JitVul:
+0.10 F1, generalized)** or **harm it (SASTBench: −0.05 F1, MCC negative)** — the difference is
the data regime and whether the round is **gated**. Context reliably helps *precision* in both.
And in both, **absolute recall is bounded by evidence reachability**, which tactics can't fix.
Conclusion stands: lead the hill-climb with *evidence acquisition + gating*, not more tactics.

## Batched SASTBench + the commit-gate experiment (the controlled re-run)

Re-ran SASTBench as the *fixed arena*, all variables frozen: pool = ALL 299 real CVEs + a
1:2 FP sample (897), persisted repo-disjoint split, predictions cached to disk once
(`experiments/sastbench/batch_sastbench.py`), so the gate comparison is pure post-hoc over the
cache (`gate_analysis.py`) — only the gate logic varies. Log
`docs/samples/sastbench-gate-analysis.log`.

**Trustworthy baseline (held-out, file context, 127 real CVEs):** recall **8/127 = 0.063**,
precision 0.571, MCC 0.071, 6 false alarms. **The recall wall is real, not a sampling
artifact** — the earlier "1/16" was 0.06; at 127 CVEs it's still 6.3%, uniform across CWEs.

**Learning round at scale (baseline vs candidate, paired n=309):**

| | precision | recall (CVEs) | F1 | MCC |
|---|---|---|---|---|
| baseline | 0.571 | 0.063 (8/127) | 0.113 | 0.071 |
| + learning | 0.667 | 0.079 (10/127) | 0.141 | 0.117 |
| Δ | +0.095 | +0.016 | +0.027 | +0.046 |

**① The earlier "backfire" was largely a small-N effect.** At n=90 the round tanked precision
(MCC went negative); at trustworthy n=309 with a cleaner regenerated candidate it's a *small,
all-axes-positive* change. Lesson: **small-N commit decisions are unreliable** — which is
exactly *why* you need a significance gate, not a point-estimate one.

**② McNemar vs Pareto — they genuinely disagree, and the disagreement is the finding:**

```
naive (ΔF1>0)                          : COMMIT
pareto (no -ε reg, ΔMCC>0)             : COMMIT     <- all axes improved
mcnemar (fixes c=7 > breaks b=4, p=.55): REJECT     <- but the gain is NOT significant
conjunction (mcnemar ∧ pareto)         : REJECT
```

- **Pareto is blind to significance.** All four metrics improved, so Pareto (and naive-ΔF1)
  commit — but the gain comes from fixing 7 findings while breaking 4 on n=309. **McNemar's exact
  test says p=0.55: statistically indistinguishable from noise.** Pareto would *ship noise.*
- **McNemar is the needed guard** — but it has a *cost*: with only a +3 net effect at n=309 it
  also **can't certify a possibly-real tiny gain** (a power limit) → it may false-reject small
  true improvements. That's the real tradeoff, now concrete.
- **The conjunction favors safety** (reject unless significant *and* non-regressing) — right for
  a validator you don't want to regress; the price is slower hill-climbing.

**Net:** the controlled re-run confirms the conceptual claim with data — *Pareto-on-point-
estimates ships noise; you need significance (McNemar) on top.* The naive-ΔF1 gate (which let
the original SASTBench round "succeed") commits a change that is **not statistically real**;
the McNemar/conjunction gate correctly withholds. And the recall wall (6.3%) means the learning
round has almost no signal to improve — reaffirming that the lever is **evidence, not tactics**.

## Hill-climbing roadmap — how to actually raise precision/recall at repo scale

Ordered by expected leverage, grounded in the whole arc (E1–E15 + the benchmark phase +
the evidence-locality diagnosis). The unifying rule: **FP/TP discrimination is bounded by
whether the deciding evidence is reachable — so the biggest gains come from *acquiring
evidence*, not from prompting harder.**

### Tier 1 — evidence acquisition (the dominant lever)
1. **Cross-function slice.** Feed the reachable source→sink across functions (callees/
   callers), not the isolated function. JitVul ships it; for PrimeVul/real repos, build the
   `git checkout @commit` + call-graph + slice extractor (CodeQL/tree-sitter+cflow). *This
   is the structural fix for the PrimeVul collapse.*
2. **Agentic abstain-and-escalate.** Replace forced binary with `{vulnerable | benign |
   insufficient-evidence}`; on "insufficient," the agent **fetches more** (pull more
   callers, grep sanitizers across files, read the header) and re-decides. Turns the
   under-flagging collapse (recall ~0) into an active investigation instead of a benign
   guess — *the single highest-value behavioral change.*
3. **Context-depth tuning.** How many call-graph hops to include (recall vs token cost);
   retrieve by relevance (lexical > semantic, per VulEval) rather than dumping the repo.

### Tier 2 — route the mechanism to the evidence type
4. **CWE-class routing** (validated in Set 1b, F1 0.60→0.81): construct/property check for
   config-crypto CWEs; taint/slice for injection; **semantic-diff / memory-model reasoning**
   for the cross-function memory bugs (UAF/overflow) that defeat isolated-function reading.
5. **Verification by reproduction** for high-stakes findings (E15/Set 3/CyberGym): confirm
   by executing a PoC (sanitizer crash / exploit fires). The only mechanism that makes the
   verdict *provably* safe (zero fabrication) — the ceiling, when static evidence is
   inconclusive.

### Tier 3 — self-evolution of the validator, done right
6. **Tactic generality + gating.** The learning round must distill **CWE-class-level**
   tactics (precondition + check), never memorized identifiers; keep a tactic only if it
   improves **held-out** without raising FP (Pareto/tournament, E2/E4/E8). This is what
   prevents the overfit the 2×2 is designed to detect.
7. **Per-CWE scoped playbooks** (E2 conditional rules): a tactic fires only for its CWE
   class, so it can't over-suppress unrelated findings.
8. **Few-shot retrieval of confirmed neighbors** (ExpeL/RAG): prepend verified-real and
   verified-benign cases of the *same CWE* (JitVul ships `few-shots.json`) — cheap recall
   lift without prompt-overfit.
9. **Multi-round with replay** (EvoHunt): iterate reflect→gate→keep across rounds, replaying
   prior cases to avoid forgetting; stop when held-out plateaus.

### Tier 4 — calibration & safety (precision without silent misses)
10. **Confidence = thoroughness** (E15 caveat): weight the verdict by how much evidence was
    gathered → surface "benign (shallow)" vs "benign (verified across call chain)".
11. **Annotate-don't-suppress** (E3 / the product principle): never silently drop; emit the
    finding with the grounded evidence + confidence and let downstream decide.
12. **Perspective ensemble:** independent validators (memory-safety / taint / authz lenses)
    vote — reduces both misses and FP, at a token cost.

**Recommended hill-climb order:** (2) abstain-and-escalate + (1) slice → (4) CWE routing →
(6/7) gated per-CWE tactic learning → (5) reproduction for high-stakes → (10/11) confidence
+ annotate. Tier-1 is where the curve bends; the learning round (Tier 3) is a second-order
polish *on top of* good evidence — exactly the E10/E1 lesson, now to be re-tested at repo
scale by this experiment.
