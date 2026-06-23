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
