# The missing parts of inference: the commit gate, evidence-gathering, and PoC-as-oracle

Three questions, one answer. The unifying claim — **a finding is verified iff a controlled
attempt produces the unwanted OUTCOME (the PoC)** — is simultaneously (a) the inner loop's
terminal condition, (b) the grounded oracle that makes the outer-loop commit gate valid, and
(c) the goal that gives evidence-gathering a stopping structure. Every failure we measured
(SASTBench's approximate labels poisoning the learning round, the 1/16 recall wall, the
ungated commit) is downstream of *not having a grounded outcome oracle*.

Definition we build on: **Risk = an attacker EXPLOITING a weakness to cause an unwanted
OUTCOME.** So "real vulnerability" ≡ "the unwanted outcome is achievable." That makes the
outcome — not a label, not an opinion — the thing to verify.

---

## Q3 first (it grounds the other two): is "produce the outcome = verified" correct?

**Yes — with one critical asymmetry.**

- **PoC succeeds ⇒ definitively REAL.** Producing the outcome (flag captured, sanitizer
  crash, data exfiltrated, auth bypassed, `/tmp/pwned` written) is *unfakeable* — the agent
  cannot argue its way to it. This is the strongest oracle there is (Cybench/CyberGym/CVE-Bench
  all rely on exactly this), and it's what made our E15/Set-3 "benign is safe" result hold:
  zero self-deception, because you can't fake a fired exploit.
- **PoC fails ⇏ benign.** Absence of a PoC is not proof of safety — it may be unexploitable,
  *or* just hard to exploit in the budget you spent. So the honest verdict space is **three
  states, not two**:

  | verdict | basis | trust |
  |---|---|---|
  | **CONFIRMED-REAL** | a PoC produced the outcome | unfakeable |
  | **GROUNDED-BENIGN** | a *proof* the outcome can't occur (complete sanitizer on the only path; sink unreachable; control validated) | strong but rare — proving a negative is hard |
  | **UNCONFIRMED** | budget/frontier exhausted, no PoC, no proof | low — *escalate, do not suppress* |

**Why this is exactly right for OUR problem (false-positive reduction):** the whole project
is about findings flagged "real" that aren't actually exploitable. PoC-as-oracle says **only
promote to CONFIRMED-REAL what you can reproduce** — so the confirmed bucket has *zero false
positives by construction*. Everything else is UNCONFIRMED (not "real", not "benign"),
routed to a human or a deeper tier. That is annotate-don't-suppress (E3) with a grounded
spine, and it dissolves the SASTBench failure mode: we never *commit* a "real" we can't show.

**Three caveats that shape the architecture:**
1. **Cost.** PoCs are expensive and often fail (Cybench/CyberGym frontier ≈ 18–25%). You
   cannot PoC every finding → a **two-tier system**: cheap static triage *filters/ranks*,
   PoC-verification *confirms the survivors*. Triage's job is recall (don't drop a real one);
   PoC's job is precision (confirm, eliminate FPs).
2. **Sandbox/safety.** "Produce the outcome" must run in a **controlled replica** (staging
   clone / container), never production — for PenPal on client systems this is a hard
   constraint (it's the difference between a benchmark like CVE-Bench's eval server and a real
   engagement).
3. **The outcome must be DEFINED per finding.** "Unwanted outcome" is concrete and
   class-specific (RCE → command runs; SQLi → unauthorized row read; auth bypass → admin
   session; SSRF → outbound callback). Defining the outcome predicate *is* defining the
   oracle. CVE-Bench's 8 runtime checks are a working template.

---

## Q1: scientific criteria for the commit gate (when is a proposed change good to merge?)

The gate decides whether a proposed improvement (a new tactic, a prompt change, a tool) is a
**real, generalizing** improvement vs noise / overfit / Goodhart. A change merits commit iff
it passes **all** of the following — measured against a **grounded oracle** (Q3) on a
**held-out split disjoint** from where it was learned:

1. **Generalization, not memorization.** Improvement must hold on a held-out set that is
   *repo/project/time-disjoint* from the train set. (We have this; it's why JitVul's gain was
   credible and the train-vs-held gap is the overfit check.)

2. **Significant, not noise — use McNemar's test.** This is the *correct* test for two
   classifiers on the *same* held-out items (paired binary outcomes). Build the disagreement
   counts on held-out: `b` = #(baseline right, candidate wrong), `c` = #(baseline wrong,
   candidate right). Commit only if **`c > b` significantly** (exact binomial on `b,c` when
   `b+c` is small; χ² otherwise), p < 0.05. McNemar asks precisely "does the change fix more
   than it breaks, beyond chance?" — exactly the merge question. (Equivalently: bootstrap CI
   on Δmetric excludes 0.)

3. **No regression on any protected axis (Pareto / asymmetric guard).** Overall significance
   can hide a tanked sub-metric. Require **Δrecall ≥ −ε AND Δprecision ≥ −ε** (ε small, e.g.
   0.02), and on imbalanced data require **ΔMCC > δ > 0** as the headline (MCC is
   imbalance-robust; F1/accuracy are not). *This single rule rejects the SASTBench backfire:
   it drove MCC +0.23 → −0.13 and precision 1.00 → 0.07 — instant reject.*

4. **Holds across subgroups (no Goodhart on one easy class).** The gain must not come from
   exploiting a single CWE/repo. Require the improvement be non-negative across the major CWE
   subgroups (or at least not significantly negative on any). Prevents a tactic that games one
   class while quietly hurting others.

5. **Beats the current CHAMPION, not just the original baseline (tournament).** Compare the
   candidate to the best playbook so far, not to scratch — and require it to survive ≥1 replay
   of historical cases (anti-forgetting). This is the EvoHunt branch-tournament (validated in
   E8: 2 of 3 rounds were correctly rejected).

6. **Cost-bounded (parsimony / anti-context-collapse).** Reject changes whose token/latency
   cost outweighs the gain, and don't let the playbook grow unboundedly (ACE: incremental
   edits, not rewrites). Gate on *cost-adjusted* gain.

7. **Oracle integrity (the meta-criterion).** All of the above are only valid if the metric is
   computed against a **grounded, untouchable** oracle. On SASTBench the FP labels are
   *approximate* (Semgrep-assumed) → the gate would be optimizing toward noise even if 1–6
   pass. **This is why Q3 matters: a PoC-grounded oracle makes the gate scientifically sound;
   an approximate-label oracle makes any gate suspect.**

**The merge rule, in one line:**
> Commit iff, on a disjoint held-out set scored by a grounded oracle, the candidate beats the
> current champion with a **McNemar-significant** gain in the **imbalance-robust** metric,
> **no ε-regression** on recall/precision, **non-negative across CWE subgroups**, within a
> **cost budget** — else reject and keep the champion.

---

## Q2: evidence-gathering — when to keep going vs give up (toward a PoC)?

The inner loop is a **bounded search whose goal is to produce the outcome.** Frame it as
optimal stopping under a value-of-information (VoI) budget. Three terminal states (= Q3's
verdicts), and a stopping rule for the hard middle:

**Terminal states (stop immediately):**
- **SUCCESS:** the outcome is produced → CONFIRMED-REAL. (the goal)
- **PROVED-SAFE:** a complete, sound reason the outcome cannot occur on any reachable path →
  GROUNDED-BENIGN. (rare)

**The stopping rule for "keep going vs give up" (when neither terminal has fired):**

Keep going while the *next action is expected to be informative or to open a path*; give up
when the **reachable evidence/exploit frontier is exhausted AND progress has plateaued**,
bounded by a **severity-scaled hard budget**:

1. **Frontier check** — is there an unexplored, *reachable* next step? (an un-fetched
   callee/caller on the taint path; an un-tried input class; an un-bypassed check). If the
   frontier is empty, you've gathered all locally-reachable evidence → stop.
2. **Progress / milestone check** — define exploitation milestones (reached the sink,
   controlled the tainted value, bypassed the guard, partial effect). Keep going while a new
   milestone is being hit within the last *k* steps; **give up after *k* steps with no new
   milestone** (the search has stalled). Milestones give a denser signal than the binary
   PoC and are what AutoPenBench/AISI ranges score on.
3. **VoI vs cost** — continue only while *expected reduction in decision-risk × impact > cost
   of the next probe*. The decision-risk is high when the agent is uncertain AND the finding is
   severe → **scale the budget by severity (CVSS):** spend many steps chasing a potential RCE,
   few on a low-impact info leak. Stop when the cheapest informative next action costs more
   than the decision is worth.
4. **Hard cap** — an absolute ceiling (steps/tokens/wall-time), scaled by severity, as the
   backstop (Cybench-style iteration cap).

When you give up under (1)–(4): return **UNCONFIRMED** — *never* "benign". UNCONFIRMED carries
a **confidence = thoroughness** (how much of the frontier was explored, how many milestones
hit) — the E15 calibration — and routes to a human or a heavier tier. **This is the fix for
the recall wall:** instead of defaulting to benign (SASTBench recall 1/16), the agent says
"reached the sink, controlled input, couldn't bypass the validator in budget — UNCONFIRMED,
0.6 confidence" → escalate, don't suppress.

**Inner-loop decision rule, in one line:**
> Pursue the outcome; stop on SUCCESS (→real) or a soundness PROOF (→benign); otherwise keep
> fetching evidence / attempting while the reachable frontier is non-empty and a new milestone
> fires within *k* steps and VoI > cost — capped by a severity-scaled budget; on give-up emit
> UNCONFIRMED with confidence = how far you got, and escalate.

---

## Synthesis — how this completes the loop (audit against the wire diagram)

```
INNER (per finding): observe ──▶ attempt to PRODUCE THE OUTCOME (iterative: fetch evidence,
                                  try exploit, hit milestones)
                                   │
                    ┌──────────────┼───────────────┐
                 SUCCESS        PROOF-SAFE      GIVE-UP (frontier∅ / no-progress / budget)
                    │               │               │
              CONFIRMED-REAL   GROUNDED-BENIGN   UNCONFIRMED (conf=thoroughness) → human/deeper tier
                    └──────────────┬───────────────┘
                                   ▼   GROUNDED ORACLE (outcome produced or not — unfakeable)
OUTER (evolution):  observe → EVALUATE vs grounded oracle → PROPOSE tactic → VERIFY on
                    disjoint held-out → COMMIT iff [McNemar-sig ΔMCC, no ε-regression,
                    subgroup-safe, beats champion, in budget] → ↻
```

- **Q3 supplies the oracle** that both the inner verdict and the outer EVALUATE depend on.
- **Q1 is the COMMIT gate**, now valid because EVALUATE is grounded.
- **Q2 is the inner-loop controller** that turns the recall wall ("benign by default") into
  "UNCONFIRMED → escalate", and produces the CONFIRMED-REAL labels that feed a trustworthy
  outer loop.

**What this says we got wrong before, precisely:** SASTBench failed on all three — an
*approximate* oracle (Q3 violated), an *ungated* commit (Q1 absent), and a *one-shot,
benign-defaulting* observe (Q2 absent). Fixing them is not three projects; it's installing the
**outcome oracle** and letting the gate and the stopping rule hang off it.

**Build order:** (1) define per-CWE outcome predicates + a sandbox to run them (the oracle);
(2) wire the McNemar+Pareto commit gate (cheap, immediate — would have rejected SASTBench);
(3) make observe iterative with the milestone/frontier/severity stopping rule and the
UNCONFIRMED state. The two-tier framing (cheap triage → PoC-confirm) keeps the expensive
oracle affordable.
