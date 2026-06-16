# Self-Evolving Loupe — design notes

How a security-finding validator gets better over time **without fine-tuning**,
and how it stays safe while doing so. Grounded in a 2025–2026 literature pass
(citations at the end; treat the newest 26xx arXiv ids as title-verified only).

---

## 1. What "self-evolving" actually means here

Not "accumulate memory." The anchor taxonomy — *A Survey of Self-Evolving Agents*
(arXiv 2507.21046) — frames evolution as **what** evolves (model / memory / tools
/ prompts), **when** (intra- vs **inter-test-time**), and **how** (feedback-driven
updates). Loupe lives in one cell: **inter-test-time, memory-only, grounded by
verified outcomes.** No weights move.

Concretely, self-evolving for a validator is a **governed loop**:

```
  finding ─▶ retrieve lessons (scoped) ─▶ validate (re-ground, don't trust)
                                              │
                       verified outcome ◀─────┘
                                              │
        distill ─▶ admit (write-gate) ─▶ consolidate (dedup/merge)
                                              │
                       credit / blame ◀───────┘   ← on later confirm/overturn
```

The load-bearing difference from generic reflection agents (Reflexion/ExpeL
retry-until-success) is that lessons are written **only from verified
dispositions** — the feedback signal is trustworthy, not self-generated. That is
the whole reason this can work without fine-tuning.

The consolidation machinery is well-trodden and directly adoptable:
- **Mem0** (2504.19413): on each outcome, retrieve same-key lessons → LLM emits
  `ADD / UPDATE / DELETE / NOOP`. This is the write-gate + merge + contradiction
  resolution in one call.
- **ExpeL** (2308.10144): natural-language insight pool with `ADD/EDIT/UPVOTE/
  DOWNVOTE` and an **importance counter** that decays contradicted lessons to 0.
- **ACE** (2510.04618) / **MUSE** (2510.08002): immediate-write + a batched
  **grow-and-refine** pass that dedups/generalizes per class — *never*
  monolithically rewriting a bucket (ACE's "context collapse" is the exact risk
  for a growing lesson store).
- **DAM** (2512.21567): treat prune/keep as a decision under uncertainty —
  **reluctant to delete a hard-won real-vuln lesson** at low confidence. The
  right asymmetry for security.

---

## 2. The grounding layer: PenPal's per-decision assumptions + confidence

PenPal already emits, per scan, the **assumptions** it made and a **confidence**
per assumption. That log is not a nice-to-have — it is the coordinate that makes
self-evolution both *useful* and *safe*. Four uses:

1. **Applicability key.** A lesson is scoped to the assumptions that held when it
   was verified. Retrieve/apply it to a new finding **only when that finding
   shares those assumptions** — not merely the same CWE. (Built: §4.)
2. **Write gate.** Only consolidate a lesson when the assumptions it rested on
   were **high-confidence and held**; low-confidence grounding → quarantine, not
   the trusted store.
3. **Trust weight + re-verify trigger.** Propagate the *minimum* assumption
   confidence into the lesson; low confidence → faster decay, lower retrieval
   weight, and — per Dual-Process AUQ (2601.15703) — a **trigger to re-verify**
   rather than to trust.
4. **Credit assignment.** When a verdict is later confirmed or overturned,
   credit/blame **the specific assumptions**, not just the lesson. Miscalibrated
   assumptions become detectable and self-correcting — this is what turns the
   assumptions DB into the signal that keeps memory honest.

> The elegant part: self-evolution *wants* broad transfer; pollution-resistance
> *wants* tight scoping. The assumption set dissolves the tension — a lesson
> transfers **exactly as far as its grounding justifies**: broad when assumptions
> are general ("egress blocked cluster-wide"), narrow when specific ("this sink
> is sanitized by validator X"). The same field is both the transfer key and the
> pollution guard.

---

## 3. The pollution threat is real (and needs no attacker)

"A lesson from one SQLi case retrieved for all SQLi cases" is precisely the
surface the 2026 security literature is alarmed about:

- **MemoryGraft** (2512.16962) — poisoned *experience retrieval*; agents replicate
  retrieved past successes, so a small fraction of bad entries dominates. This is
  Loupe's design.
- **PoisonedRAG** (2402.07867) — 5 poisoned docs in a million → ~90% hijack.
- **AgentPoison** (2407.12784) — an over-broad embedding *is* an unintended
  trigger that captures a whole class.
- **"Your Agent May Misevolve"** (2509.26354) — safety degrades *specifically
  after memory accumulation*, even in frontier models.

And critically: **we already hit this with no adversary.** The v1 distiller wrote
an unconditional class-level rule and suppression jumped to 0.227 — honest
over-generalization is the same failure mode as poisoning. Memory safety here is
not a threat-model exercise; it is a correctness requirement.

---

## 4. The defense, and what we measured

The single most important rule (AUQ 2601.15703; governance framework SSGM
2603.11768): **a retrieved lesson may RAISE A FLAG for re-verification — it must
never auto-flip a verdict by itself.** Independent re-grounding before any
suppress/pass breaks the self-reinforcement loop. Everything else is hardening:

| Defense | Source | In Loupe |
|---|---|---|
| Write-time admission > retrieval filtering | 2603.15994 (8:1 distractors: read-filter→0%, write-gate→100%) | `Memory(write_gate=True)` refuses unconditional benign lessons |
| Assumption-scoped retrieval | this design / §2 | `Memory(scope_assumptions=True)`; `Lesson.applies_to` |
| Provenance + trust + track-record + decay | 2601.05504, 2509.09498 (SEDM) | *next* |
| Consensus over nearest-neighbor on conflict | ReliabilityRAG 2509.23519 | *next* |
| Drift monitor on per-class verdict mix | 2509.26354, 2604.16339 | *next* |

**Experiment (`experiments/pollution.py`).** Inject a poisoned over-broad benign
lesson into a class that contains a *trap* (a real finding sharing the class with
benign siblings) and measure corruption (reals wrongly suppressed) vs benign_kept
(legit benefit retained):

```
defense regime            poison?  corruption  benign_kept
none (auto-apply)             yes 2/2 = 1.00  5/5 = 1.00
write-gate only                no 2/2 = 1.00  5/5 = 1.00
scope only                    yes 2/2 = 1.00  5/5 = 1.00
write-gate + scope             no 0/2 = 0.00  5/5 = 1.00
flag-don't-flip only          yes 0/2 = 0.00  5/5 = 1.00
full defense                   no 0/2 = 0.00  5/5 = 1.00
```

Takeaways: **no single layer suffices** — write-gate stops the poison but the
*clean* lesson still misfires unscoped; scope alone lets the unconditional poison
through. `write-gate + scope` (or `flag-don't-flip`) drives corruption to 0
**without** collapsing the benign-suppression benefit. (Deterministic policy
simulation — isolates the memory subsystem, not the LLM.)

---

## 5. Domain context: what cuts benign positives

From the vuln-validation literature pass:
- **Execution-grounded confirmation with reachability checks** is the strongest
  lever — MAPTA (2508.20816), XBOW — but POC-GYM (2602.04165) warns "the PoC ran"
  over-counts ~2× unless you confirm it *reaches the real sink*.
- **CWE-specific schema-constrained adjudication** — ZeroFalse (2510.02534),
  QASecClaw (2605.01885) — drives OWASP precision to ~0.95+ at ~3% recall cost;
  QASecClaw's **fail-open** default (keep the finding when uncertain) is the right
  recall guard.
- **The deployment-context flip is unformalized in academia.** The closest is
  *industry* — Qualys TruConfirm ("EternalBlue only if SMBv1 is exposed; Log4Shell
  only if the JNDI path is live"). AXE (2602.14345) labels reports "benign or
  purely theoretical" but validates against a *running* target, not the deployed
  environment's neutralizing conditions. **That gap is Loupe's defensible
  novelty** — benchmarking the egress/auth/reachability *precondition* flip.

---

## 6. The second loop: prompt evolution (GEPA)

There are two things that can evolve here, and they're complementary — the survey
taxonomy's "evolve **memory**" vs "evolve **prompts**":

- **Inner / online — memory** (this doc's core): per-class verified lessons
  accumulate at test time.
- **Outer / offline — prompts** (GEPA): the *fixed* textual scaffolding — the
  distiller and validator instructions — is optimized against the benchmark
  metric, once, before deployment.

**GEPA** (*Reflective Prompt Evolution Can Outperform RL*, Agrawal et al. 2025;
arXiv 2507.19457 — verify) does the outer loop with two moves: **reflective
mutation** (the LLM reads execution traces + natural-language feedback and
rewrites the instruction, a far richer signal than scalar RL reward) and
**Pareto selection** (keep a *frontier* of candidates that each win on different
instances/objectives, instead of collapsing to one scalar-best prompt).

Why it fits Loupe specifically:
1. **The v1→v2 distiller fix was a manual GEPA step** — observe suppression
   spike, reflect, rewrite to conditional rules. GEPA automates exactly that.
2. **Our pass condition is multi-objective** (bp_rate ↓ AND recall flat AND
   suppression low). GEPA's Pareto frontier is built to *not* crush that tradeoff
   into one number — the failure mode of "just minimize bp_rate."
3. We already emit the **textual feedback** GEPA feeds on ("suppressed real F
   because lesson X over-generalized"), straight from the suppression analysis.

Target the **distiller prompt** first (current bottleneck). Caveats: it tunes
static prompts, not the deployment-flip reasoning that is the novelty; optimizing
on OWASP risks overfitting to OWASP's sanitizer-style FPs (use a held-out split);
and it needs a *trustworthy* metric, so it belongs **after** the eval is scaled.
Skeleton: `experiments/gepa_distiller.py` (hand-rolled GEPA-lite, dependency-light;
DSPy's `dspy.GEPA` is the off-the-shelf alternative).

## 7. Roadmap

**Built:** single-stage validator ablation; verified-lesson memory; conditional
distiller; assumption-scoped retrieval + write-gate; pollution defense matrix.

**Next, in order:**
1. **Re-key + flag-don't-flip in the LLM loop.** Thread `apply_mode="flag"` through
   the validator so a lesson annotates "re-verify," never decides. Add the
   assumption-fingerprint to retrieval on real data.
2. **Trust + decay + track-record.** Per-lesson confidence (from PenPal's log),
   time decay, and empirical correctness credit/blame on later outcomes (SEDM).
3. **Consensus + drift monitor.** Conflict resolution over a class's lessons; alarm
   on verdict-distribution shift.
4. **Scale the curve.** ✅ Done — 300 cases × 3 seeds (`experiments/scale.py`).
   Verdict: the benign-positive axis barely moves (memory isn't an FP-cutter on
   OWASP); the real, compounding benefit is **recall** — distilled-lessons hold
   recall ~1.0 while baseline degrades to ~0.80. distilled > raw > baseline,
   error bars ±0.003. The deployment-context FP axis still needs the grounded tier.
5. **GEPA the distiller** (§6) — auto-evolve the distiller prompt against a Pareto
   of (bp_rate, recall, suppression) on a held-out split. *After* step 4.

---

## References (curated)

Verified 2024–2025 anchors: ExpeL (2308.10144), AWM (2409.07429), A-MEM
(2502.12110), Mem0 (2504.19413), Self-Evolving Agents survey (2507.21046), ACE
(2510.04618), MUSE (2510.08002); PoisonedRAG (2402.07867), AgentPoison
(2407.12784), ReliabilityRAG (2509.23519), SEDM (2509.09498), Misevolve
(2509.26354); MAPTA (2508.20816), ZeroFalse (2510.02534), CVE-Bench (2503.17332).

Prompt evolution: GEPA (2507.19457 — verify).

Title-verified 2025–2026 (re-pull PDFs before quoting figures): DAM (2512.21567),
MemoryGraft (2512.16962), memory-poisoning defense (2601.05504), AUQ
(2601.15703), SSGM (2603.11768), write-gating (2603.15994), QASecClaw
(2605.01885), AXE (2602.14345), POC-GYM (2602.04165), Qualys TruConfirm
(industry, 2026).
